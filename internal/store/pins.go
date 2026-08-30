package store

// Pin is one R22 supply-chain artifact under integrity protection.
type Pin struct {
	Path        string `json:"path"`
	Dev         uint32 `json:"dev"`
	Ino         uint64 `json:"ino"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	PinnedAt    int64  `json:"pinned_at"`
	TamperedAt  int64  `json:"tampered_at,omitempty"`
	Quarantined bool   `json:"quarantined"`
}

// UpsertPin records (or re-records) a pin. A re-pin clears tamper/quarantine state.
func (s *Store) UpsertPin(p Pin) error {
	q := 0
	if p.Quarantined {
		q = 1
	}
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO pins (path, dev, ino, sha256, size, pinned_at, tampered_at, quarantined)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Path, p.Dev, p.Ino, p.SHA256, p.Size, p.PinnedAt, p.TamperedAt, q)
	return err
}

// Pins lists every pin, sorted by path.
func (s *Store) Pins() ([]Pin, error) {
	rows, err := s.db.Query(`SELECT path, dev, ino, sha256, size, pinned_at, tampered_at, quarantined FROM pins ORDER BY path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Pin
	for rows.Next() {
		var p Pin
		var q int
		if err := rows.Scan(&p.Path, &p.Dev, &p.Ino, &p.SHA256, &p.Size, &p.PinnedAt, &p.TamperedAt, &q); err != nil {
			return nil, err
		}
		p.Quarantined = q == 1
		out = append(out, p)
	}
	return out, rows.Err()
}

// MarkPinTampered flags a pin as tampered + quarantined and records the inode the
// tampered content now lives at (an editor's atomic save changes the inode).
func (s *Store) MarkPinTampered(path string, ts int64, dev uint32, ino uint64) error {
	_, err := s.db.Exec(`UPDATE pins SET tampered_at = ?, quarantined = 1, dev = ?, ino = ? WHERE path = ?`, ts, dev, ino, path)
	return err
}

// UpdatePinInode records a moved-but-identical file (same sha, new inode) silently.
func (s *Store) UpdatePinInode(path string, dev uint32, ino uint64) error {
	_, err := s.db.Exec(`UPDATE pins SET dev = ?, ino = ? WHERE path = ?`, dev, ino, path)
	return err
}

// DeletePin forgets a pin.
func (s *Store) DeletePin(path string) error {
	_, err := s.db.Exec(`DELETE FROM pins WHERE path = ?`, path)
	return err
}

// Canary is one R23 planted decoy credential.
type Canary struct {
	Path      string `json:"path"`
	Dev       uint32 `json:"dev"`
	Ino       uint64 `json:"ino"`
	SHA256    string `json:"sha256"`
	PlantedAt int64  `json:"planted_at"`
}

// UpsertCanary records a planted decoy.
func (s *Store) UpsertCanary(c Canary) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO canaries (path, dev, ino, sha256, planted_at) VALUES (?, ?, ?, ?, ?)`,
		c.Path, c.Dev, c.Ino, c.SHA256, c.PlantedAt)
	return err
}

// Canaries lists every planted decoy, sorted by path.
func (s *Store) Canaries() ([]Canary, error) {
	rows, err := s.db.Query(`SELECT path, dev, ino, sha256, planted_at FROM canaries ORDER BY path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Canary
	for rows.Next() {
		var c Canary
		if err := rows.Scan(&c.Path, &c.Dev, &c.Ino, &c.SHA256, &c.PlantedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCanary forgets a decoy.
func (s *Store) DeleteCanary(path string) error {
	_, err := s.db.Exec(`DELETE FROM canaries WHERE path = ?`, path)
	return err
}
