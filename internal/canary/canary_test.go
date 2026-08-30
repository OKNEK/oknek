package canary

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlantCreatesDecoy0600(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".aws", "credentials")
	sha, err := Plant(p)
	if err != nil || len(sha) != 64 {
		t.Fatalf("plant: %v sha=%q", err, sha)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "aws_access_key_id = AKIA") {
		t.Fatalf("decoy content: %s", b)
	}
}

func TestPlantRefusesRealFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secrets.json")
	real := []byte(`{"real": true}`)
	if err := os.WriteFile(p, real, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Plant(p); !errors.Is(err, ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
	b, _ := os.ReadFile(p)
	if !bytes.Equal(b, real) {
		t.Fatal("real file was modified")
	}
}

func TestRemoveOnlyIfUnchanged(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".env.backup")
	sha, err := Plant(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("now a real secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Remove(p, sha); !errors.Is(err, ErrChanged) {
		t.Fatalf("want ErrChanged, got %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("changed file must survive")
	}
	p2 := filepath.Join(t.TempDir(), "id_rsa_old")
	sha2, _ := Plant(p2)
	if err := Remove(p2, sha2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p2); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("decoy should be gone")
	}
	if err := Remove(p2, sha2); err != nil {
		t.Fatalf("remove of missing is a no-op: %v", err)
	}
}

func TestDecoyShapesAndUniqueness(t *testing.T) {
	if !bytes.Contains(Decoy("id_rsa_old"), []byte("BEGIN OPENSSH PRIVATE KEY")) {
		t.Fatal("ssh decoy")
	}
	if !bytes.Contains(Decoy(".env.backup"), []byte("DATABASE_URL=")) {
		t.Fatal("env decoy")
	}
	if !bytes.Contains(Decoy("secrets.json"), []byte(`"api_key"`)) {
		t.Fatal("json decoy")
	}
	if bytes.Equal(Decoy("credentials"), Decoy("credentials")) {
		t.Fatal("decoys must be unique per plant")
	}
}
