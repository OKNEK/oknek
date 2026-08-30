package ebpf

import "net"

// egressPolicy mirrors `struct oknek_egress_policy` in oknek_lsm.c (8 bytes:
// gw_v4[4], gw_port u16, allow_dns u8, enforce u8). cilium/ebpf marshals it
// into the single-entry oknek_egress ARRAY map.
type egressPolicy struct {
	GwV4     [4]byte
	GwPort   uint16
	AllowDNS uint8
	Enforce  uint8
	DNSv4    [3][4]byte // resolver IPv4s; :53 allowed only to these (empty = legacy allow-any)
}

func buildEgressPolicy(gw net.IP, gwPort int, allowDNS, enforce bool, resolvers []net.IP) egressPolicy {
	var p egressPolicy
	if v4 := gw.To4(); v4 != nil {
		copy(p.GwV4[:], v4)
	}
	p.GwPort = uint16(gwPort)
	if allowDNS {
		p.AllowDNS = 1
	}
	if enforce {
		p.Enforce = 1
	}
	n := 0
	for _, r := range resolvers {
		if n >= len(p.DNSv4) {
			break
		}
		if v4 := r.To4(); v4 != nil {
			copy(p.DNSv4[n][:], v4)
			n++
		}
	}
	return p
}
