package ebpf

import (
	"net"
	"testing"
	"unsafe"
)

func TestEgressPolicyLayout(t *testing.T) {
	// Must match struct oknek_egress_policy in oknek_lsm.c:
	// gw_v4[4] + gw_port(2) + allow_dns(1) + enforce(1) + dns_v4[3][4] = 20.
	if got := unsafe.Sizeof(egressPolicy{}); got != 20 {
		t.Fatalf("egressPolicy size = %d, want 20 (must match the C struct)", got)
	}
}

func TestBuildEgressPolicy(t *testing.T) {
	p := buildEgressPolicy(net.ParseIP("127.0.0.1"), 4000, true, true,
		[]net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("1.1.1.1")})
	if p.GwV4 != [4]byte{127, 0, 0, 1} {
		t.Errorf("gw_v4 = %v, want 127.0.0.1 bytes", p.GwV4)
	}
	if p.GwPort != 4000 || p.AllowDNS != 1 || p.Enforce != 1 {
		t.Errorf("policy = %+v", p)
	}
	if p.DNSv4[0] != [4]byte{8, 8, 8, 8} || p.DNSv4[1] != [4]byte{1, 1, 1, 1} {
		t.Errorf("resolvers = %v, want 8.8.8.8 then 1.1.1.1", p.DNSv4)
	}
	p2 := buildEgressPolicy(net.ParseIP("10.0.0.5"), 0, false, false, nil)
	if p2.AllowDNS != 0 || p2.Enforce != 0 || p2.GwV4 != [4]byte{10, 0, 0, 5} {
		t.Errorf("policy2 = %+v", p2)
	}
	if p2.DNSv4 != [3][4]byte{} {
		t.Errorf("policy2 resolvers should be empty, got %v", p2.DNSv4)
	}
}
