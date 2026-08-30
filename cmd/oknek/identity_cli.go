package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oknek/oknek/internal/identity"
)

// oknek identity issue --agent <name> [--ttl 300] [--aud <str>]   mint a kernel-attested identity token
// oknek identity verify <jwt> [--pubkey <hex>]                     verify signature + expiry, print claims
// oknek identity pubkey                                            print the attestation public key (hex + JWKS)
func runIdentity(configPath string, rest []string) {
	c, _ := client(configPath)
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: oknek identity issue --agent <name> [--ttl <secs>] [--aud <str>] | verify <jwt> [--pubkey <hex>] | pubkey")
		os.Exit(2)
	}
	switch rest[0] {
	case "issue":
		agent, aud := "", ""
		ttl := 0
		for i := 1; i+1 < len(rest); i++ {
			switch rest[i] {
			case "--agent":
				agent = rest[i+1]
			case "--aud":
				aud = rest[i+1]
			case "--ttl":
				ttl, _ = strconv.Atoi(rest[i+1])
			}
		}
		if agent == "" {
			fmt.Fprintln(os.Stderr, "oknek identity issue: --agent <name> required")
			os.Exit(2)
		}
		var out struct {
			Token  string          `json:"token"`
			Claims identity.Claims `json:"claims"`
		}
		if err := c.Call("identity.issue", map[string]interface{}{"agent": agent, "ttl_seconds": ttl, "aud": aud}, &out); err != nil {
			fmt.Fprintf(os.Stderr, "oknek: identity issue: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(out.Token)
	case "verify":
		if len(rest) < 2 {
			fmt.Fprintln(os.Stderr, "usage: oknek identity verify <jwt> [--pubkey <hex>]")
			os.Exit(2)
		}
		tok := strings.TrimSpace(rest[1])
		pubHex := ""
		for i := 2; i+1 < len(rest); i++ {
			if rest[i] == "--pubkey" {
				pubHex = rest[i+1]
			}
		}
		if pubHex == "" {
			var pk struct {
				PubKeyHex string `json:"pubkey_hex"`
			}
			if err := c.Call("identity.pubkey", nil, &pk); err != nil {
				fmt.Fprintf(os.Stderr, "oknek: identity verify: no --pubkey and daemon unreachable: %v\n", err)
				os.Exit(1)
			}
			pubHex = pk.PubKeyHex
		}
		pub, err := hex.DecodeString(pubHex)
		if err != nil || len(pub) != 32 {
			fmt.Fprintln(os.Stderr, "oknek: identity verify: bad pubkey (want 64 hex)")
			os.Exit(2)
		}
		claims, err := identity.Verify(tok, pub, time.Now().Unix())
		if err != nil {
			fmt.Printf("INVALID · %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("VALID · %s\n", claims.Sub)
		fmt.Printf("   issued %s · expires %s (%ds left)\n",
			time.Unix(claims.Iat, 0).UTC().Format(time.RFC3339), time.Unix(claims.Exp, 0).UTC().Format(time.RFC3339), claims.Exp-time.Now().Unix())
		b, _ := json.MarshalIndent(claims.Oknek, "   ", "  ")
		fmt.Printf("   %s\n", b)
	case "pubkey":
		var pk struct {
			PubKeyHex string `json:"pubkey_hex"`
			KID       string `json:"kid"`
			JWKS      string `json:"jwks"`
		}
		if err := c.Call("identity.pubkey", nil, &pk); err != nil {
			fmt.Fprintf(os.Stderr, "oknek: identity pubkey: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("okredo attest pubkey (ed25519) · kid %s\n%s\n%s\n", pk.KID, pk.PubKeyHex, pk.JWKS)
	default:
		fmt.Fprintln(os.Stderr, "usage: oknek identity issue|verify|pubkey")
		os.Exit(2)
	}
}
