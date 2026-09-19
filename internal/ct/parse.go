package ct

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
)

type entryResp struct {
	Entries []struct {
		LeafInput string `json:"leaf_input"`
	} `json:"entries"`
}

func domainsFromEntriesJSON(body []byte) []string {
	var resp entryResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil
	}
	out := make([]string, 0, len(resp.Entries)*2)
	seen := make(map[string]struct{}, len(resp.Entries)*2)
	for _, e := range resp.Entries {
		raw, err := base64.StdEncoding.DecodeString(e.LeafInput)
		if err != nil || len(raw) < 15 {
			continue
		}
		for _, d := range domainsFromLeaf(raw) {
			d = strings.ToLower(strings.TrimSpace(d))
			d = strings.TrimPrefix(d, "*.")
			if d == "" || strings.Contains(d, " ") || !strings.Contains(d, ".") {
				continue
			}
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	return out
}

func domainsFromLeaf(leaf []byte) []string {
	// MerkleTreeLeaf: version(1) + leaf_type(1) + TimestampedEntry
	if len(leaf) < 12 || leaf[0] != 0 || leaf[1] != 0 {
		return domainsFromCertBytes(leaf)
	}
	// TimestampedEntry: timestamp(8) + entry_type(2) + ...
	off := 2 + 8
	if len(leaf) < off+2 {
		return nil
	}
	entryType := binary.BigEndian.Uint16(leaf[off : off+2])
	off += 2
	switch entryType {
	case 0: // x509_entry
		if len(leaf) < off+3 {
			return nil
		}
		certLen := int(leaf[off])<<16 | int(leaf[off+1])<<8 | int(leaf[off+2])
		off += 3
		if certLen <= 0 || off+certLen > len(leaf) {
			return nil
		}
		return domainsFromCertBytes(leaf[off : off+certLen])
	case 1: // precert_entry
		if len(leaf) < off+32+3 {
			return nil
		}
		off += 32 // issuer key hash
		tbsLen := int(leaf[off])<<16 | int(leaf[off+1])<<8 | int(leaf[off+2])
		off += 3
		if tbsLen <= 0 || off+tbsLen > len(leaf) {
			return nil
		}
		return domainsFromTBS(leaf[off : off+tbsLen])
	default:
		return domainsFromCertBytes(leaf)
	}
}

func domainsFromCertBytes(der []byte) []string {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		// Sometimes extra wrapping; try to find SEQUENCE start
		for i := 0; i < len(der)-4; i++ {
			if der[i] == 0x30 && der[i+1] == 0x82 {
				cert, err = x509.ParseCertificate(der[i:])
				if err == nil {
					break
				}
			}
		}
		if err != nil {
			return nil
		}
	}
	out := make([]string, 0, 1+len(cert.DNSNames))
	if cert.Subject.CommonName != "" {
		out = append(out, cert.Subject.CommonName)
	}
	out = append(out, cert.DNSNames...)
	return out
}

func domainsFromTBS(tbs []byte) []string {
	// Go has no public TBS parser; pull DNS-like IA5Strings carefully from SAN extensions.
	return extractDNSFromASN1(tbs)
}

// extractDNSFromASN1 finds dNSName (tag 0x82) values inside SAN-like structures.
func extractDNSFromASN1(b []byte) []string {
	var out []string
	for i := 0; i+2 < len(b); i++ {
		if b[i] != 0x82 { // context-specific [2] dNSName
			continue
		}
		n := int(b[i+1])
		if n&0x80 != 0 {
			continue // skip long-form for safety
		}
		if n < 4 || i+2+n > len(b) {
			continue
		}
		s := string(b[i+2 : i+2+n])
		if !looksLikeDomain(s) {
			continue
		}
		out = append(out, strings.ToLower(s))
		i += 1 + n
	}
	return out
}

func looksLikeDomain(s string) bool {
	if len(s) < 4 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '-' || r == '*' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	parts := strings.Split(s, ".")
	tld := parts[len(parts)-1]
	if len(tld) < 2 {
		return false
	}
	for _, r := range tld {
		if r < 'a' || r > 'z' {
			if r >= 'A' && r <= 'Z' {
				continue
			}
			return false
		}
	}
	return true
}
