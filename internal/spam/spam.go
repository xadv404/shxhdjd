package spam

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	reIPv4     = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	reDigits   = regexp.MustCompile(`^\d+$`)
	reUUID     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reHexLong  = regexp.MustCompile(`^[0-9a-f]{20,}$`)
	reHashish  = regexp.MustCompile(`^[0-9a-f]{32,}$`)
	reManyDash = regexp.MustCompile(`-{3,}`)
	reLocal    = regexp.MustCompile(`(?i)^(localhost|local|intranet|internal|corp|lan)(\.|$)`)
)

var badTLDs = map[string]struct{}{
	"local": {}, "localhost": {}, "invalid": {}, "test": {}, "example": {},
	"onion": {}, "i2p": {}, "arpa": {},
}

var junkWords = []string{
	"mailinator", "guerrillamail", "tempmail", "throwaway", "spam",
	"phishing", "malware", "virus", "botnet", "xn--",
}

// IsClean returns true if domain passes zero-spam rules.
func IsClean(domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	d = strings.TrimPrefix(d, "*.")
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	if strings.ContainsAny(d, " \t\n\r") || strings.Contains(d, "..") {
		return false
	}
	if reIPv4.MatchString(d) || reLocal.MatchString(d) {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	tld := labels[len(labels)-1]
	if _, bad := badTLDs[tld]; bad || len(tld) < 2 || len(tld) > 24 {
		return false
	}
	for _, r := range tld {
		if r < 'a' || r > 'z' {
			return false // TLD letters only — drops parse junk like com0 / org0y0
		}
	}
	for _, lab := range labels {
		if lab == "" || len(lab) > 63 {
			return false
		}
		if lab[0] == '-' || lab[len(lab)-1] == '-' {
			return false
		}
		for _, r := range lab {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_') {
				return false
			}
		}
		if reUUID.MatchString(lab) || reHexLong.MatchString(lab) || reHashish.MatchString(lab) {
			return false
		}
		if reManyDash.MatchString(lab) {
			return false
		}
		// too many digits in label
		digits := 0
		for _, r := range lab {
			if unicode.IsDigit(r) {
				digits++
			}
		}
		if len(lab) >= 8 && digits*100/len(lab) >= 70 {
			return false
		}
	}
	for _, w := range junkWords {
		if strings.Contains(d, w) {
			return false
		}
	}
	// reject pure numeric SLD like 12345.com when very long
	sld := labels[len(labels)-2]
	if len(sld) >= 12 && reDigits.MatchString(sld) {
		return false
	}
	return true
}
