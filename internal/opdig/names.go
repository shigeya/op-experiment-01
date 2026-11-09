// Package opdig looks up the records that draft-shigeya-dns-opkey-00
// places under the _op label and reports what a verifier would read
// from them.
//
// It reads OPKEY RDATA in the transitional TLSA form (draft §4.1,
// §4.3), the Issuer Pinning Record (SVCB, draft §8.2) and Revocation
// Records (TXT, draft §8.3). It does not validate DNSSEC itself: the
// DNSSEC state it reports is the AD bit of the resolver's answer.
package opdig

import (
	"errors"
	"fmt"
	"strings"
)

// ErrName is returned for a name that cannot be used.
var ErrName = errors.New("opdig: name")

const (
	maxLabelLength = 63
	maxNameLength  = 253

	labelOP            = "_op"
	labelIssuerKey     = "_issuer-key"
	labelOriginatorKey = "_originator-key"
	labelRevocation    = "_revocation"
)

// RecordKind selects the node under which a record name lies.
type RecordKind int

const (
	// OriginatorKeyRecord is a name below _originator-key._op.<cp-issuer>
	// (draft §3.2).
	OriginatorKeyRecord RecordKind = iota + 1
	// RevocationRecord is a name below _revocation._op.<pa-issuer>
	// (draft §8.3).
	RevocationRecord
)

func (k RecordKind) nodeLabel() string {
	if k == RevocationRecord {
		return labelRevocation
	}
	return labelOriginatorKey
}

// NormalizeName returns name in the form used for comparison and for
// queries: lower case, no trailing dot. Only ASCII names (A-labels) are
// accepted; converting a U-label is left to the caller.
func NormalizeName(name string) (string, error) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	if n == "" {
		return "", fmt.Errorf("%w: empty", ErrName)
	}
	if len(n) > maxNameLength {
		return "", fmt.Errorf("%w: %q is longer than %d octets", ErrName, name, maxNameLength)
	}
	for _, label := range strings.Split(n, ".") {
		if err := checkLabel(label); err != nil {
			return "", fmt.Errorf("%w: %q: %v", ErrName, name, err)
		}
	}
	return n, nil
}

func checkLabel(label string) error {
	if label == "" {
		return errors.New("empty label")
	}
	if len(label) > maxLabelLength {
		return fmt.Errorf("label longer than %d octets", maxLabelLength)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		isAlnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if !isAlnum && c != '-' && c != '_' {
			return fmt.Errorf("character %q is not allowed (A-labels only)", c)
		}
	}
	return nil
}

// PinName returns _op.<originator>, the name of the Issuer Pinning
// Record (draft §8.2). originator must already be normalized.
func PinName(originator string) string {
	return labelOP + "." + originator
}

// IssuerKeyName returns _issuer-key._op.<issuer>, the name of the
// Issuer Key Record (draft §3.1). issuer must already be normalized.
func IssuerKeyName(issuer string) string {
	return labelIssuerKey + "." + labelOP + "." + issuer
}

// RecordName returns the name of an Originator Key Record or a
// Revocation Record of issuer (already normalized).
//
// arg is either a full name, which must lie below the node of kind
// under issuer by the rule of draft §3.2 (trailing labels equal, at
// least one label before them), or a single record label, which is
// placed directly below that node.
func RecordName(kind RecordKind, arg, issuer string) (string, error) {
	node := kind.nodeLabel() + "." + labelOP + "." + issuer
	n, err := NormalizeName(arg)
	if err != nil {
		return "", err
	}
	if !strings.Contains(n, ".") {
		return NormalizeName(n + "." + node)
	}
	if !strings.HasSuffix(n, "."+node) {
		return "", fmt.Errorf("%w: %s does not lie below %s", ErrName, n, node)
	}
	return n, nil
}
