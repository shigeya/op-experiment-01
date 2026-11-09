package opdig

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/shigeya/dnsdata-go/zone"
)

// Outcome is what a check concludes from one answer.
type Outcome string

const (
	OutcomeKeysPresent  Outcome = "keys-present"
	OutcomeNoUsableKey  Outcome = "no-usable-key"
	OutcomeAbsent       Outcome = "absent"
	OutcomePinned       Outcome = "pinned"
	OutcomeUnpinned     Outcome = "unpinned"
	OutcomeNoOPDeclared Outcome = "no-op-declared"
	OutcomeNoUsablePin  Outcome = "no-usable-pin"
	OutcomeRevoked      Outcome = "revoked"
	OutcomeNotRevoked   Outcome = "not-revoked"
	OutcomeNoAssurance  Outcome = "no-assurance"
	OutcomeFailure      Outcome = "failure"
)

// Role says which OPKEY RRset a check reads.
type Role string

const (
	RoleIssuerKey       Role = "issuer-key"
	RolePinnedIssuerKey Role = "pinned-issuer-key"
	RoleOriginatorKey   Role = "originator-key"
)

// KeyEntry is one RR of an OPKEY RRset.
type KeyEntry struct {
	RData  string `json:"rdata"`
	Usable bool   `json:"usable"`
	Reason string `json:"reason,omitempty"`
}

// OPKEYCheck is the reading of a TLSA RRset as OPKEY RDATA.
type OPKEYCheck struct {
	Role    Role       `json:"role"`
	Name    string     `json:"name"`
	Status  Status     `json:"status"`
	Outcome Outcome    `json:"outcome"`
	Detail  string     `json:"detail"`
	Keys    []KeyEntry `json:"keys,omitempty"`
}

// PinEntry is one RR of an Issuer Pinning Record.
type PinEntry struct {
	RData  string `json:"rdata"`
	Usable bool   `json:"usable"`
	Reason string `json:"reason,omitempty"`
}

// PinCheck is the reading of the Issuer Pinning Record (draft §8.2).
type PinCheck struct {
	Name    string     `json:"name"`
	Status  Status     `json:"status"`
	Outcome Outcome    `json:"outcome"`
	Detail  string     `json:"detail"`
	Issuers []string   `json:"issuers,omitempty"`
	Entries []PinEntry `json:"entries,omitempty"`
}

// RevocationCheck is the reading of a Revocation Record (draft §8.3).
type RevocationCheck struct {
	Name      string   `json:"name"`
	Status    Status   `json:"status"`
	Outcome   Outcome  `json:"outcome"`
	Detail    string   `json:"detail"`
	RevokedAt string   `json:"revoked_at,omitempty"`
	Strings   []string `json:"strings,omitempty"`
}

// notSecureOrFailure maps the statuses that lead to no conclusion. An
// alias is a failure here (draft §6.1); InterpretPin reads it before
// calling this (draft §8).
func notSecureOrFailure(a Answer) (Outcome, string, bool) {
	switch a.Status {
	case StatusNotSecure:
		return OutcomeNoAssurance, "no assurance (draft §6.1): " + a.Reason, true
	case StatusFailure, StatusAlias:
		return OutcomeFailure, "verification failure (draft §6.1): " + a.Reason, true
	}
	return "", "", false
}

// pinAlias reads an answer at the Issuer Pinning Record reached through
// an alias. Draft §8 reads it as an Insecure answer, so the originator is
// unpinned, unless its validation state is Bogus or Indeterminate. With
// the AD bit set the answer was validated and is not Bogus; without it
// the tool cannot tell, as for any answer without AD (draft §6.1).
func pinAlias(c PinCheck, a Answer) PinCheck {
	const reading = "draft §8 reads an answer reached through an alias as Insecure: the originator is unpinned; " +
		"the records at the alias target are not used"
	if a.AD {
		c.Outcome = OutcomeUnpinned
		c.Detail = a.Reason + "; " + reading
		return c
	}
	c.Outcome = OutcomeNoAssurance
	c.Detail = a.Reason + "; AD bit not set: " + reading +
		", unless the answer is Bogus or Indeterminate, which an answer without AD cannot exclude"
	return c
}

// InterpretOPKEY reads the TLSA RRset of a as OPKEY RDATA (draft §4.3,
// §2.1).
func InterpretOPKEY(role Role, a Answer) OPKEYCheck {
	c := OPKEYCheck{Role: role, Name: a.Name, Status: a.Status}
	keys, keyErr := zone.OPKEYFromTLSA(a.RRs)
	usable := 0
	if keyErr == nil {
		for _, k := range keys {
			e := KeyEntry{RData: k.String(), Usable: k.Usable()}
			if e.Usable {
				usable++
			} else {
				e.Reason = k.Check().Error()
			}
			c.Keys = append(c.Keys, e)
		}
	}
	if o, d, ok := notSecureOrFailure(a); ok {
		c.Outcome, c.Detail = o, d
		return c
	}
	if keyErr != nil {
		c.Outcome, c.Detail = OutcomeFailure, "malformed RDATA in the RRset: "+keyErr.Error()
		return c
	}
	switch {
	case a.Status == StatusSecureAbsent:
		c.Outcome = OutcomeAbsent
		c.Detail = "Secure " + a.Reason + ": no key is valid at this name"
		if role == RoleOriginatorKey {
			c.Detail += " (the CP is revoked)"
		}
	case usable == 0:
		c.Outcome = OutcomeNoUsableKey
		c.Detail = fmt.Sprintf("RRset present with %d RR(s), none usable: no key is valid at this name", len(keys))
	default:
		c.Outcome = OutcomeKeysPresent
		c.Detail = fmt.Sprintf("%d usable RR(s) of %d", usable, len(keys))
	}
	return c
}

// InterpretPin reads the Issuer Pinning Record (draft §8.1, §8.2).
func InterpretPin(a Answer) PinCheck {
	c := PinCheck{Name: a.Name, Status: a.Status}
	if a.Status == StatusAlias {
		return pinAlias(c, a)
	}
	if o, d, ok := notSecureOrFailure(a); ok {
		c.Outcome, c.Detail = o, d
		if a.Status == StatusNotSecure {
			c.Detail += "; draft §8.2 reads an Insecure answer as unpinned, " +
				"but without validation an Insecure answer cannot be told from an unvalidated one"
		}
		return c
	}
	if a.Status == StatusSecureAbsent {
		c.Outcome = OutcomeUnpinned
		c.Detail = "Secure " + a.Reason + ": the originator is unpinned"
		return c
	}
	recs := make([]*zone.SVCB, 0, len(a.RRs))
	for _, rr := range a.RRs {
		s, err := zone.ParseSVCB(rr, rr.Value)
		if err != nil {
			c.Outcome, c.Detail = OutcomeFailure, "malformed SVCB RDATA: "+err.Error()
			return c
		}
		recs = append(recs, s)
	}
	if hasAliasMode(recs) {
		c.Outcome, c.Detail = OutcomeNoOPDeclared, aliasModeDetail(recs)
		for _, rr := range a.RRs {
			c.Entries = append(c.Entries, PinEntry{RData: rr.Value, Usable: false, Reason: "AliasMode present"})
		}
		return c
	}
	return pinServiceMode(c, a, recs)
}

func hasAliasMode(recs []*zone.SVCB) bool {
	for _, s := range recs {
		if s.Priority == 0 {
			return true
		}
	}
	return false
}

func aliasModeDetail(recs []*zone.SVCB) string {
	if len(recs) == 1 && recs[0].Target == "." {
		return "AliasMode with TargetName \".\": the originator declares that it has no Originator Profile"
	}
	return "AliasMode with another TargetName, or mixed with ServiceMode: read as the declaration of no Originator Profile; verification fails"
}

func pinServiceMode(c PinCheck, a Answer, recs []*zone.SVCB) PinCheck {
	issuers := []string{}
	usable := 0
	for i, s := range recs {
		e := PinEntry{RData: a.RRs[i].Value}
		switch {
		case hasMandatoryKey(s):
			e.Reason = "carries the mandatory key"
		case s.Target == ".":
			e.Usable = true
			e.Reason = "TargetName \".\" names no CP issuer"
		default:
			e.Usable = true
			issuers = appendUnique(issuers, strings.ToLower(strings.TrimSuffix(s.Target, ".")))
		}
		if e.Usable {
			usable++
		}
		c.Entries = append(c.Entries, e)
	}
	if usable == 0 {
		c.Outcome = OutcomeNoUsablePin
		c.Detail = "Secure RRset with no usable RR: verification failure"
		return c
	}
	slices.Sort(issuers)
	c.Outcome, c.Issuers = OutcomePinned, issuers
	if len(issuers) == 0 {
		c.Detail = "pinned to an empty set of CP issuers: every CP fails the check"
	} else {
		c.Detail = "pinned to " + strings.Join(issuers, ", ")
	}
	return c
}

func hasMandatoryKey(s *zone.SVCB) bool {
	for _, p := range s.Params {
		if p.Key == zone.SvcKeyMandatory {
			return true
		}
	}
	return false
}

func appendUnique(list []string, v string) []string {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

// revocationPrefix and revocationField give the RDATA format of draft
// §8.3: "v=op1; revoked=<time>".
const (
	revocationPrefix = "v=op1; "
	revocationField  = "revoked="
)

// InterpretRevocation reads a Revocation Record (draft §8.3). Presence
// alone decides; the time is reported only when the RDATA has the
// format of the draft.
func InterpretRevocation(a Answer) RevocationCheck {
	c := RevocationCheck{Name: a.Name, Status: a.Status}
	for _, rr := range a.RRs {
		strs, err := rr.TXTStrings()
		if err != nil {
			strs = []string{rr.Value}
		}
		c.Strings = append(c.Strings, strs...)
	}
	if o, d, ok := notSecureOrFailure(a); ok {
		c.Outcome, c.Detail = o, d
		return c
	}
	if a.Status == StatusSecureAbsent {
		c.Outcome = OutcomeNotRevoked
		c.Detail = "Secure " + a.Reason + ": the PA has not been revoked"
		return c
	}
	c.Outcome = OutcomeRevoked
	if t, ok := revocationTime(a.RRs); ok {
		c.RevokedAt = t
		c.Detail = "the PA has been revoked at " + t
		return c
	}
	c.Detail = "the PA has been revoked (RDATA not in the form \"v=op1; revoked=<time>\"; presence alone decides)"
	return c
}

// revocationTime returns the time of a single RR with a single
// character-string of the draft's format.
func revocationTime(rrs []*zone.ResourceRecord) (string, bool) {
	if len(rrs) != 1 {
		return "", false
	}
	strs, err := rrs[0].TXTStrings()
	if err != nil || len(strs) != 1 {
		return "", false
	}
	rest, ok := strings.CutPrefix(strs[0], revocationPrefix+revocationField)
	if !ok {
		return "", false
	}
	if _, err := time.Parse(time.RFC3339, rest); err != nil {
		return "", false
	}
	return rest, true
}
