package opdig

import (
	"fmt"
	"strings"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

// Status is the classification of one answer, before the record type is
// interpreted.
type Status string

const (
	// StatusSecurePresent: NOERROR with the RRset at the queried name,
	// and the AD bit set.
	StatusSecurePresent Status = "secure-present"
	// StatusSecureAbsent: NXDOMAIN or NODATA with the AD bit set.
	StatusSecureAbsent Status = "secure-absent"
	// StatusNotSecure: NOERROR or NXDOMAIN without the AD bit. The
	// answer is Insecure, or the resolver did not validate it; the two
	// cannot be told apart from the answer.
	StatusNotSecure Status = "not-secure"
	// StatusFailure: a resolution failure, or an RCODE other than NOERROR
	// and NXDOMAIN.
	StatusFailure Status = "failure"
	// StatusAlias: NOERROR or NXDOMAIN reached through an alias (a CNAME
	// or DNAME, or the RRset at another owner name). The records at the
	// alias target are never used. How the answer is read depends on the
	// name (draft §6.1, §8); AD keeps the resolver's bit.
	StatusAlias Status = "alias"
)

// Answer is a classified response.
type Answer struct {
	Name   string
	QType  uint16
	Status Status
	// Resolved is false when no response was received.
	Resolved bool
	RCode    uint8
	AD       bool
	// RRs holds the records of the queried type at the queried name.
	RRs    []*zone.ResourceRecord
	Reason string
}

// Classify applies the DNSSEC rules of draft §6.1 that can be applied
// to a single answer, using the AD bit as the validation state.
func Classify(name string, qtype uint16, resp Response, err error) Answer {
	a := Answer{Name: name, QType: qtype}
	if err != nil {
		a.Status = StatusFailure
		a.Reason = "resolution failure: " + err.Error()
		return a
	}
	a.Resolved, a.RCode, a.AD = true, resp.RCode, resp.AD

	if resp.RCode != rcodeNoError && resp.RCode != rcodeNXDomain {
		a.Status = StatusFailure
		a.Reason = "RCODE " + rcodeName(resp.RCode)
		return a
	}
	if alias := aliasReason(name, qtype, resp.Answer); alias != "" {
		a.Status = StatusAlias
		a.Reason = alias
		return a
	}
	a.RRs = recordsOf(name, qtype, resp.Answer)
	presence := presenceText(resp.RCode, len(a.RRs))
	switch {
	case !resp.AD:
		a.Status = StatusNotSecure
		a.Reason = presence + "; AD bit not set: Insecure, or not validated by the resolver"
	case len(a.RRs) > 0:
		a.Status = StatusSecurePresent
		a.Reason = presence
	default:
		a.Status = StatusSecureAbsent
		a.Reason = presence
	}
	return a
}

func presenceText(rcode uint8, n int) string {
	switch {
	case rcode == rcodeNXDomain:
		return "NXDOMAIN"
	case n == 0:
		return "NODATA"
	}
	return fmt.Sprintf("%d RR(s)", n)
}

// aliasReason reports why the answer section shows an alias: a CNAME or
// DNAME, or data of the queried type at another owner name.
func aliasReason(name string, qtype uint16, answer []*zone.ResourceRecord) string {
	for _, rr := range answer {
		switch {
		case rr.Type == types.TypeCNAME || rr.Type == types.TypeDNAME:
			return fmt.Sprintf("answer reached through an alias (%s %s)", typeName(rr.Type), rr.Label)
		case rr.Type == qtype && !sameName(rr.Label, name):
			return "answer reached through an alias (RRset at " + rr.Label + ")"
		}
	}
	return ""
}

func recordsOf(name string, qtype uint16, answer []*zone.ResourceRecord) []*zone.ResourceRecord {
	var out []*zone.ResourceRecord
	for _, rr := range answer {
		if rr.Type == qtype && sameName(rr.Label, name) {
			out = append(out, rr)
		}
	}
	return out
}

func sameName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func typeName(t uint16) string {
	if s, err := types.RRTypeToString(t); err == nil {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

func rcodeName(rc uint8) string {
	if s, err := types.RCodeToString(uint16(rc)); err == nil {
		return s
	}
	return fmt.Sprintf("RCODE%d", rc)
}
