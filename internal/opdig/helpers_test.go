package opdig

import (
	"context"
	"fmt"
	"testing"

	"github.com/shigeya/dnsdata-go/zone"
)

// Fixed digests used across the tests. They are not the digests of any
// real key.
const (
	sha256Hex = "519d038f5a3d81b2363f346dffb9a4fc3bd90942114a8b929d5769d583daf25d"
	sha512Hex = "1234d008a31a51ab3cb6acbe48eb0ef35a5073bf39944c49784deb400b455c211af9b84db50c38460e55ff969a999b271ebb0ebb2d8f3f5f28d325a27dad7bf1"
)

// rr builds a resource record from presentation text, as a resolver
// adapter would.
func rr(t *testing.T, owner string, rrtype uint16, value string) *zone.ResourceRecord {
	t.Helper()
	rec, err := zone.NewResourceRecord(owner, 3600, "IN", rrtype, value)
	if err != nil {
		t.Fatalf("NewResourceRecord(%s %d %q): %v", owner, rrtype, value, err)
	}
	return rec
}

// queryKey identifies one question in a fakeLookuper.
type queryKey struct {
	name  string
	qtype uint16
}

// fakeLookuper answers from a fixed table and records every question.
// Names in the table are written without the trailing dot.
type fakeLookuper struct {
	answers map[queryKey]Response
	errs    map[queryKey]error
	asked   []queryKey
}

func newFake() *fakeLookuper {
	return &fakeLookuper{answers: map[queryKey]Response{}, errs: map[queryKey]error{}}
}

func (f *fakeLookuper) set(name string, qtype uint16, resp Response) {
	f.answers[queryKey{name, qtype}] = resp
}

func (f *fakeLookuper) Lookup(_ context.Context, name string, qtype uint16) (Response, error) {
	k := queryKey{name, qtype}
	f.asked = append(f.asked, k)
	if err, ok := f.errs[k]; ok {
		return Response{}, err
	}
	if resp, ok := f.answers[k]; ok {
		return resp, nil
	}
	// Anything not in the table is a Secure NXDOMAIN.
	return Response{RCode: rcodeNXDomain, AD: true}, nil
}

// secure returns a Secure NOERROR response carrying rrs in the answer
// section.
func secure(rrs ...*zone.ResourceRecord) Response {
	return Response{RCode: rcodeNoError, AD: true, Answer: rrs}
}

func tlsaValue(mt int, hexDigest string) string {
	return fmt.Sprintf("3 1 %d %s", mt, hexDigest)
}
