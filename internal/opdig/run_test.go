package opdig

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shigeya/dnsdata-go/types"
)

const (
	originator = "op-experiment.net"
	cpIssuer   = "cpi.op-experiment.net"
	recLabel   = "7be3bdc5-2ef1-4bc1-93df-c88ea37aaff7"
)

// experimentZone answers like the experiment's zone: the originator pins
// one CP issuer, which publishes an Issuer Key Record and one Originator
// Key Record.
func experimentZone(t *testing.T) *fakeLookuper {
	t.Helper()
	f := newFake()
	f.set("_op."+originator, types.TypeSVCB, secure(rr(t, "_op."+originator+".", types.TypeSVCB, "1 "+cpIssuer+".")))
	ik := "_issuer-key._op." + cpIssuer
	f.set(ik, types.TypeTLSA, secure(
		rr(t, ik+".", types.TypeTLSA, tlsaValue(1, sha256Hex)),
		rr(t, ik+".", types.TypeTLSA, tlsaValue(2, sha512Hex)),
	))
	ok := recLabel + "._originator-key._op." + cpIssuer
	f.set(ok, types.TypeTLSA, secure(rr(t, ok+".", types.TypeTLSA, tlsaValue(1, sha256Hex))))
	return f
}

func fixedClock() func() time.Time {
	base := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	n := 0
	return func() time.Time {
		n++
		return base.Add(time.Duration(n) * time.Millisecond)
	}
}

func TestRun_OriginatorFollowsPin(t *testing.T) {
	f := experimentZone(t)
	r := Runner{Lookuper: f, Now: fixedClock()}

	rep, err := r.Run(context.Background(), Request{Name: "Op-Experiment.NET.", FollowPin: true})

	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Name != originator {
		t.Errorf("Name = %q", rep.Name)
	}
	if rep.Pin.Outcome != OutcomePinned || !equalStrings(rep.Pin.Issuers, []string{cpIssuer}) {
		t.Errorf("Pin = %s %v", rep.Pin.Outcome, rep.Pin.Issuers)
	}
	if rep.IssuerKey.Outcome != OutcomeAbsent {
		t.Errorf("own IssuerKey = %s, want absent", rep.IssuerKey.Outcome)
	}
	if len(rep.PinnedIssuerKeys) != 1 || rep.PinnedIssuerKeys[0].Outcome != OutcomeKeysPresent {
		t.Fatalf("PinnedIssuerKeys = %+v", rep.PinnedIssuerKeys)
	}
	wantOrder := []queryKey{
		{"_op." + originator, types.TypeSVCB},
		{"_issuer-key._op." + originator, types.TypeTLSA},
		{"_issuer-key._op." + cpIssuer, types.TypeTLSA},
	}
	if len(f.asked) != len(wantOrder) {
		t.Fatalf("asked %v, want %v", f.asked, wantOrder)
	}
	for i := range wantOrder {
		if f.asked[i] != wantOrder[i] {
			t.Errorf("query %d = %v, want %v", i, f.asked[i], wantOrder[i])
		}
	}
	if len(rep.Trace) != 3 {
		t.Fatalf("Trace = %d entries", len(rep.Trace))
	}
	first := rep.Trace[0]
	if first.Seq != 1 || first.Name != "_op."+originator || first.Type != "SVCB" ||
		first.RCode != "NOERROR" || !first.AD || first.Answers != 1 ||
		first.Outcome != OutcomePinned || first.Duration != time.Millisecond {
		t.Errorf("Trace[0] = %+v", first)
	}
}

func TestRun_PinToSelfIsNotQueriedTwice(t *testing.T) {
	f := newFake()
	f.set("_op."+cpIssuer, types.TypeSVCB, secure(rr(t, "_op."+cpIssuer+".", types.TypeSVCB, "1 "+cpIssuer+".")))

	rep, err := Runner{Lookuper: f}.Run(context.Background(), Request{Name: cpIssuer, FollowPin: true})

	if err != nil {
		t.Fatal(err)
	}
	if len(f.asked) != 2 || len(rep.PinnedIssuerKeys) != 0 {
		t.Errorf("asked %v, pinned issuer keys %d", f.asked, len(rep.PinnedIssuerKeys))
	}
}

func TestRun_NoFollowPin(t *testing.T) {
	f := experimentZone(t)
	rep, err := Runner{Lookuper: f}.Run(context.Background(), Request{Name: originator})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.PinnedIssuerKeys) != 0 || len(f.asked) != 2 {
		t.Errorf("followed the pin without being asked: %v", f.asked)
	}
}

func TestRun_IssuerWithRecords(t *testing.T) {
	f := experimentZone(t)
	req := Request{
		Name:           cpIssuer,
		OriginatorKeys: []string{recLabel, "deadbeef", "x._originator-key._op.other.example"},
		Revocations:    []string{"r1"},
	}

	rep, err := Runner{Lookuper: f}.Run(context.Background(), req)

	if err != nil {
		t.Fatal(err)
	}
	if rep.IssuerKey.Outcome != OutcomeKeysPresent {
		t.Errorf("IssuerKey = %s", rep.IssuerKey.Outcome)
	}
	if rep.Pin.Outcome != OutcomeUnpinned {
		t.Errorf("Pin = %s", rep.Pin.Outcome)
	}
	if len(rep.OriginatorKeys) != 3 {
		t.Fatalf("OriginatorKeys = %d", len(rep.OriginatorKeys))
	}
	if got := rep.OriginatorKeys[0]; got.Outcome != OutcomeKeysPresent || got.Name != recLabel+"._originator-key._op."+cpIssuer {
		t.Errorf("OriginatorKeys[0] = %s %s", got.Outcome, got.Name)
	}
	if got := rep.OriginatorKeys[1]; got.Outcome != OutcomeAbsent {
		t.Errorf("OriginatorKeys[1] = %s", got.Outcome)
	}
	if got := rep.OriginatorKeys[2]; got.Outcome != OutcomeFailure || !strings.Contains(got.Detail, "below") {
		t.Errorf("OriginatorKeys[2] = %s %q", got.Outcome, got.Detail)
	}
	if len(rep.Revocations) != 1 || rep.Revocations[0].Outcome != OutcomeNotRevoked {
		t.Errorf("Revocations = %+v", rep.Revocations)
	}
	// The rejected name is not queried.
	for _, q := range f.asked {
		if strings.Contains(q.name, "other.example") {
			t.Errorf("queried a name outside the issuer: %v", q)
		}
	}
	if len(rep.Trace) != 5 {
		t.Errorf("Trace = %d entries, want 5", len(rep.Trace))
	}
}

func TestRun_OnlyTLSASVCBAndTXTAreQueried(t *testing.T) {
	f := experimentZone(t)
	_, err := Runner{Lookuper: f}.Run(context.Background(), Request{
		Name: cpIssuer, FollowPin: true, OriginatorKeys: []string{recLabel}, Revocations: []string{"r1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range f.asked {
		switch q.qtype {
		case types.TypeTLSA, types.TypeSVCB, types.TypeTXT:
		default:
			t.Errorf("queried type %d for %s", q.qtype, q.name)
		}
		if q.qtype >= 65280 && q.qtype <= 65534 {
			t.Errorf("queried a private-use type %d", q.qtype)
		}
	}
}

func TestLookupGuardRejectsOtherTypes(t *testing.T) {
	f := newFake()
	r := Runner{Lookuper: f}
	for _, qtype := range []uint16{65280, 65534, types.TypeA, 0} {
		if _, err := r.lookup(context.Background(), "x.example", qtype); err == nil {
			t.Errorf("type %d: want error", qtype)
		}
	}
	if len(f.asked) != 0 {
		t.Errorf("guard let queries through: %v", f.asked)
	}
}

func TestRun_TransportErrorIsTraced(t *testing.T) {
	f := experimentZone(t)
	f.errs[queryKey{"_op." + originator, types.TypeSVCB}] = errors.New("i/o timeout")

	rep, err := Runner{Lookuper: f}.Run(context.Background(), Request{Name: originator})

	if err != nil {
		t.Fatal(err)
	}
	if rep.Pin.Outcome != OutcomeFailure {
		t.Errorf("Pin = %s", rep.Pin.Outcome)
	}
	if rep.Trace[0].Error == "" || rep.Trace[0].RCode != "" {
		t.Errorf("Trace[0] = %+v", rep.Trace[0])
	}
}

func TestRun_InvalidName(t *testing.T) {
	if _, err := (Runner{Lookuper: newFake()}).Run(context.Background(), Request{Name: "a..b"}); err == nil {
		t.Error("want error")
	}
	if _, err := (Runner{}).Run(context.Background(), Request{Name: originator}); err == nil {
		t.Error("nil Lookuper: want error")
	}
}
