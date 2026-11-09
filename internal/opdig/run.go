package opdig

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/shigeya/dnsdata-go/types"
)

// Request says what to look up.
type Request struct {
	// Name is the originator or issuer name the records are under.
	Name string
	// OriginatorKeys are Originator Key Record names below
	// _originator-key._op.<Name>, or bare record labels.
	OriginatorKeys []string
	// Revocations are Revocation Record names below
	// _revocation._op.<Name>, or bare record labels.
	Revocations []string
	// FollowPin also reads the Issuer Key Record of every CP issuer the
	// Issuer Pinning Record names.
	FollowPin bool
}

// TraceEntry records one query.
type TraceEntry struct {
	Seq      int           `json:"seq"`
	Name     string        `json:"name"`
	Type     string        `json:"type"`
	RCode    string        `json:"rcode,omitempty"`
	AD       bool          `json:"ad"`
	Answers  int           `json:"answers"`
	Duration time.Duration `json:"duration_ns"`
	Status   Status        `json:"status"`
	Outcome  Outcome       `json:"outcome"`
	Error    string        `json:"error,omitempty"`
}

// Report is the result of one run.
type Report struct {
	Name             string            `json:"name"`
	Pin              PinCheck          `json:"pin"`
	IssuerKey        OPKEYCheck        `json:"issuer_key"`
	PinnedIssuerKeys []OPKEYCheck      `json:"pinned_issuer_keys,omitempty"`
	OriginatorKeys   []OPKEYCheck      `json:"originator_keys,omitempty"`
	Revocations      []RevocationCheck `json:"revocations,omitempty"`
	Trace            []TraceEntry      `json:"trace"`
}

// Runner performs the lookups of a Request.
type Runner struct {
	Lookuper Lookuper
	// Now is the clock used to time queries; nil means time.Now.
	Now func() time.Time
}

// allowedQTypes are the only types opdig sends. OPKEY itself has no
// allocated value, and a private-use value is never sent (draft §4.1,
// §4.3).
var allowedQTypes = map[uint16]bool{
	types.TypeTLSA: true,
	types.TypeSVCB: true,
	types.TypeTXT:  true,
}

// run carries the state of one Run call.
type run struct {
	r     Runner
	trace []TraceEntry
}

// Run looks up the records of req and interprets them. It fails only
// for an unusable Request.
func (r Runner) Run(ctx context.Context, req Request) (Report, error) {
	if r.Lookuper == nil {
		return Report{}, errors.New("opdig: no lookuper configured")
	}
	name, err := NormalizeName(req.Name)
	if err != nil {
		return Report{}, err
	}
	st := &run{r: r}
	rep := Report{Name: name}

	pinAns := st.query(ctx, PinName(name), types.TypeSVCB)
	rep.Pin = InterpretPin(pinAns)
	st.setOutcome(rep.Pin.Outcome)

	rep.IssuerKey = st.opkey(ctx, RoleIssuerKey, IssuerKeyName(name))
	if req.FollowPin && rep.Pin.Outcome == OutcomePinned {
		for _, issuer := range rep.Pin.Issuers {
			if issuer == name {
				continue // already read as rep.IssuerKey
			}
			rep.PinnedIssuerKeys = append(rep.PinnedIssuerKeys, st.opkey(ctx, RolePinnedIssuerKey, IssuerKeyName(issuer)))
		}
	}
	for _, arg := range req.OriginatorKeys {
		rep.OriginatorKeys = append(rep.OriginatorKeys, st.originatorKey(ctx, arg, name))
	}
	for _, arg := range req.Revocations {
		rep.Revocations = append(rep.Revocations, st.revocation(ctx, arg, name))
	}
	rep.Trace = st.trace
	return rep, nil
}

func (st *run) opkey(ctx context.Context, role Role, name string) OPKEYCheck {
	c := InterpretOPKEY(role, st.query(ctx, name, types.TypeTLSA))
	st.setOutcome(c.Outcome)
	return c
}

func (st *run) originatorKey(ctx context.Context, arg, issuer string) OPKEYCheck {
	name, err := RecordName(OriginatorKeyRecord, arg, issuer)
	if err != nil {
		return OPKEYCheck{Role: RoleOriginatorKey, Name: arg, Status: StatusFailure,
			Outcome: OutcomeFailure, Detail: "not queried: " + err.Error()}
	}
	return st.opkey(ctx, RoleOriginatorKey, name)
}

func (st *run) revocation(ctx context.Context, arg, issuer string) RevocationCheck {
	name, err := RecordName(RevocationRecord, arg, issuer)
	if err != nil {
		return RevocationCheck{Name: arg, Status: StatusFailure,
			Outcome: OutcomeFailure, Detail: "not queried: " + err.Error()}
	}
	c := InterpretRevocation(st.query(ctx, name, types.TypeTXT))
	st.setOutcome(c.Outcome)
	return c
}

// query sends one query, classifies it and appends a trace entry whose
// outcome is filled in by setOutcome.
func (st *run) query(ctx context.Context, name string, qtype uint16) Answer {
	now := st.r.Now
	if now == nil {
		now = time.Now
	}
	start := now()
	resp, err := st.r.lookup(ctx, name, qtype)
	elapsed := now().Sub(start)

	a := Classify(name, qtype, resp, err)
	e := TraceEntry{
		Seq: len(st.trace) + 1, Name: name, Type: typeName(qtype),
		Duration: elapsed, Status: a.Status, AD: a.AD, Answers: len(a.RRs),
	}
	if err != nil {
		e.Error = err.Error()
	} else {
		e.RCode = rcodeName(a.RCode)
	}
	st.trace = append(st.trace, e)
	return a
}

func (st *run) setOutcome(o Outcome) {
	if len(st.trace) > 0 {
		st.trace[len(st.trace)-1].Outcome = o
	}
}

// lookup refuses any type outside allowedQTypes before it reaches the
// network.
func (r Runner) lookup(ctx context.Context, name string, qtype uint16) (Response, error) {
	if !allowedQTypes[qtype] {
		return Response{}, fmt.Errorf("opdig: refusing to query type %d", qtype)
	}
	return r.Lookuper.Lookup(ctx, name, qtype)
}
