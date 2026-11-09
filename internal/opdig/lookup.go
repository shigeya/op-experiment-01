package opdig

import (
	"context"
	"errors"
	"fmt"

	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// RCODE values used here (RFC 1035 §4.1.1).
const (
	rcodeNoError  uint8 = 0
	rcodeServFail uint8 = 2
	rcodeNXDomain uint8 = 3
)

// Response is one DNS answer as opdig needs it: the header bits and the
// answer and authority sections, kept apart so that an answer reached
// through an alias can be told from a direct one.
type Response struct {
	RCode     uint8
	AD        bool
	Answer    []*zone.ResourceRecord
	Authority []*zone.ResourceRecord
}

// Lookuper sends one query. Implementations are swapped in tests.
type Lookuper interface {
	Lookup(ctx context.Context, name string, qtype uint16) (Response, error)
}

// Querier returns the raw response octets for one query. The auth,
// DoT and DoH clients of dnsdata-go satisfy it.
type Querier interface {
	Query(ctx context.Context, name string, qtype uint16) ([]byte, error)
}

// WireLookuper adapts a Querier into a Lookuper.
type WireLookuper struct {
	Querier Querier
}

// Lookup sends the query and parses the response.
func (w WireLookuper) Lookup(ctx context.Context, name string, qtype uint16) (Response, error) {
	if w.Querier == nil {
		return Response{}, errors.New("opdig: no querier configured")
	}
	raw, err := w.Querier.Query(ctx, name, qtype)
	if err != nil {
		return Response{}, err
	}
	msg, err := wire.ParseMessage(raw)
	if err != nil {
		return Response{}, fmt.Errorf("opdig: parse response: %w", err)
	}
	answer, err := toRecords(msg.Raw, msg.Answer)
	if err != nil {
		return Response{}, err
	}
	authority, err := toRecords(msg.Raw, msg.Authority)
	if err != nil {
		return Response{}, err
	}
	return Response{
		RCode:     msg.Header.RCode(),
		AD:        msg.Header.AD(),
		Answer:    answer,
		Authority: authority,
	}, nil
}

func toRecords(raw []byte, rrs []wire.RawRR) ([]*zone.ResourceRecord, error) {
	out := make([]*zone.ResourceRecord, 0, len(rrs))
	for _, rr := range rrs {
		value, err := wire.RDataToString(raw, rr.Type, rr.RData, rr.RDataStart)
		if err != nil {
			return nil, fmt.Errorf("opdig: record %s type %d: %w", rr.Name, rr.Type, err)
		}
		rec, err := zone.NewResourceRecordWithRData(rr.Name, rr.TTL, rr.Class, rr.Type, value, rr.RData)
		if err != nil {
			return nil, fmt.Errorf("opdig: record %s type %d: %w", rr.Name, rr.Type, err)
		}
		out = append(out, rec)
	}
	return out, nil
}
