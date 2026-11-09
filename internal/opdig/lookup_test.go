package opdig

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/wire"
	"github.com/shigeya/dnsdata-go/zone"
)

// fakeQuerier returns fixed message octets.
type fakeQuerier struct {
	msg []byte
	err error
}

func (f fakeQuerier) Query(context.Context, string, uint16) ([]byte, error) {
	return f.msg, f.err
}

type rawRecord struct {
	name   string
	rrtype uint16
	rdata  []byte
}

// buildResponse assembles a DNS response with uncompressed names: one
// question, the given answer and authority records.
func buildResponse(t *testing.T, flags uint16, qname string, qtype uint16, answer, authority []rawRecord) []byte {
	t.Helper()
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:], 0x1234)
	binary.BigEndian.PutUint16(msg[2:], flags)
	binary.BigEndian.PutUint16(msg[4:], 1)
	binary.BigEndian.PutUint16(msg[6:], uint16(len(answer)))
	binary.BigEndian.PutUint16(msg[8:], uint16(len(authority)))
	msg = append(msg, wireName(t, qname)...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	for _, r := range append(append([]rawRecord(nil), answer...), authority...) {
		msg = append(msg, wireName(t, r.name)...)
		msg = binary.BigEndian.AppendUint16(msg, r.rrtype)
		msg = binary.BigEndian.AppendUint16(msg, 1)
		msg = binary.BigEndian.AppendUint32(msg, 300)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(r.rdata)))
		msg = append(msg, r.rdata...)
	}
	return msg
}

func wireName(t *testing.T, name string) []byte {
	t.Helper()
	b, err := wire.DomainNameToWirePreserveCase(name)
	if err != nil {
		t.Fatalf("DomainNameToWire(%q): %v", name, err)
	}
	return b
}

func TestWireLookuper_SplitsSectionsAndReadsHeader(t *testing.T) {
	key, err := zone.ParseOPKEY(tlsaValue(1, sha256Hex))
	if err != nil {
		t.Fatal(err)
	}
	const qname = "_issuer-key._op.cpi.op-experiment.net."
	const flagsQRRDRAAD = 0x8000 | 0x0100 | 0x0080 | 0x0020
	msg := buildResponse(t, flagsQRRDRAAD, qname, types.TypeTLSA,
		[]rawRecord{{qname, types.TypeTLSA, key.RData()}},
		[]rawRecord{{"op-experiment.net.", types.TypeTXT, []byte("\x05hello")}},
	)

	resp, err := WireLookuper{Querier: fakeQuerier{msg: msg}}.Lookup(context.Background(), qname, types.TypeTLSA)

	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !resp.AD || resp.RCode != rcodeNoError {
		t.Errorf("AD=%v RCode=%d, want AD and NOERROR", resp.AD, resp.RCode)
	}
	if len(resp.Answer) != 1 || len(resp.Authority) != 1 {
		t.Fatalf("answer=%d authority=%d, want 1 and 1", len(resp.Answer), len(resp.Authority))
	}
	if resp.Answer[0].Type != types.TypeTLSA {
		t.Errorf("answer type = %d", resp.Answer[0].Type)
	}
}

func TestWireLookuper_NXDomainWithoutAD(t *testing.T) {
	const qname = "_op.example.org."
	msg := buildResponse(t, 0x8000|0x0080|uint16(rcodeNXDomain), qname, types.TypeSVCB, nil, nil)

	resp, err := WireLookuper{Querier: fakeQuerier{msg: msg}}.Lookup(context.Background(), qname, types.TypeSVCB)

	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if resp.AD || resp.RCode != rcodeNXDomain {
		t.Errorf("AD=%v RCode=%d, want no AD and NXDOMAIN", resp.AD, resp.RCode)
	}
}

func TestWireLookuper_TransportAndParseErrors(t *testing.T) {
	boom := errors.New("boom")
	if _, err := (WireLookuper{Querier: fakeQuerier{err: boom}}).Lookup(context.Background(), "a.", types.TypeTXT); !errors.Is(err, boom) {
		t.Errorf("transport error not passed through: %v", err)
	}
	if _, err := (WireLookuper{Querier: fakeQuerier{msg: []byte{1, 2, 3}}}).Lookup(context.Background(), "a.", types.TypeTXT); err == nil {
		t.Error("short message: want error")
	}
	if _, err := (WireLookuper{}).Lookup(context.Background(), "a.", types.TypeTXT); err == nil {
		t.Error("nil querier: want error")
	}
}
