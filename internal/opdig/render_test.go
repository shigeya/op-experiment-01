package opdig

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func sampleReport(t *testing.T) Report {
	t.Helper()
	rep, err := Runner{Lookuper: experimentZone(t), Now: fixedClock()}.Run(context.Background(), Request{
		Name: originator, FollowPin: true, Revocations: []string{"r1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestRenderText(t *testing.T) {
	var buf bytes.Buffer
	const basis = "AD bit from DoH https://resolver.example/dns-query"

	if err := RenderText(&buf, sampleReport(t), basis); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	for _, want := range []string{
		"opkey-dig " + originator,
		basis,
		"_op." + originator,
		"pinned to " + cpIssuer,
		"_issuer-key._op." + cpIssuer,
		"3 1 1 " + sha256Hex,
		"keys-present",
		"r1._revocation._op." + originator,
		"not-revoked",
		"queries: 4",
		"SVCB",
		"TLSA",
		"TXT",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
}

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer

	if err := RenderJSON(&buf, sampleReport(t), "basis"); err != nil {
		t.Fatal(err)
	}

	var got struct {
		DNSSECBasis string `json:"dnssec_basis"`
		Report      Report `json:"report"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	if got.DNSSECBasis != "basis" || len(got.Report.Trace) != 4 || got.Report.Trace[0].Type != "SVCB" {
		t.Errorf("decoded %+v", got)
	}
}
