package opdig

import (
	"errors"
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

func TestClassify(t *testing.T) {
	const name = "_issuer-key._op.cpi.op-experiment.net"
	tlsa := rr(t, name+".", types.TypeTLSA, tlsaValue(1, sha256Hex))
	sig := rr(t, name+".", types.TypeRRSIG, "TLSA 13 5 3600 1796625540 1794033540 46584 op-experiment.net. AAAA")
	tests := []struct {
		label     string
		resp      Response
		err       error
		want      Status
		wantCount int
	}{
		{label: "secure data", resp: secure(tlsa, sig), want: StatusSecurePresent, wantCount: 1},
		{label: "secure NODATA", resp: secure(), want: StatusSecureAbsent},
		{label: "secure NXDOMAIN", resp: Response{RCode: rcodeNXDomain, AD: true}, want: StatusSecureAbsent},
		{label: "data without AD", resp: Response{RCode: rcodeNoError, Answer: []*zone.ResourceRecord{tlsa}}, want: StatusNotSecure, wantCount: 1},
		{label: "NXDOMAIN without AD", resp: Response{RCode: rcodeNXDomain}, want: StatusNotSecure},
		{label: "SERVFAIL", resp: Response{RCode: rcodeServFail}, want: StatusFailure},
		{label: "REFUSED with AD", resp: Response{RCode: 5, AD: true}, want: StatusFailure},
		{label: "transport error", err: errors.New("timeout"), want: StatusFailure},
		{
			label: "CNAME in the answer is an alias",
			resp:  secure(rr(t, name+".", types.TypeCNAME, "elsewhere.example."), rr(t, "elsewhere.example.", types.TypeTLSA, tlsaValue(1, sha256Hex))),
			want:  StatusAlias,
		},
		{
			label: "RRset at another owner is an alias",
			resp:  secure(rr(t, "elsewhere.example.", types.TypeTLSA, tlsaValue(1, sha256Hex))),
			want:  StatusAlias,
		},
		{
			label: "alias without AD is still an alias",
			resp:  Response{RCode: rcodeNoError, Answer: []*zone.ResourceRecord{rr(t, name+".", types.TypeCNAME, "elsewhere.example.")}},
			want:  StatusAlias,
		},
		{
			label: "SERVFAIL with a CNAME is a failure, not an alias",
			resp:  Response{RCode: rcodeServFail, Answer: []*zone.ResourceRecord{rr(t, name+".", types.TypeCNAME, "elsewhere.example.")}},
			want:  StatusFailure,
		},
		{
			label: "owner name differing only in case is the same name",
			resp:  secure(rr(t, "_ISSUER-KEY._op.CPI.op-experiment.net.", types.TypeTLSA, tlsaValue(1, sha256Hex))),
			want:  StatusSecurePresent, wantCount: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			got := Classify(name, types.TypeTLSA, tt.resp, tt.err)
			if got.Status != tt.want {
				t.Errorf("Status = %s, want %s (reason %q)", got.Status, tt.want, got.Reason)
			}
			if len(got.RRs) != tt.wantCount {
				t.Errorf("RRs = %d, want %d", len(got.RRs), tt.wantCount)
			}
			if got.Status != StatusSecurePresent && got.Reason == "" {
				t.Error("Reason is empty")
			}
		})
	}
}
