package opdig

import (
	"testing"

	"github.com/shigeya/dnsdata-go/types"
	"github.com/shigeya/dnsdata-go/zone"
)

func answerOf(t *testing.T, name string, qtype uint16, resp Response) Answer {
	t.Helper()
	return Classify(name, qtype, resp, nil)
}

func TestInterpretOPKEY(t *testing.T) {
	const name = "_issuer-key._op.cpi.op-experiment.net"
	owner := name + "."
	tests := []struct {
		label       string
		resp        Response
		role        Role
		wantOutcome Outcome
		wantUsable  int
		wantKeys    int
	}{
		{
			label:       "two usable RRs",
			resp:        secure(rr(t, owner, types.TypeTLSA, tlsaValue(1, sha256Hex)), rr(t, owner, types.TypeTLSA, tlsaValue(2, sha512Hex))),
			role:        RoleIssuerKey,
			wantOutcome: OutcomeKeysPresent, wantUsable: 2, wantKeys: 2,
		},
		{
			label:       "only unusable RRs: present, no key valid",
			resp:        secure(rr(t, owner, types.TypeTLSA, "2 1 1 "+sha256Hex), rr(t, owner, types.TypeTLSA, "3 0 1 "+sha256Hex), rr(t, owner, types.TypeTLSA, "3 1 1 abcd")),
			role:        RoleIssuerKey,
			wantOutcome: OutcomeNoUsableKey, wantKeys: 3,
		},
		{
			label:       "secure absence",
			resp:        secure(),
			role:        RoleOriginatorKey,
			wantOutcome: OutcomeAbsent,
		},
		{
			label:       "no AD",
			resp:        Response{RCode: rcodeNoError, Answer: secure(rr(t, owner, types.TypeTLSA, tlsaValue(1, sha256Hex))).Answer},
			role:        RoleIssuerKey,
			wantOutcome: OutcomeNoAssurance, wantKeys: 1, wantUsable: 1,
		},
		{
			label:       "SERVFAIL",
			resp:        Response{RCode: rcodeServFail},
			role:        RoleIssuerKey,
			wantOutcome: OutcomeFailure,
		},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			got := InterpretOPKEY(tt.role, answerOf(t, name, types.TypeTLSA, tt.resp))
			if got.Outcome != tt.wantOutcome {
				t.Errorf("Outcome = %s, want %s (%s)", got.Outcome, tt.wantOutcome, got.Detail)
			}
			if len(got.Keys) != tt.wantKeys {
				t.Errorf("Keys = %d, want %d", len(got.Keys), tt.wantKeys)
			}
			usable := 0
			for _, k := range got.Keys {
				if k.Usable {
					usable++
				} else if k.Reason == "" {
					t.Errorf("unusable key %s has no reason", k.RData)
				}
			}
			if usable != tt.wantUsable {
				t.Errorf("usable = %d, want %d", usable, tt.wantUsable)
			}
			if got.Detail == "" {
				t.Error("Detail is empty")
			}
		})
	}
}

func TestInterpretOPKEY_MalformedWithoutADIsNoAssurance(t *testing.T) {
	const name = "_issuer-key._op.cpi.op-experiment.net"
	resp := Response{RCode: rcodeNoError, Answer: secure(rr(t, name+".", types.TypeTLSA, `\# 2 0301`)).Answer}
	got := InterpretOPKEY(RoleIssuerKey, answerOf(t, name, types.TypeTLSA, resp))
	if got.Outcome != OutcomeNoAssurance {
		t.Errorf("Outcome = %s (%s), want no-assurance", got.Outcome, got.Detail)
	}
}

func TestInterpretPin_NoADMentionsBothReadings(t *testing.T) {
	got := InterpretPin(answerOf(t, "_op.op-experiment.net", types.TypeSVCB, Response{RCode: rcodeNXDomain}))
	if !containsAll(got.Detail, "§8.2", "unpinned") {
		t.Errorf("Detail = %q", got.Detail)
	}
}

// cnameTo returns a response whose answer section reaches name through a
// CNAME to target, with the target's RRset of qtype.
func cnameTo(t *testing.T, name, target string, qtype uint16, value string, ad bool) Response {
	t.Helper()
	return Response{RCode: rcodeNoError, AD: ad, Answer: []*zone.ResourceRecord{
		rr(t, name+".", types.TypeCNAME, target+"."),
		rr(t, target+".", qtype, value),
	}}
}

func TestInterpretPin_Alias(t *testing.T) {
	const name = "_op.op-experiment.net"
	tests := []struct {
		label       string
		resp        Response
		wantOutcome Outcome
		wantDetail  []string
	}{
		{
			label:       "alias with AD is read as Insecure: unpinned (draft §8)",
			resp:        cnameTo(t, name, "elsewhere.example", types.TypeSVCB, "1 a.example.", true),
			wantOutcome: OutcomeUnpinned,
			wantDetail:  []string{"alias", "§8", "unpinned"},
		},
		{
			label:       "alias without AD carries no assurance and names the §8 reading",
			resp:        cnameTo(t, name, "elsewhere.example", types.TypeSVCB, "1 a.example.", false),
			wantOutcome: OutcomeNoAssurance,
			wantDetail:  []string{"alias", "§8", "unpinned"},
		},
		{
			label:       "SERVFAIL with a CNAME stays a failure",
			resp:        Response{RCode: rcodeServFail, Answer: []*zone.ResourceRecord{rr(t, name+".", types.TypeCNAME, "elsewhere.example.")}},
			wantOutcome: OutcomeFailure,
		},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			got := InterpretPin(answerOf(t, name, types.TypeSVCB, tt.resp))
			if got.Outcome != tt.wantOutcome {
				t.Fatalf("Outcome = %s, want %s (%s)", got.Outcome, tt.wantOutcome, got.Detail)
			}
			if !containsAll(got.Detail, tt.wantDetail...) {
				t.Errorf("Detail = %q, want %q", got.Detail, tt.wantDetail)
			}
			if contains(got.Detail, "§6.1") && tt.wantOutcome != OutcomeFailure {
				t.Errorf("Detail cites §6.1 for an alias at the pin: %q", got.Detail)
			}
			if len(got.Issuers) != 0 || len(got.Entries) != 0 {
				t.Errorf("records at the alias target were used: issuers %v, entries %v", got.Issuers, got.Entries)
			}
		})
	}
}

func TestInterpretOPKEYAndRevocation_AliasIsFailure(t *testing.T) {
	const keyName = "_issuer-key._op.cpi.op-experiment.net"
	key := InterpretOPKEY(RoleIssuerKey, answerOf(t, keyName, types.TypeTLSA,
		cnameTo(t, keyName, "elsewhere.example", types.TypeTLSA, tlsaValue(1, sha256Hex), true)))
	if key.Outcome != OutcomeFailure || !containsAll(key.Detail, "§6.1", "alias") {
		t.Errorf("OPKEY: Outcome %s, Detail %q", key.Outcome, key.Detail)
	}
	const revName = "x._revocation._op.pai.op-experiment.net"
	rev := InterpretRevocation(answerOf(t, revName, types.TypeTXT,
		cnameTo(t, revName, "elsewhere.example", types.TypeTXT, `"v=op1; revoked=2026-11-14T10:00:00Z"`, true)))
	if rev.Outcome != OutcomeFailure || !containsAll(rev.Detail, "§6.1", "alias") {
		t.Errorf("Revocation: Outcome %s, Detail %q", rev.Outcome, rev.Detail)
	}
}

func TestInterpretOPKEY_OriginatorAbsenceSaysRevoked(t *testing.T) {
	const name = "x._originator-key._op.cpi.op-experiment.net"
	got := InterpretOPKEY(RoleOriginatorKey, answerOf(t, name, types.TypeTLSA, secure()))
	if got.Outcome != OutcomeAbsent || !containsAll(got.Detail, "CP", "revoked") {
		t.Errorf("Outcome %s, Detail %q", got.Outcome, got.Detail)
	}
}

func TestInterpretPin(t *testing.T) {
	const name = "_op.op-experiment.net"
	owner := name + "."
	tests := []struct {
		label       string
		resp        Response
		wantOutcome Outcome
		wantIssuers []string
	}{
		{
			label:       "ServiceMode pins one issuer",
			resp:        secure(rr(t, owner, types.TypeSVCB, "1 CPI.op-experiment.net.")),
			wantOutcome: OutcomePinned, wantIssuers: []string{"cpi.op-experiment.net"},
		},
		{
			label: "ServiceMode with two issuers, sorted and deduplicated",
			resp: secure(
				rr(t, owner, types.TypeSVCB, "2 b.example."),
				rr(t, owner, types.TypeSVCB, "1 a.example."),
				rr(t, owner, types.TypeSVCB, "3 a.example."),
			),
			wantOutcome: OutcomePinned, wantIssuers: []string{"a.example", "b.example"},
		},
		{
			label:       "ServiceMode with target dot pins the empty set",
			resp:        secure(rr(t, owner, types.TypeSVCB, "1 .")),
			wantOutcome: OutcomePinned, wantIssuers: []string{},
		},
		{
			label:       "AliasMode dot declares no OP",
			resp:        secure(rr(t, owner, types.TypeSVCB, "0 .")),
			wantOutcome: OutcomeNoOPDeclared,
		},
		{
			label:       "AliasMode with another target is read as the declaration",
			resp:        secure(rr(t, owner, types.TypeSVCB, "0 elsewhere.example.")),
			wantOutcome: OutcomeNoOPDeclared,
		},
		{
			label:       "AliasMode mixed with ServiceMode is read as the declaration",
			resp:        secure(rr(t, owner, types.TypeSVCB, "0 ."), rr(t, owner, types.TypeSVCB, "1 a.example.")),
			wantOutcome: OutcomeNoOPDeclared,
		},
		{
			label:       "only RRs with the mandatory key: no usable RR",
			resp:        secure(rr(t, owner, types.TypeSVCB, "1 a.example. mandatory=alpn alpn=h2")),
			wantOutcome: OutcomeNoUsablePin,
		},
		{
			label:       "mandatory RR is skipped, the other pins",
			resp:        secure(rr(t, owner, types.TypeSVCB, "1 a.example. mandatory=alpn alpn=h2"), rr(t, owner, types.TypeSVCB, "2 b.example. alpn=h2")),
			wantOutcome: OutcomePinned, wantIssuers: []string{"b.example"},
		},
		{
			label:       "secure absence leaves the originator unpinned",
			resp:        Response{RCode: rcodeNXDomain, AD: true},
			wantOutcome: OutcomeUnpinned,
		},
		{
			label:       "no AD",
			resp:        Response{RCode: rcodeNXDomain},
			wantOutcome: OutcomeNoAssurance,
		},
		{
			label:       "SERVFAIL",
			resp:        Response{RCode: rcodeServFail},
			wantOutcome: OutcomeFailure,
		},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			got := InterpretPin(answerOf(t, name, types.TypeSVCB, tt.resp))
			if got.Outcome != tt.wantOutcome {
				t.Fatalf("Outcome = %s, want %s (%s)", got.Outcome, tt.wantOutcome, got.Detail)
			}
			if tt.wantIssuers != nil && !equalStrings(got.Issuers, tt.wantIssuers) {
				t.Errorf("Issuers = %v, want %v", got.Issuers, tt.wantIssuers)
			}
			if got.Detail == "" {
				t.Error("Detail is empty")
			}
		})
	}
}

func TestInterpretRevocation(t *testing.T) {
	const name = "x._revocation._op.pai.op-experiment.net"
	owner := name + "."
	noAD := secure(rr(t, owner, types.TypeTXT, `"v=op1; revoked=2026-11-14T10:00:00Z"`))
	noAD.AD = false
	tests := []struct {
		label       string
		resp        Response
		wantOutcome Outcome
		wantTime    string
	}{
		{
			label:       "well-formed record",
			resp:        secure(rr(t, owner, types.TypeTXT, `"v=op1; revoked=2026-11-14T10:00:00Z"`)),
			wantOutcome: OutcomeRevoked, wantTime: "2026-11-14T10:00:00Z",
		},
		{
			label:       "unparsable record still revokes",
			resp:        secure(rr(t, owner, types.TypeTXT, `"garbage"`)),
			wantOutcome: OutcomeRevoked,
		},
		{
			label:       "bad time still revokes",
			resp:        secure(rr(t, owner, types.TypeTXT, `"v=op1; revoked=yesterday"`)),
			wantOutcome: OutcomeRevoked,
		},
		{
			label:       "two strings still revoke",
			resp:        secure(rr(t, owner, types.TypeTXT, `"v=op1; " "revoked=2026-11-14T10:00:00Z"`)),
			wantOutcome: OutcomeRevoked,
		},
		{
			label:       "secure absence",
			resp:        Response{RCode: rcodeNXDomain, AD: true},
			wantOutcome: OutcomeNotRevoked,
		},
		{label: "no AD", resp: noAD, wantOutcome: OutcomeNoAssurance},
		{
			label:       "SERVFAIL",
			resp:        Response{RCode: rcodeServFail},
			wantOutcome: OutcomeFailure,
		},
	}
	for _, tt := range tests {
		t.Run(tt.label, func(t *testing.T) {
			got := InterpretRevocation(answerOf(t, name, types.TypeTXT, tt.resp))
			if got.Outcome != tt.wantOutcome {
				t.Fatalf("Outcome = %s, want %s (%s)", got.Outcome, tt.wantOutcome, got.Detail)
			}
			if got.RevokedAt != tt.wantTime {
				t.Errorf("RevokedAt = %q, want %q", got.RevokedAt, tt.wantTime)
			}
			if got.Detail == "" {
				t.Error("Detail is empty")
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
