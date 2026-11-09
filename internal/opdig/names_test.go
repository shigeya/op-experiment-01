package opdig

import (
	"strings"
	"testing"
)

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "op-experiment.net", want: "op-experiment.net"},
		{in: "Op-Experiment.NET.", want: "op-experiment.net"},
		{in: "_op.example.org", want: "_op.example.org"},
		{in: "", wantErr: true},
		{in: ".", wantErr: true},
		{in: "a..b", wantErr: true},
		{in: "bücher.example", wantErr: true},
		{in: strings.Repeat("a", 64) + ".example", wantErr: true},
		{in: "has space.example", wantErr: true},
	}
	for _, tt := range tests {
		got, err := NormalizeName(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("NormalizeName(%q) = %q, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeName(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("NormalizeName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestFixedNames(t *testing.T) {
	if got := PinName("op-experiment.net"); got != "_op.op-experiment.net" {
		t.Errorf("PinName = %q", got)
	}
	if got := IssuerKeyName("cpi.op-experiment.net"); got != "_issuer-key._op.cpi.op-experiment.net" {
		t.Errorf("IssuerKeyName = %q", got)
	}
}

func TestRecordName(t *testing.T) {
	const issuer = "cpi.op-experiment.net"
	const label = "7be3bdc5-2ef1-4bc1-93df-c88ea37aaff7"
	tests := []struct {
		name    string
		kind    RecordKind
		arg     string
		want    string
		wantErr bool
	}{
		{
			name: "bare label is composed under the issuer",
			kind: OriginatorKeyRecord, arg: label,
			want: label + "._originator-key._op." + issuer,
		},
		{
			name: "full name below the node is used as is",
			kind: OriginatorKeyRecord, arg: strings.ToUpper(label) + "._originator-key._op." + issuer + ".",
			want: label + "._originator-key._op." + issuer,
		},
		{
			name: "extra labels between the record label and the node are allowed",
			kind: OriginatorKeyRecord, arg: label + ".shard1._originator-key._op." + issuer,
			want: label + ".shard1._originator-key._op." + issuer,
		},
		{
			name: "revocation label is composed under _revocation",
			kind: RevocationRecord, arg: label,
			want: label + "._revocation._op." + issuer,
		},
		{
			name: "name under another issuer is rejected",
			kind: OriginatorKeyRecord, arg: label + "._originator-key._op.cip.op-experiment.net",
			wantErr: true,
		},
		{
			name: "the node itself is rejected",
			kind: OriginatorKeyRecord, arg: "_originator-key._op." + issuer,
			wantErr: true,
		},
		{
			name: "suffix match that is not on a label boundary is rejected",
			kind: OriginatorKeyRecord, arg: "x._originator-key._op.xcpi.op-experiment.net",
			wantErr: true,
		},
		{
			name: "revocation name under _originator-key is rejected",
			kind: RevocationRecord, arg: label + "._originator-key._op." + issuer,
			wantErr: true,
		},
		{
			name: "empty argument is rejected",
			kind: RevocationRecord, arg: "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RecordName(tt.kind, tt.arg, issuer)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("RecordName = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("RecordName: %v", err)
			}
			if got != tt.want {
				t.Errorf("RecordName = %q, want %q", got, tt.want)
			}
		})
	}
}
