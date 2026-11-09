package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	cfg, err := parseArgs([]string{
		"-originator-key", "a", "-originator-key", "b",
		"-revocation", "r", "-json", "-follow-pin=false",
		"-transport", "udp", "-server", "192.0.2.1",
		"op-experiment.net",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.name != "op-experiment.net" || len(cfg.originatorKeys) != 2 || len(cfg.revocations) != 1 ||
		!cfg.json || cfg.followPin || cfg.transport != "udp" || cfg.server != "192.0.2.1" {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestParseArgs_Defaults(t *testing.T) {
	cfg, err := parseArgs([]string{"op-experiment.net"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.transport != "doh" || !cfg.followPin || cfg.json {
		t.Errorf("cfg = %+v", cfg)
	}
}

func TestParseArgs_Errors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"a.example", "b.example"},
		{"-transport", "carrier-pigeon", "a.example"},
		{"-transport", "udp", "a.example"},
		{"-transport", "dot", "a.example"},
		{"-server", "http://resolver.example/dns-query", "a.example"},
		{"-transport", "doh", "-server", "HTTP://resolver.example/dns-query", "a.example"},
		{"-server", "resolver.example", "a.example"},
		{"-server", "https://", "a.example"},
		{"-server", "https://%zz", "a.example"},
	} {
		if _, err := parseArgs(args); err == nil {
			t.Errorf("parseArgs(%q): want error", args)
		}
	}
}

func TestParseArgs_DoHServerHTTPS(t *testing.T) {
	cfg, err := parseArgs([]string{"-server", "https://resolver.example/dns-query", "a.example"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.server != "https://resolver.example/dns-query" {
		t.Errorf("server = %q", cfg.server)
	}
}

func TestNewQuerier_Basis(t *testing.T) {
	tests := []struct {
		cfg  config
		want []string
	}{
		{config{transport: "doh"}, []string{"DoH", "https://"}},
		{config{transport: "doh", server: "https://resolver.example/dns-query"}, []string{"DoH https://resolver.example/dns-query"}},
		{config{transport: "dot", server: "192.0.2.1"}, []string{"DoT 192.0.2.1:853"}},
		{config{transport: "udp", server: "192.0.2.1"}, []string{"192.0.2.1:53", "unauthenticated"}},
	}
	for _, tt := range tests {
		q, basis, err := newQuerier(tt.cfg)
		if err != nil || q == nil {
			t.Fatalf("newQuerier(%+v): %v", tt.cfg, err)
		}
		for _, w := range tt.want {
			if !strings.Contains(basis, w) {
				t.Errorf("basis %q lacks %q", basis, w)
			}
		}
	}
}

func TestRunMain_UsageError(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runMain(nil, &out, &errOut); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), "usage") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

// allFlags are the flags the usage text must describe.
var allFlags = []string{"-originator-key", "-revocation", "-follow-pin", "-json", "-transport", "-server", "-timeout"}

func TestRunMain_UsageErrorListsFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runMain([]string{"-no-such-flag", "a.example"}, &out, &errOut); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	for _, f := range allFlags {
		if !strings.Contains(errOut.String(), f) {
			t.Errorf("stderr lacks %q:\n%s", f, errOut.String())
		}
	}
}

func TestRunMain_Help(t *testing.T) {
	for _, arg := range []string{"-h", "-help", "--help"} {
		var out, errOut bytes.Buffer
		if code := runMain([]string{arg}, &out, &errOut); code != exitOK {
			t.Errorf("%s: exit code = %d, want %d", arg, code, exitOK)
		}
		if strings.Contains(out.String()+errOut.String(), "help requested") {
			t.Errorf("%s: help is reported as an error:\n%s%s", arg, out.String(), errOut.String())
		}
		if errOut.Len() != 0 {
			t.Errorf("%s: stderr = %q, want empty", arg, errOut.String())
		}
		for _, f := range append([]string{"usage: opkey-dig"}, allFlags...) {
			if !strings.Contains(out.String(), f) {
				t.Errorf("%s: stdout lacks %q:\n%s", arg, f, out.String())
			}
		}
	}
}
