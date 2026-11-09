package opdig

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// errWriter keeps the first write error so that rendering code can stay
// linear.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}

// RenderText writes the report for a human reader. basis says where the
// DNSSEC state came from.
func RenderText(w io.Writer, rep Report, basis string) error {
	ew := &errWriter{w: w}
	ew.printf("opkey-dig %s\n", rep.Name)
	ew.printf("DNSSEC state: %s (not validated by this tool)\n", basis)

	renderPin(ew, rep.Pin)
	renderOPKEY(ew, "Issuer Key Record", rep.IssuerKey)
	for _, c := range rep.PinnedIssuerKeys {
		renderOPKEY(ew, "Issuer Key Record of a pinned CP issuer", c)
	}
	for _, c := range rep.OriginatorKeys {
		renderOPKEY(ew, "Originator Key Record", c)
	}
	for _, c := range rep.Revocations {
		renderRevocation(ew, c)
	}
	if ew.err != nil {
		return ew.err
	}
	return renderTrace(w, rep.Trace)
}

func renderHeading(ew *errWriter, title, name, form string, status Status, outcome Outcome, detail string) {
	ew.printf("\n%s  %s  %s\n", title, name, form)
	ew.printf("  status:  %s\n", status)
	ew.printf("  outcome: %s: %s\n", outcome, detail)
}

func renderPin(ew *errWriter, c PinCheck) {
	renderHeading(ew, "Issuer Pinning Record", c.Name, "SVCB", c.Status, c.Outcome, c.Detail)
	for _, e := range c.Entries {
		ew.printf("    SVCB %s  %s\n", e.RData, usableText(e.Usable, e.Reason))
	}
}

func renderOPKEY(ew *errWriter, title string, c OPKEYCheck) {
	renderHeading(ew, title, c.Name, "TLSA read as OPKEY", c.Status, c.Outcome, c.Detail)
	for _, k := range c.Keys {
		ew.printf("    TLSA %s  %s\n", k.RData, usableText(k.Usable, k.Reason))
	}
}

func renderRevocation(ew *errWriter, c RevocationCheck) {
	renderHeading(ew, "Revocation Record", c.Name, "TXT", c.Status, c.Outcome, c.Detail)
	for _, s := range c.Strings {
		ew.printf("    TXT %q\n", s)
	}
}

func usableText(usable bool, reason string) string {
	text := "unusable"
	if usable {
		text = "usable"
	}
	if reason != "" {
		text += " (" + reason + ")"
	}
	return text
}

func renderTrace(w io.Writer, trace []TraceEntry) error {
	var total time.Duration
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "\nTrace\n")
	fmt.Fprintf(tw, "seq\tname\ttype\trcode\tAD\tanswers\tms\tstatus\toutcome\n")
	for _, e := range trace {
		total += e.Duration
		rcode := e.RCode
		if e.Error != "" {
			rcode = "error: " + strings.TrimSpace(e.Error)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%d\t%.1f\t%s\t%s\n",
			e.Seq, e.Name, e.Type, rcode, adText(e.AD), e.Answers, millis(e.Duration), e.Status, e.Outcome)
	}
	fmt.Fprintf(tw, "queries: %d, total %.1f ms\n", len(trace), millis(total))
	return tw.Flush()
}

func adText(ad bool) string {
	if ad {
		return "1"
	}
	return "0"
}

func millis(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

// RenderJSON writes the report and the DNSSEC basis as one JSON object.
func RenderJSON(w io.Writer, rep Report, basis string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		DNSSECBasis string `json:"dnssec_basis"`
		Report      Report `json:"report"`
	}{basis, rep})
}
