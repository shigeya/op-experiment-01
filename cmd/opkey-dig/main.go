// Command opkey-dig looks up the records that draft-shigeya-dns-opkey-00
// places under _op for a name and shows how a verifier would read them:
// the Issuer Pinning Record (SVCB), the Issuer Key Record and any
// Originator Key Records (OPKEY RDATA in the transitional TLSA form),
// and any Revocation Records (TXT), with a trace of every query.
//
// The DNSSEC state shown is the AD bit of the resolver's answers; the
// tool does not validate DNSSEC itself.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/shigeya/dnsdata-go/resolver/auth"
	"github.com/shigeya/dnsdata-go/resolver/doh"
	"github.com/shigeya/dnsdata-go/resolver/dot"
	"github.com/shigeya/op-experiment-01/internal/opdig"
)

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2

	defaultTimeout = 15 * time.Second
	userAgent      = "opkey-dig"
)

const usageText = `usage: opkey-dig [flags] <name>

<name> is an originator or issuer name. opkey-dig queries
  _op.<name>              SVCB  (Issuer Pinning Record)
  _issuer-key._op.<name>  TLSA  (Issuer Key Record, read as OPKEY)
and, when asked, Originator Key Records and Revocation Records of <name>.

flags:
`

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type config struct {
	name           string
	originatorKeys []string
	revocations    []string
	followPin      bool
	json           bool
	transport      string
	server         string
	timeout        time.Duration
}

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr))
}

func runMain(args []string, stdout, stderr io.Writer) int {
	cfg, err := parseArgs(args)
	if errors.Is(err, flag.ErrHelp) {
		writeUsage(stdout)
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(stderr, "opkey-dig: %v\n", err)
		writeUsage(stderr)
		return exitUsage
	}
	q, basis, err := newQuerier(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "opkey-dig: %v\n", err)
		return exitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	runner := opdig.Runner{Lookuper: opdig.WireLookuper{Querier: q}}
	rep, err := runner.Run(ctx, opdig.Request{
		Name:           cfg.name,
		OriginatorKeys: cfg.originatorKeys,
		Revocations:    cfg.revocations,
		FollowPin:      cfg.followPin,
	})
	if err != nil {
		fmt.Fprintf(stderr, "opkey-dig: %v\n", err)
		return exitUsage
	}
	render := opdig.RenderText
	if cfg.json {
		render = opdig.RenderJSON
	}
	if err := render(stdout, rep, basis); err != nil {
		fmt.Fprintf(stderr, "opkey-dig: write output: %v\n", err)
		return exitError
	}
	return exitOK
}

// newFlagSet defines the flags of opkey-dig into cfg, oks and revs. The
// flag package's own messages are discarded; runMain prints them.
func newFlagSet(cfg *config, oks, revs *stringList) *flag.FlagSet {
	fs := flag.NewFlagSet("opkey-dig", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(oks, "originator-key", "Originator Key Record name below _originator-key._op.<name>, or a bare record label (repeatable)")
	fs.Var(revs, "revocation", "Revocation Record name below _revocation._op.<name>, or a bare record label (repeatable)")
	fs.BoolVar(&cfg.followPin, "follow-pin", true, "also read the Issuer Key Record of each CP issuer named by the Issuer Pinning Record")
	fs.BoolVar(&cfg.json, "json", false, "write the report and trace as JSON")
	fs.StringVar(&cfg.transport, "transport", "doh", "how to reach the resolver: doh, dot or udp (UDP with TCP fallback)")
	fs.StringVar(&cfg.server, "server", "", "resolver: an https DoH URL, or an address for dot and udp (required for dot and udp)")
	fs.DurationVar(&cfg.timeout, "timeout", defaultTimeout, "time limit for the whole run")
	return fs
}

// writeUsage writes the usage text and the description of every flag to w.
func writeUsage(w io.Writer) {
	var cfg config
	var oks, revs stringList
	fs := newFlagSet(&cfg, &oks, &revs)
	fmt.Fprint(w, usageText)
	fs.SetOutput(w)
	fs.PrintDefaults()
}

func parseArgs(args []string) (config, error) {
	var cfg config
	var oks, revs stringList
	fs := newFlagSet(&cfg, &oks, &revs)
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() != 1 {
		return config{}, errors.New("exactly one name is required")
	}
	cfg.name = fs.Arg(0)
	cfg.originatorKeys, cfg.revocations = oks, revs
	switch cfg.transport {
	case "doh":
		if cfg.server != "" {
			if err := checkDoHURL(cfg.server); err != nil {
				return config{}, err
			}
		}
	case "dot", "udp":
		if cfg.server == "" {
			return config{}, fmt.Errorf("-server is required with -transport %s", cfg.transport)
		}
	default:
		return config{}, fmt.Errorf("unknown transport %q", cfg.transport)
	}
	return cfg, nil
}

// checkDoHURL accepts only an https URL with a host. The AD bit is read
// as the validation state, so the channel to the resolver has to be
// authenticated (draft §6.1); plain http is refused rather than reported.
func checkDoHURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("-server: not a URL: %v", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("-server with -transport doh must be an https URL with a host, got %q", s)
	}
	return nil
}

// newQuerier builds the dnsdata-go client for cfg and says, for the
// output, what the AD bit it reports rests on.
func newQuerier(cfg config) (opdig.Querier, string, error) {
	switch cfg.transport {
	case "doh":
		providers := doh.DefaultProviders()
		if cfg.server != "" {
			providers = []string{cfg.server}
		}
		c := doh.NewClient(doh.WithProviders(providers...), doh.WithUserAgent(userAgent))
		return c, "AD bit from DoH " + strings.Join(providers, ", ") + " (first that answers)", nil
	case "dot":
		c := dot.NewClient(dot.WithServers(cfg.server))
		return c, "AD bit from DoT " + strings.Join(c.Servers(), ", "), nil
	case "udp":
		c := auth.NewClient(auth.WithServers(cfg.server))
		return c, "AD bit from " + strings.Join(c.Servers(), ", ") +
			" over UDP/TCP (unauthenticated channel: the AD bit is not protected in transit)", nil
	}
	return nil, "", fmt.Errorf("unknown transport %q", cfg.transport)
}
