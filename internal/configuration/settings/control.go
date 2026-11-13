package settings

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/qdm12/dns/v2/pkg/provider"
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

// Egress source kinds and defaults.
const (
	sourceKindHTTP     = "http"
	sourceKindDNS      = "dns"
	sourceKindPublicIP = "publicip"
	sourceKindStatic   = "static"

	sourceSpecParts            = 2
	defaultEgressQuorum        = 2
	defaultEgressMinSources    = 3
	defaultEgressCacheTTL      = 10 * time.Second
	defaultEgressSourceTimeout = 1500 * time.Millisecond
	defaultEgressBackoff       = 30 * time.Second
	defaultEgressBackoffMax    = 300 * time.Second

	defaultCanaryMinBodyBytes = 1
	defaultCanaryTimeout      = 2000 * time.Millisecond
	sha256HexBytes            = 32
)

// Control contains the settings for the control plane extensions.
type Control struct {
	// Enabled enables the control plane routes.
	// It defaults to true.
	Enabled *bool
	// StateDir is the directory used to persist the control plane state.
	// It cannot be empty in the internal state and defaults to /gluetun/control.
	StateDir string
	// StateMode defines how the persisted state and the environment are merged.
	// It can be "state", "env" or "merge", and defaults to "state".
	StateMode string
	// Egress contains the egress verification settings.
	Egress Egress
	// DNS contains the DNS ladder settings.
	DNS DNSLadder
	// Transport contains the transport ladder settings.
	Transport TransportLadder
	// Canary contains the neutral HTTP canary settings.
	Canary Canary
}

func (c Control) validate() (err error) {
	if c.Enabled != nil && !*c.Enabled {
		return nil
	}

	if !path.IsAbs(c.StateDir) {
		return fmt.Errorf("state directory path must be absolute: %s", c.StateDir)
	}

	info, err := os.Stat(c.StateDir)
	switch {
	case err == nil && !info.IsDir():
		return fmt.Errorf("state directory path is not a directory: %s", c.StateDir)
	case err == nil:
		probeFile, err := os.CreateTemp(c.StateDir, ".write-probe-*")
		if err != nil {
			return fmt.Errorf("state directory is not writable: %w", err)
		}
		probeName := probeFile.Name()
		_ = probeFile.Close()
		_ = os.Remove(probeName)
	case os.IsNotExist(err):
		// The directory is created when the control plane starts.
	default:
		return fmt.Errorf("checking state directory: %w", err)
	}

	err = validate.IsOneOf(c.StateMode, "state", "env", "merge")
	if err != nil {
		return fmt.Errorf("state mode: %w", err)
	}

	err = c.Egress.validate()
	if err != nil {
		return fmt.Errorf("egress: %w", err)
	}

	err = c.DNS.validate()
	if err != nil {
		return fmt.Errorf("dns: %w", err)
	}

	err = c.Transport.validate()
	if err != nil {
		return fmt.Errorf("transport: %w", err)
	}

	err = c.Canary.validate()
	if err != nil {
		return fmt.Errorf("canary: %w", err)
	}

	return nil
}

func (c Control) copy() (copied Control) {
	return Control{
		Enabled:   gosettings.CopyPointer(c.Enabled),
		StateDir:  c.StateDir,
		StateMode: c.StateMode,
		Egress:    c.Egress.copy(),
		DNS:       c.DNS.copy(),
		Transport: c.Transport.copy(),
		Canary:    c.Canary,
	}
}

// overrideWith overrides fields of the receiver settings object with any
// field set in the other settings.
func (c *Control) overrideWith(other Control) {
	c.Enabled = gosettings.OverrideWithPointer(c.Enabled, other.Enabled)
	c.StateDir = gosettings.OverrideWithComparable(c.StateDir, other.StateDir)
	c.StateMode = gosettings.OverrideWithComparable(c.StateMode, other.StateMode)
	c.Egress.overrideWith(other.Egress)
	c.DNS.overrideWith(other.DNS)
	c.Transport.overrideWith(other.Transport)
	c.Canary.overrideWith(other.Canary)
}

func (c *Control) setDefaults() {
	c.Enabled = gosettings.DefaultPointer(c.Enabled, true)
	c.StateDir = gosettings.DefaultComparable(c.StateDir, "/gluetun/control")
	c.StateMode = gosettings.DefaultComparable(c.StateMode, "state")
	c.Egress.setDefaults()
	c.DNS.setDefaults()
	c.Transport.setDefaults()
	c.Canary.setDefaults()
}

func (c Control) String() string {
	return c.toLinesNode().String()
}

func (c Control) toLinesNode() (node *gotree.Node) {
	node = gotree.New("Control plane settings:")
	node.Appendf("Enabled: %s", gosettings.BoolToYesNo(c.Enabled))
	node.Appendf("State directory: %s", c.StateDir)
	node.Appendf("State mode: %s", c.StateMode)
	node.AppendNode(c.Egress.toLinesNode())
	node.AppendNode(c.DNS.toLinesNode())
	node.AppendNode(c.Transport.toLinesNode())
	node.AppendNode(c.Canary.toLinesNode())
	return node
}

func (c *Control) read(r *reader.Reader) (err error) {
	c.Enabled, err = r.BoolPtr("CONTROL_PLANE_ENABLED")
	if err != nil {
		return err
	}

	c.StateDir = r.String("CONTROL_STATE_DIR")
	c.StateMode = r.String("CONTROL_STATE_MODE")

	err = c.Egress.read(r)
	if err != nil {
		return err
	}

	err = c.DNS.read(r)
	if err != nil {
		return err
	}

	err = c.Transport.read(r)
	if err != nil {
		return err
	}

	return c.Canary.read(r)
}

// Egress contains the egress verification settings.
type Egress struct {
	// Enabled enables egress verification.
	// It defaults to true.
	Enabled *bool
	// Sources is the ordered list of sources in the kind:name format.
	// It defaults to [http:ipify dns:whoami publicip:internal].
	Sources []string
	// Quorum is the number of agreeing sources required to consider an
	// egress IP verified. It defaults to 2.
	Quorum uint
	// MinSources is the minimal number of usable sources.
	// It defaults to 3.
	MinSources uint
	// AllowSingle allows a single source to be used for verification.
	// It defaults to false.
	AllowSingle *bool
	// CacheTTL is the duration for which a verification result is cached.
	// It defaults to 10 seconds.
	CacheTTL time.Duration
	// SourceTimeout is the timeout for a single source.
	// It defaults to 1500 milliseconds.
	SourceTimeout time.Duration
	// SourceBackoff is the base backoff for a failing source.
	// It defaults to 30 seconds.
	SourceBackoff time.Duration
	// SourceBackoffMax is the maximum backoff for a failing source.
	// It defaults to 300 seconds.
	SourceBackoffMax time.Duration
	// Family is the primary IP family to verify.
	// It can be "4", "6" or "both", and defaults to "4".
	Family string
	// ForbiddenIPs is the list of IP addresses to reject.
	ForbiddenIPs []netip.Addr
	// HostIPAuto captures the underlay host IP at startup.
	// It defaults to true.
	HostIPAuto *bool
	// HostIP is the underlay host IP to use when HostIPAuto is false.
	HostIP netip.Addr
	// AllowTestNets allows documentation IP ranges. It defaults to false.
	AllowTestNets *bool
}

func (e Egress) validate() (err error) {
	if e.Enabled != nil && !*e.Enabled {
		return nil
	}

	if len(e.Sources) == 0 {
		return fmt.Errorf("no source configured")
	}

	allowedKinds := []string{sourceKindHTTP, sourceKindDNS, sourceKindPublicIP, sourceKindStatic}
	for i, source := range e.Sources {
		parts := strings.SplitN(source, ":", sourceSpecParts)
		if len(parts) != 2 || parts[1] == "" {
			return fmt.Errorf("source %d is not in the kind:name format: %s", i+1, source)
		}
		err = validate.IsOneOf(parts[0], allowedKinds...)
		if err != nil {
			return fmt.Errorf("source %d kind: %w", i+1, err)
		}
	}

	if e.MinSources == 0 {
		return fmt.Errorf("minimum sources must be greater than 0")
	}
	if e.Quorum == 0 {
		return fmt.Errorf("quorum must be greater than 0")
	}
	if e.Quorum > e.MinSources {
		return fmt.Errorf("quorum %d is greater than minimum sources %d", e.Quorum, e.MinSources)
	}

	allowSingle := e.AllowSingle != nil && *e.AllowSingle
	if !allowSingle && uint(len(e.Sources)) < e.MinSources {
		return fmt.Errorf("configured sources %d is less than minimum sources %d",
			len(e.Sources), e.MinSources)
	}
	if allowSingle && len(e.Sources) == 1 && e.Quorum > 1 {
		return fmt.Errorf("quorum %d cannot be met with a single source", e.Quorum)
	}

	if e.CacheTTL < 0 {
		return fmt.Errorf("cache TTL cannot be negative: %s", e.CacheTTL)
	}
	if e.SourceTimeout <= 0 {
		return fmt.Errorf("source timeout must be greater than 0")
	}
	if e.SourceBackoff <= 0 {
		return fmt.Errorf("source backoff must be greater than 0")
	}
	if e.SourceBackoffMax < e.SourceBackoff {
		return fmt.Errorf("source maximum backoff %s is less than source backoff %s",
			e.SourceBackoffMax, e.SourceBackoff)
	}

	err = validate.IsOneOf(e.Family, "4", "6", "both")
	if err != nil {
		return fmt.Errorf("family: %w", err)
	}

	for _, ip := range e.ForbiddenIPs {
		if !ip.IsValid() {
			return fmt.Errorf("forbidden IP address is not valid: %s", ip)
		}
	}

	hostIPAuto := e.HostIPAuto == nil || *e.HostIPAuto
	if hostIPAuto && e.HostIP.IsValid() {
		return fmt.Errorf("host IP cannot be set when host IP auto capture is enabled")
	}
	if !hostIPAuto && !e.HostIP.IsValid() {
		return fmt.Errorf("host IP must be set when host IP auto capture is disabled")
	}

	return nil
}

func (e Egress) copy() (copied Egress) {
	return Egress{
		Enabled:          gosettings.CopyPointer(e.Enabled),
		Sources:          gosettings.CopySlice(e.Sources),
		Quorum:           e.Quorum,
		MinSources:       e.MinSources,
		AllowSingle:      gosettings.CopyPointer(e.AllowSingle),
		CacheTTL:         e.CacheTTL,
		SourceTimeout:    e.SourceTimeout,
		SourceBackoff:    e.SourceBackoff,
		SourceBackoffMax: e.SourceBackoffMax,
		Family:           e.Family,
		ForbiddenIPs:     gosettings.CopySlice(e.ForbiddenIPs),
		HostIPAuto:       gosettings.CopyPointer(e.HostIPAuto),
		HostIP:           e.HostIP,
		AllowTestNets:    gosettings.CopyPointer(e.AllowTestNets),
	}
}

func (e *Egress) overrideWith(other Egress) {
	e.Enabled = gosettings.OverrideWithPointer(e.Enabled, other.Enabled)
	e.Sources = gosettings.OverrideWithSlice(e.Sources, other.Sources)
	e.Quorum = gosettings.OverrideWithComparable(e.Quorum, other.Quorum)
	e.MinSources = gosettings.OverrideWithComparable(e.MinSources, other.MinSources)
	e.AllowSingle = gosettings.OverrideWithPointer(e.AllowSingle, other.AllowSingle)
	e.CacheTTL = gosettings.OverrideWithComparable(e.CacheTTL, other.CacheTTL)
	e.SourceTimeout = gosettings.OverrideWithComparable(e.SourceTimeout, other.SourceTimeout)
	e.SourceBackoff = gosettings.OverrideWithComparable(e.SourceBackoff, other.SourceBackoff)
	e.SourceBackoffMax = gosettings.OverrideWithComparable(e.SourceBackoffMax, other.SourceBackoffMax)
	e.Family = gosettings.OverrideWithComparable(e.Family, other.Family)
	e.ForbiddenIPs = gosettings.OverrideWithSlice(e.ForbiddenIPs, other.ForbiddenIPs)
	e.HostIPAuto = gosettings.OverrideWithPointer(e.HostIPAuto, other.HostIPAuto)
	e.HostIP = gosettings.OverrideWithComparable(e.HostIP, other.HostIP)
	e.AllowTestNets = gosettings.OverrideWithPointer(e.AllowTestNets, other.AllowTestNets)
}

func (e *Egress) setDefaults() {
	e.Enabled = gosettings.DefaultPointer(e.Enabled, true)
	e.Sources = gosettings.DefaultSlice(e.Sources, []string{
		"http:ipify", "dns:whoami", "publicip:internal",
	})
	e.Quorum = gosettings.DefaultComparable(e.Quorum, defaultEgressQuorum)
	e.MinSources = gosettings.DefaultComparable(e.MinSources, defaultEgressMinSources)
	e.AllowSingle = gosettings.DefaultPointer(e.AllowSingle, false)
	e.CacheTTL = gosettings.DefaultComparable(e.CacheTTL, defaultEgressCacheTTL)
	e.SourceTimeout = gosettings.DefaultComparable(e.SourceTimeout, defaultEgressSourceTimeout)
	e.SourceBackoff = gosettings.DefaultComparable(e.SourceBackoff, defaultEgressBackoff)
	e.SourceBackoffMax = gosettings.DefaultComparable(e.SourceBackoffMax, defaultEgressBackoffMax)
	e.Family = gosettings.DefaultComparable(e.Family, "4")
	e.HostIPAuto = gosettings.DefaultPointer(e.HostIPAuto, true)
	e.AllowTestNets = gosettings.DefaultPointer(e.AllowTestNets, false)
}

func (e Egress) String() string {
	return e.toLinesNode().String()
}

func (e Egress) toLinesNode() (node *gotree.Node) {
	node = gotree.New("Egress verification settings:")
	node.Appendf("Enabled: %s", gosettings.BoolToYesNo(e.Enabled))
	node.Appendf("Sources: %s", strings.Join(e.Sources, ", "))
	node.Appendf("Quorum: %d", e.Quorum)
	node.Appendf("Minimum sources: %d", e.MinSources)
	node.Appendf("Allow single source: %s", gosettings.BoolToYesNo(e.AllowSingle))
	node.Appendf("Cache TTL: %s", e.CacheTTL)
	node.Appendf("Source timeout: %s", e.SourceTimeout)
	node.Appendf("Source backoff: %s", e.SourceBackoff)
	node.Appendf("Source maximum backoff: %s", e.SourceBackoffMax)
	node.Appendf("IP family: %s", e.Family)
	node.Appendf("Host IP automatic capture: %s", gosettings.BoolToYesNo(e.HostIPAuto))
	node.Appendf("Allow test networks: %s", gosettings.BoolToYesNo(e.AllowTestNets))
	return node
}

func (e *Egress) read(r *reader.Reader) (err error) {
	e.Enabled, err = r.BoolPtr("CONTROL_EGRESS_ENABLED")
	if err != nil {
		return err
	}

	e.Sources = r.CSV("CONTROL_EGRESS_SOURCES")
	quorum, err := r.UintPtr("CONTROL_EGRESS_QUORUM")
	if err != nil {
		return err
	}
	if quorum != nil {
		e.Quorum = *quorum
	}
	minSources, err := r.UintPtr("CONTROL_EGRESS_MIN_SOURCES")
	if err != nil {
		return err
	}
	if minSources != nil {
		e.MinSources = *minSources
	}
	e.AllowSingle, err = r.BoolPtr("CONTROL_EGRESS_ALLOW_SINGLE")
	if err != nil {
		return err
	}
	cacheTTLSeconds, err := r.UintPtr("CONTROL_EGRESS_CACHE_TTL_S")
	if err != nil {
		return err
	}
	if cacheTTLSeconds != nil {
		e.CacheTTL = time.Duration(*cacheTTLSeconds) * time.Second //nolint:gosec // validated
	}
	sourceTimeoutMS, err := r.UintPtr("CONTROL_EGRESS_SOURCE_TIMEOUT_MS")
	if err != nil {
		return err
	}
	if sourceTimeoutMS != nil {
		e.SourceTimeout = time.Duration(*sourceTimeoutMS) * time.Millisecond //nolint:gosec // validated
	}
	sourceBackoffMS, err := r.UintPtr("CONTROL_EGRESS_SOURCE_BACKOFF_MS")
	if err != nil {
		return err
	}
	if sourceBackoffMS != nil {
		e.SourceBackoff = time.Duration(*sourceBackoffMS) * time.Millisecond //nolint:gosec // validated
	}
	sourceBackoffMaxMS, err := r.UintPtr("CONTROL_EGRESS_SOURCE_BACKOFF_MAX_MS")
	if err != nil {
		return err
	}
	if sourceBackoffMaxMS != nil {
		e.SourceBackoffMax = time.Duration(*sourceBackoffMaxMS) * time.Millisecond //nolint:gosec // validated
	}
	e.Family = r.String("CONTROL_EGRESS_FAMILY")
	e.ForbiddenIPs, err = r.CSVNetipAddresses("CONTROL_EGRESS_FORBIDDEN_IPS")
	if err != nil {
		return err
	}
	e.HostIPAuto, err = r.BoolPtr("CONTROL_EGRESS_HOST_IP_AUTO")
	if err != nil {
		return err
	}
	e.HostIP, err = r.NetipAddr("CONTROL_HOST_IP")
	if err != nil {
		return err
	}
	e.AllowTestNets, err = r.BoolPtr("CONTROL_EGRESS_ALLOW_TEST_NETS")
	if err != nil {
		return err
	}

	return nil
}

// DNSLadder contains the DNS ladder settings.
type DNSLadder struct {
	// Ladder is the ordered list of DNS tiers.
	// It defaults to [dot plain].
	Ladder []string
	// FailClosed prevents DNS requests from escaping the tunnel.
	// It defaults to true.
	FailClosed *bool
	// RedundancyRequired refuses a single tier ladder.
	// It defaults to false.
	RedundancyRequired *bool
	// ProvidersDot are the DoT providers, defaulting to the DNS providers.
	ProvidersDot []string
	// ProvidersDoh are the DoH providers, defaulting to the DoT providers.
	ProvidersDoh []string
	// PlainAddresses are the plain DNS addresses, defaulting to the plain
	// addresses of the DNS providers.
	PlainAddresses []netip.AddrPort
	// Timeout is the timeout of one tier attempt.
	// It defaults to 800ms.
	Timeout time.Duration
	// Attempts is the number of attempts per tier before falling back.
	// It defaults to 2.
	Attempts int
	// FailuresToDown is the number of consecutive failures marking an endpoint
	// down. It defaults to 3.
	FailuresToDown int
	// SuccessesToRecover is the number of consecutive successes marking an
	// endpoint up. It defaults to 2.
	SuccessesToRecover int
	// BaseCooldown is the initial cooldown of a down endpoint.
	// It defaults to 5s.
	BaseCooldown time.Duration
	// MaxCooldown is the cooldown backoff ceiling.
	// It defaults to 5min.
	MaxCooldown time.Duration
	// ProbeInterval is the active probe interval of down endpoints.
	// It defaults to 30s.
	ProbeInterval time.Duration
	// ProbeDomain is the neutral domain used by active probes.
	// It defaults to example.com.
	ProbeDomain string
}

func (d DNSLadder) validate() (err error) {
	if len(d.Ladder) == 0 {
		return fmt.Errorf("ladder is empty")
	}

	validTiers := []string{"dot", "doh", "plain"}
	seen := make(map[string]struct{}, len(d.Ladder))
	for i, tier := range d.Ladder {
		err = validate.IsOneOf(tier, validTiers...)
		if err != nil {
			return fmt.Errorf("tier %d: %w", i+1, err)
		}
		_, duplicate := seen[tier]
		if duplicate {
			return fmt.Errorf("tier %q is duplicated", tier)
		}
		seen[tier] = struct{}{}
	}

	failClosed := d.FailClosed == nil || *d.FailClosed
	redundancyRequired := d.RedundancyRequired != nil && *d.RedundancyRequired
	if failClosed && redundancyRequired && len(d.Ladder) < 2 {
		return fmt.Errorf("at least two tiers are required when fail closed and redundancy are enabled")
	}

	err = validateDNSProviders(d.ProvidersDot, "DNS_TIER_PROVIDERS_DOT")
	if err != nil {
		return err
	}
	err = validateDNSProviders(d.ProvidersDoh, "DNS_TIER_PROVIDERS_DOH")
	if err != nil {
		return err
	}

	switch {
	case d.Timeout <= 0:
		return fmt.Errorf("DNS tier timeout must be positive: %s", d.Timeout)
	case d.Attempts < 1:
		return fmt.Errorf("DNS tier attempts must be at least 1: %d", d.Attempts)
	case d.FailuresToDown < 1:
		return fmt.Errorf("DNS health failures must be at least 1: %d",
			d.FailuresToDown)
	case d.SuccessesToRecover < 1:
		return fmt.Errorf("DNS health successes must be at least 1: %d",
			d.SuccessesToRecover)
	case d.BaseCooldown < 0:
		return fmt.Errorf("DNS health cooldown must not be negative: %s",
			d.BaseCooldown)
	case d.MaxCooldown < d.BaseCooldown:
		return fmt.Errorf("DNS health cooldown maximum %s is less than base %s",
			d.MaxCooldown, d.BaseCooldown)
	case d.ProbeInterval < 0:
		return fmt.Errorf("DNS probe interval must not be negative: %s",
			d.ProbeInterval)
	case d.ProbeDomain == "":
		return fmt.Errorf("DNS probe domain is empty")
	}

	return nil
}

func validateDNSProviders(names []string, setting string) (err error) {
	providers := provider.NewProviders()
	for index, name := range names {
		_, err = providers.Get(name)
		if err != nil {
			return fmt.Errorf("%s provider %d: %w", setting, index+1, err)
		}
	}
	return nil
}

func (d DNSLadder) copy() (copied DNSLadder) {
	return DNSLadder{
		Ladder:             gosettings.CopySlice(d.Ladder),
		FailClosed:         gosettings.CopyPointer(d.FailClosed),
		RedundancyRequired: gosettings.CopyPointer(d.RedundancyRequired),
		ProvidersDot:       gosettings.CopySlice(d.ProvidersDot),
		ProvidersDoh:       gosettings.CopySlice(d.ProvidersDoh),
		PlainAddresses:     gosettings.CopySlice(d.PlainAddresses),
		Timeout:            d.Timeout,
		Attempts:           d.Attempts,
		FailuresToDown:     d.FailuresToDown,
		SuccessesToRecover: d.SuccessesToRecover,
		BaseCooldown:       d.BaseCooldown,
		MaxCooldown:        d.MaxCooldown,
		ProbeInterval:      d.ProbeInterval,
		ProbeDomain:        d.ProbeDomain,
	}
}

func (d *DNSLadder) overrideWith(other DNSLadder) {
	d.Ladder = gosettings.OverrideWithSlice(d.Ladder, other.Ladder)
	d.FailClosed = gosettings.OverrideWithPointer(d.FailClosed, other.FailClosed)
	d.RedundancyRequired = gosettings.OverrideWithPointer(d.RedundancyRequired, other.RedundancyRequired)
	d.ProvidersDot = gosettings.OverrideWithSlice(d.ProvidersDot, other.ProvidersDot)
	d.ProvidersDoh = gosettings.OverrideWithSlice(d.ProvidersDoh, other.ProvidersDoh)
	d.PlainAddresses = gosettings.OverrideWithSlice(d.PlainAddresses, other.PlainAddresses)
	d.Timeout = gosettings.OverrideWithComparable(d.Timeout, other.Timeout)
	d.Attempts = gosettings.OverrideWithComparable(d.Attempts, other.Attempts)
	d.FailuresToDown = gosettings.OverrideWithComparable(d.FailuresToDown, other.FailuresToDown)
	d.SuccessesToRecover = gosettings.OverrideWithComparable(d.SuccessesToRecover, other.SuccessesToRecover)
	d.BaseCooldown = gosettings.OverrideWithComparable(d.BaseCooldown, other.BaseCooldown)
	d.MaxCooldown = gosettings.OverrideWithComparable(d.MaxCooldown, other.MaxCooldown)
	d.ProbeInterval = gosettings.OverrideWithComparable(d.ProbeInterval, other.ProbeInterval)
	d.ProbeDomain = gosettings.OverrideWithComparable(d.ProbeDomain, other.ProbeDomain)
}

func (d *DNSLadder) setDefaults() {
	d.Ladder = gosettings.DefaultSlice(d.Ladder, []string{"dot", "plain"})
	d.FailClosed = gosettings.DefaultPointer(d.FailClosed, true)
	d.RedundancyRequired = gosettings.DefaultPointer(d.RedundancyRequired, false)
	d.ProvidersDot = gosettings.DefaultSlice(d.ProvidersDot, []string{})
	d.ProvidersDoh = gosettings.DefaultSlice(d.ProvidersDoh, []string{})
	d.PlainAddresses = gosettings.DefaultSlice(d.PlainAddresses, []netip.AddrPort{})
	d.Timeout = gosettings.DefaultComparable(d.Timeout, 800*time.Millisecond)
	d.Attempts = gosettings.DefaultComparable(d.Attempts, 2)
	d.FailuresToDown = gosettings.DefaultComparable(d.FailuresToDown, 3)
	d.SuccessesToRecover = gosettings.DefaultComparable(d.SuccessesToRecover, 2)
	d.BaseCooldown = gosettings.DefaultComparable(d.BaseCooldown, 5*time.Second)
	d.MaxCooldown = gosettings.DefaultComparable(d.MaxCooldown, 5*time.Minute)
	d.ProbeInterval = gosettings.DefaultComparable(d.ProbeInterval, 30*time.Second)
	d.ProbeDomain = gosettings.DefaultComparable(d.ProbeDomain, "example.com")
}

func (d DNSLadder) String() string {
	return d.toLinesNode().String()
}

func (d DNSLadder) toLinesNode() (node *gotree.Node) {
	node = gotree.New("DNS ladder settings:")
	node.Appendf("Ladder: %s", strings.Join(d.Ladder, ", "))
	node.Appendf("Fail closed: %s", gosettings.BoolToYesNo(d.FailClosed))
	node.Appendf("Redundancy required: %s", gosettings.BoolToYesNo(d.RedundancyRequired))
	if len(d.ProvidersDot) > 0 {
		node.Appendf("DoT providers: %s", strings.Join(d.ProvidersDot, ", "))
	}
	if len(d.ProvidersDoh) > 0 {
		node.Appendf("DoH providers: %s", strings.Join(d.ProvidersDoh, ", "))
	}
	if len(d.PlainAddresses) > 0 {
		addresses := make([]string, len(d.PlainAddresses))
		for i, address := range d.PlainAddresses {
			addresses[i] = address.String()
		}
		node.Appendf("Plain addresses: %s", strings.Join(addresses, ", "))
	}
	node.Appendf("Tier timeout: %s", d.Timeout)
	node.Appendf("Tier attempts: %d", d.Attempts)
	node.Appendf("Health failures to down: %d", d.FailuresToDown)
	node.Appendf("Health successes to recover: %d", d.SuccessesToRecover)
	node.Appendf("Health cooldown: %s", d.BaseCooldown)
	node.Appendf("Health cooldown maximum: %s", d.MaxCooldown)
	node.Appendf("Probe interval: %s", d.ProbeInterval)
	node.Appendf("Probe domain: %s", d.ProbeDomain)
	return node
}

func (d *DNSLadder) read(r *reader.Reader) (err error) {
	d.Ladder = r.CSV("DNS_LADDER")
	d.FailClosed, err = r.BoolPtr("DNS_FAIL_CLOSED")
	if err != nil {
		return err
	}
	d.RedundancyRequired, err = r.BoolPtr("DNS_REDUNDANCY_REQUIRED")
	if err != nil {
		return err
	}

	d.ProvidersDot = r.CSV("DNS_TIER_PROVIDERS_DOT")
	d.ProvidersDoh = r.CSV("DNS_TIER_PROVIDERS_DOH")
	d.PlainAddresses, err = r.CSVNetipAddrPorts("DNS_TIER_ADDRESSES_PLAIN")
	if err != nil {
		return err
	}

	timeoutMS, err := r.UintPtr("DNS_TIER_TIMEOUT_MS")
	if err != nil {
		return err
	}
	if timeoutMS != nil {
		d.Timeout = time.Duration(*timeoutMS) * time.Millisecond //nolint:gosec
	}

	attempts, err := r.UintPtr("DNS_TIER_ATTEMPTS")
	if err != nil {
		return err
	}
	if attempts != nil {
		d.Attempts = int(*attempts) //nolint:gosec
	}

	failures, err := r.UintPtr("DNS_HEALTH_FAILURES")
	if err != nil {
		return err
	}
	if failures != nil {
		d.FailuresToDown = int(*failures) //nolint:gosec
	}

	successes, err := r.UintPtr("DNS_HEALTH_SUCCESSES")
	if err != nil {
		return err
	}
	if successes != nil {
		d.SuccessesToRecover = int(*successes) //nolint:gosec
	}

	cooldownMS, err := r.UintPtr("DNS_HEALTH_COOLDOWN_MS")
	if err != nil {
		return err
	}
	if cooldownMS != nil {
		d.BaseCooldown = time.Duration(*cooldownMS) * time.Millisecond //nolint:gosec
	}

	maxCooldownMS, err := r.UintPtr("DNS_HEALTH_COOLDOWN_MAX_MS")
	if err != nil {
		return err
	}
	if maxCooldownMS != nil {
		d.MaxCooldown = time.Duration(*maxCooldownMS) * time.Millisecond //nolint:gosec
	}

	probeSeconds, err := r.UintPtr("DNS_PROBE_INTERVAL_S")
	if err != nil {
		return err
	}
	if probeSeconds != nil {
		d.ProbeInterval = time.Duration(*probeSeconds) * time.Second //nolint:gosec
	}

	d.ProbeDomain = r.String("DNS_PROBE_DOMAIN")
	return nil
}

// Canary contains the neutral HTTP canary settings.
type Canary struct {
	// URL is the neutral canary endpoint. Empty disables the canary.
	URL string
	// Method is the HTTP method used by the canary. It defaults to GET.
	Method string
	// ExpectStatus is the expected HTTP status. It defaults to 200.
	ExpectStatus uint
	// MinBodyBytes is the minimal response body size. It defaults to 1.
	MinBodyBytes uint
	// ExpectSHA256 is the optional lowercase hex SHA-256 of the body.
	ExpectSHA256 string
	// Timeout is the canary request timeout. It defaults to 2 seconds.
	Timeout time.Duration
}

func (c Canary) validate() (err error) {
	if c.URL != "" {
		parsed, err := url.Parse(c.URL)
		if err != nil {
			return fmt.Errorf("parsing URL: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("URL scheme must be http or https: %s", parsed.Scheme)
		}
	}

	_, err = http.NewRequestWithContext(context.Background(), c.Method,
		"http://example.invalid", nil)
	if err != nil {
		return fmt.Errorf("method: %w", err)
	}
	if c.ExpectStatus < 100 || c.ExpectStatus > 599 {
		return fmt.Errorf("expected status must be between 100 and 599: %d",
			c.ExpectStatus)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than 0")
	}
	if c.ExpectSHA256 != "" {
		decoded, err := hex.DecodeString(c.ExpectSHA256)
		if err != nil {
			return fmt.Errorf("decoding expected SHA-256: %w", err)
		}
		if len(decoded) != sha256HexBytes {
			return fmt.Errorf("expected SHA-256 must be 32 bytes, got %d",
				len(decoded))
		}
	}
	return nil
}

func (c *Canary) overrideWith(other Canary) {
	c.URL = gosettings.OverrideWithComparable(c.URL, other.URL)
	c.Method = gosettings.OverrideWithComparable(c.Method, other.Method)
	c.ExpectStatus = gosettings.OverrideWithComparable(c.ExpectStatus, other.ExpectStatus)
	c.MinBodyBytes = gosettings.OverrideWithComparable(c.MinBodyBytes, other.MinBodyBytes)
	c.ExpectSHA256 = gosettings.OverrideWithComparable(c.ExpectSHA256, other.ExpectSHA256)
	c.Timeout = gosettings.OverrideWithComparable(c.Timeout, other.Timeout)
}

func (c *Canary) setDefaults() {
	c.Method = gosettings.DefaultComparable(c.Method, http.MethodGet)
	c.ExpectStatus = gosettings.DefaultComparable(c.ExpectStatus, http.StatusOK)
	c.MinBodyBytes = gosettings.DefaultComparable(c.MinBodyBytes, defaultCanaryMinBodyBytes)
	c.Timeout = gosettings.DefaultComparable(c.Timeout, defaultCanaryTimeout)
}

func (c Canary) String() string {
	return c.toLinesNode().String()
}

func (c Canary) toLinesNode() (node *gotree.Node) {
	node = gotree.New("Canary settings:")
	if c.URL == "" {
		node.Appendf("Enabled: no")
		return node
	}
	node.Appendf("URL: %s", c.URL)
	node.Appendf("Method: %s", c.Method)
	node.Appendf("Expected status: %d", c.ExpectStatus)
	node.Appendf("Minimum body bytes: %d", c.MinBodyBytes)
	node.Appendf("Expected SHA-256: %t", c.ExpectSHA256 != "")
	node.Appendf("Timeout: %s", c.Timeout)
	return node
}

func (c *Canary) read(r *reader.Reader) (err error) {
	c.URL = r.String("CONTROL_CANARY_URL")
	c.Method = r.String("CONTROL_CANARY_METHOD")
	expectStatus, err := r.UintPtr("CONTROL_CANARY_EXPECT_STATUS")
	if err != nil {
		return err
	}
	if expectStatus != nil {
		c.ExpectStatus = *expectStatus
	}
	minBodyBytes, err := r.UintPtr("CONTROL_CANARY_MIN_BODY_BYTES")
	if err != nil {
		return err
	}
	if minBodyBytes != nil {
		c.MinBodyBytes = *minBodyBytes
	}
	c.ExpectSHA256 = r.String("CONTROL_CANARY_EXPECT_SHA256")
	timeoutMS, err := r.UintPtr("CONTROL_CANARY_TIMEOUT_MS")
	if err != nil {
		return err
	}
	if timeoutMS != nil {
		c.Timeout = time.Duration(*timeoutMS) * time.Millisecond //nolint:gosec // validated
	}
	return nil
}
