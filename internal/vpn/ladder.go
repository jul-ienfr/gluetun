package vpn

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/verify"
	"github.com/qdm12/gluetun/internal/models"
	transportpkg "github.com/qdm12/gluetun/internal/vpn/transport"
	"github.com/qdm12/log"
)

const ladderEarlyErrorWait = 100 * time.Millisecond

type vpnRunner interface {
	Run(ctx context.Context, waitError chan<- error, tunnelReady chan<- struct{})
}

// ladderDriver implements transport.Driver against the live VPN loop. One
// driver is created per loop settings snapshot so that the server selection
// stays pinned for the whole ladder run.
type ladderDriver struct {
	loop   *Loop
	base   settings.VPN
	runCtx context.Context
	logger log.LoggerInterface
	target transportpkg.Target

	mutex        sync.Mutex
	cancel       context.CancelFunc
	running      bool
	vpnInterface string
	connection   models.Connection
	tunnelUp     tunnelUpData
	waitError    chan error
	tunnelReady  chan struct{}
	done         chan struct{}
	current      transportpkg.Transport
	currentSet   settings.VPN
	lastVerified time.Time
}

func newLadderDriver(loop *Loop, base settings.VPN) *ladderDriver {
	driver := &ladderDriver{
		loop:   loop,
		base:   base,
		logger: loop.logger,
	}
	driver.target = driver.targetFor(base)
	return driver
}

// Configure pins the driver on a loop settings snapshot. It is called from the
// loop goroutine before every ladder run.
func (d *ladderDriver) Configure(ctx context.Context, base settings.VPN) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.base = base
	d.runCtx = ctx
	d.target = d.targetFor(base)
}

// targetFor resolves the pinned hostname from the provider catalogue instead
// of DNS. The ladder runs before the tunnel is up, so the local DNS ladder can
// be fail-closed and unable to resolve the server name yet.
func (d *ladderDriver) targetFor(base settings.VPN) transportpkg.Target {
	target := ladderTarget(base)
	if target.Hostname == "" || target.EndpointIP.IsValid() ||
		base.Provider.Name == "" {
		return target
	}
	providerConf := d.loop.providers.Get(base.Provider.Name)
	if providerConf == nil {
		return target
	}
	selection := base.Provider.ServerSelection
	if selection.VPN == "" {
		selection.VPN = base.Type
	}
	if selection.VPN == "" {
		selection.VPN = vpn.OpenVPN
	}
	if selection.Mode == "" {
		selection.Mode = "random"
	}
	connection, err := providerConf.GetConnection(selection, false)
	if err != nil || !connection.IP.IsValid() {
		return target
	}
	target.EndpointIP = connection.IP
	return target
}

// shouldRunLadder reports whether the runtime ladder can drive the loop for
// the given settings. An explicit VPN type or a custom OpenVPN configuration
// keeps the upstream behavior.
func (l *Loop) shouldRunLadder(settings settings.VPN) bool {
	if l.transport == nil || l.transportDrv == nil {
		return false
	}
	if settings.TypeExplicit {
		return false
	}
	if settings.Type == vpn.AmneziaWg {
		return false
	}
	if settings.OpenVPN.ConfFile != nil && *settings.OpenVPN.ConfFile != "" {
		return false
	}
	return ladderTarget(settings).Hostname != ""
}

func (l *Loop) runLadder(ctx context.Context, settings settings.VPN) {
	l.ladderActive.Store(true)
	defer l.ladderActive.Store(false)

	ladderCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	l.transportDrv.Configure(ladderCtx, settings)
	target := l.transportDrv.Target()
	l.logger.Infof("starting transport ladder for %s", target.Hostname)

	done := make(chan struct{})
	var runErr error
	go func() {
		defer close(done)
		_, runErr = l.transport.Run(ladderCtx, target,
			func(result transportpkg.Result) {
				l.backoffTime = defaultBackoffTime
				l.signalOrSetStatus(constants.Running)
				data, currentSettings := l.transportDrv.TunnelUpData()
				go l.onTunnelUp(ladderCtx, ctx, currentSettings, data) //nolint:gosec
				_ = result
			})
	}()

	select {
	case <-ctx.Done():
		cancel()
		<-done
		return
	case <-l.stop:
		l.userTrigger = true
		l.logger.Info("stopping")
		cancel()
		_ = l.transportDrv.Teardown(context.Background())
		<-done
		l.cleanup()
		l.stopped <- struct{}{}
		select {
		case <-l.start:
			l.userTrigger = true
			l.logger.Info("starting")
		case <-ctx.Done():
		}
		return
	case <-l.start:
		l.userTrigger = true
		l.logger.Info("starting")
		cancel()
		_ = l.transportDrv.Teardown(context.Background())
		<-done
		return
	case <-done:
		if runErr != nil && ladderCtx.Err() == nil {
			l.crashed(ctx, runErr)
		}
		return
	}
}

// ladderTarget returns the pinned server target for the runtime ladder. The
// ladder is only activated when a hostname is pinned, which guarantees that
// every transport in the ladder reaches the same server.
func ladderTarget(settings settings.VPN) transportpkg.Target {
	hostnames := settings.Provider.ServerSelection.Hostnames
	if len(hostnames) == 0 {
		return transportpkg.Target{}
	}
	target := transportpkg.Target{Hostname: hostnames[0]}
	switch settings.Type {
	case vpn.Wireguard:
		target.EndpointIP = settings.Provider.ServerSelection.Wireguard.EndpointIP
		if settings.Provider.ServerSelection.Wireguard.EndpointPort != nil {
			target.Port = *settings.Provider.ServerSelection.Wireguard.EndpointPort
		}
	case vpn.OpenVPN:
		target.EndpointIP = settings.Provider.ServerSelection.OpenVPN.EndpointIP
		if settings.Provider.ServerSelection.OpenVPN.CustomPort != nil {
			target.Port = *settings.Provider.ServerSelection.OpenVPN.CustomPort
		}
	}
	return target
}

func (d *ladderDriver) Target() transportpkg.Target {
	return d.target
}

func (d *ladderDriver) Preflight(ctx context.Context, name transportpkg.Transport,
	target transportpkg.Target,
) error {
	preflight := transportpkg.NewPreflight(transportpkg.PreflightSettings{
		Credentials: ladderCredentials(d.base),
		Ports:       ladderPorts(d.base),
	})
	_, err := preflight.Check(ctx, name, target)
	return err
}

func ladderCredentials(settings settings.VPN) transportpkg.Credentials {
	credentials := transportpkg.Credentials{
		OpenVPN: settings.OpenVPN.User != nil &&
			settings.OpenVPN.Password != nil &&
			(*settings.OpenVPN.User != "" ||
				*settings.OpenVPN.Password != "" ||
				(settings.OpenVPN.ConfFile != nil && *settings.OpenVPN.ConfFile != "")),
		WireGuard: settings.Wireguard.PrivateKey != nil &&
			*settings.Wireguard.PrivateKey != "",
	}
	// The currently configured transport is usable even before its secrets are
	// exposed by the settings state.
	switch settings.Type {
	case vpn.OpenVPN:
		credentials.OpenVPN = true
	case vpn.Wireguard:
		credentials.WireGuard = true
	}
	return credentials
}

func ladderPorts(settings settings.VPN) map[transportpkg.Transport]uint16 {
	ports := make(map[transportpkg.Transport]uint16, 3)
	if settings.Provider.ServerSelection.Wireguard.EndpointPort != nil {
		ports[transportpkg.WireGuard] =
			*settings.Provider.ServerSelection.Wireguard.EndpointPort
	}
	if settings.Provider.ServerSelection.OpenVPN.CustomPort != nil {
		port := *settings.Provider.ServerSelection.OpenVPN.CustomPort
		ports[transportpkg.OpenVPNUDP] = port
		ports[transportpkg.OpenVPNTCP] = port
	}
	return ports
}

func (d *ladderDriver) Apply(ctx context.Context, name transportpkg.Transport,
	_ transportpkg.Target,
) error {
	select {
	case <-d.runCtx.Done():
		return d.runCtx.Err()
	default:
	}

	settings := ladderSettings(d.base, name)

	var runner vpnRunner
	var connection models.Connection
	var err error
	subLogger := d.logger.New(log.SetComponent(settings.Type))
	providerConf := d.loop.providers.Get(settings.Provider.Name)
	switch settings.Type {
	case vpn.OpenVPN:
		runner, connection, err = setupOpenVPN(ctx, d.loop.fw, d.loop.openvpnConf,
			providerConf, settings, d.loop.ipv6SupportLevel, d.loop.cmder, subLogger)
	case vpn.Wireguard:
		runner, connection, err = setupWireguard(ctx, d.loop.netLinker, d.loop.fw,
			providerConf, settings, d.loop.ipv6SupportLevel, subLogger)
	default:
		return transportpkg.NewFailure(transportpkg.ReasonConfigInvalid,
			fmt.Errorf("transport %q maps to unsupported VPN type %q",
				name, settings.Type))
	}
	if err != nil {
		return transportpkg.NewFailure(transportpkg.ReasonConfigInvalid, err)
	}

	portForwarder := getPortForwarder(providerConf, d.loop.providers,
		*settings.Provider.PortForwarding.Provider)

	vpnCtx, cancel := context.WithCancel(d.runCtx)
	waitError := make(chan error, 1)
	tunnelReady := make(chan struct{}, 1)
	done := make(chan struct{})

	go func() {
		defer close(done)
		runner.Run(vpnCtx, waitError, tunnelReady)
	}()

	d.mutex.Lock()
	d.cancel = cancel
	d.running = true
	d.current = name
	d.currentSet = settings
	d.vpnInterface = ladderInterface(settings)
	d.connection = connection
	d.tunnelUp = tunnelUpData{
		upCommand: *settings.UpCommand,
		pmtud: tunnelUpPMTUDData{
			enabled: settings.Type != vpn.Wireguard ||
				*settings.Wireguard.MTU == 0,
			vpnType:   settings.Type,
			network:   connection.Protocol,
			icmpAddrs: settings.PMTUD.ICMPAddresses,
			tcpAddrs:  settings.PMTUD.TCPAddresses,
		},
		serverIP:       connection.IP,
		serverName:     connection.ServerName,
		canPortForward: connection.PortForward,
		portForwarder:  portForwarder,
		vpnIntf:        ladderInterface(settings),
		username:       settings.Provider.PortForwarding.Username,
		password:       settings.Provider.PortForwarding.Password,
	}
	d.mutex.Unlock()

	// The runner goroutine is stored in the driver so AwaitTunnel can observe
	// its early failure without racing with the attempt timeout.
	d.mutex.Lock()
	d.waitError = waitError
	d.tunnelReady = tunnelReady
	d.done = done
	d.mutex.Unlock()

	select {
	case err := <-waitError:
		d.teardownState()
		return ladderFailure(name, err)
	case <-time.After(ladderEarlyErrorWait):
		return nil
	case <-ctx.Done():
		d.teardownState()
		return ctx.Err()
	case <-done:
		d.teardownState()
		return transportpkg.NewFailure(transportpkg.ReasonInterfaceDown,
			errors.New("VPN runner exited before the tunnel was ready"))
	}
}

func (d *ladderDriver) AwaitTunnel(ctx context.Context, name transportpkg.Transport,
	_ transportpkg.Target,
) error {
	d.mutex.Lock()
	waitError := d.waitError
	tunnelReady := d.tunnelReady
	done := d.done
	tunnelUp := d.tunnelUp
	vpnInterface := d.vpnInterface
	currentSettings := d.currentSet
	d.mutex.Unlock()

	select {
	case <-tunnelReady:
		if vpnInterface == "" {
			return transportpkg.NewFailure(transportpkg.ReasonInterfaceDown,
				errors.New("tunnel is ready without an interface"))
		}
		d.loop.applyTunnelUp(ctx, currentSettings, tunnelUp)
		return nil
	case err := <-waitError:
		return ladderFailure(name, err)
	case <-done:
		return transportpkg.NewFailure(transportpkg.ReasonInterfaceDown,
			errors.New("VPN runner exited before the tunnel was ready"))
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *ladderDriver) VerifyEgress(ctx context.Context) (netip.Addr, error) {
	verifier := d.loop.egress
	if verifier == nil {
		return netip.Addr{}, transportpkg.NewFailure(transportpkg.ReasonNoEgress,
			errors.New("egress verification is not configured"))
	}

	const attempts = 10
	const retryDelay = 2 * time.Second
	var lastVerification egress.Verification
	var lastErr error
	for attempt := range attempts {
		verification, err := verifier.Verify(ctx, verify.Request{Fresh: true})
		if err == nil && verification.Verified && verification.IP.IsValid() {
			d.mutex.Lock()
			d.lastVerified = time.Now()
			d.mutex.Unlock()
			return verification.IP, nil
		}
		lastVerification = verification
		lastErr = err
		if attempt == attempts-1 || ctx.Err() != nil {
			break
		}
		// The tunnel is up but DNS or the public-IP provider may still be
		// starting. A single probe tore down working tunnels; retry inside
		// the same bounded attempt budget instead.
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}

	if lastErr != nil {
		return netip.Addr{}, transportpkg.NewFailure(transportpkg.ReasonNoEgress,
			lastErr)
	}
	message := "egress verification failed"
	if lastVerification.Reason != nil {
		message += ": " + string(*lastVerification.Reason)
	}
	return netip.Addr{}, transportpkg.NewFailure(transportpkg.ReasonNoEgress,
		errors.New(message))
}

func (d *ladderDriver) Health(_ context.Context, _ transportpkg.Transport,
	_ transportpkg.Target,
) (transportpkg.Health, error) {
	d.mutex.Lock()
	vpnInterface := d.vpnInterface
	lastVerified := d.lastVerified
	d.mutex.Unlock()

	health := transportpkg.Health{
		Status: string(d.loop.GetStatus()),
	}
	if vpnInterface != "" {
		_, err := d.loop.netLinker.LinkByName(vpnInterface)
		health.InterfaceUp = err == nil
	}
	if !lastVerified.IsZero() {
		health.HandshakeAt = lastVerified
		health.DNSReachable = true
	}
	return health, nil
}

func (d *ladderDriver) Reconnect(ctx context.Context, transport transportpkg.Transport,
	target transportpkg.Target,
) error {
	if err := d.Teardown(ctx); err != nil {
		return err
	}
	err := d.Apply(ctx, transport, target)
	if err != nil {
		return err
	}
	if err := d.AwaitTunnel(ctx, transport, target); err != nil {
		return err
	}
	_, err = d.VerifyEgress(ctx)
	return err
}

func (d *ladderDriver) Teardown(ctx context.Context) error {
	d.mutex.Lock()
	cancel := d.cancel
	done := d.done
	d.cancel = nil
	d.waitError = nil
	d.tunnelReady = nil
	d.done = nil
	d.running = false
	d.mutex.Unlock()

	if cancel == nil {
		return nil
	}
	cancel()

	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
		return errors.New("timed out waiting for the VPN runner to stop")
	}
	d.mutex.Lock()
	currentSettings := d.currentSet
	d.mutex.Unlock()
	d.loop.cleanupWith(currentSettings)
	d.mutex.Lock()
	d.vpnInterface = ""
	d.connection = models.Connection{}
	d.tunnelUp = tunnelUpData{}
	d.current = ""
	d.currentSet = settings.VPN{}
	d.lastVerified = time.Time{}
	d.mutex.Unlock()
	return nil
}

func (d *ladderDriver) teardownState() {
	d.mutex.Lock()
	cancel := d.cancel
	d.cancel = nil
	d.waitError = nil
	d.tunnelReady = nil
	d.done = nil
	d.running = false
	d.vpnInterface = ""
	d.connection = models.Connection{}
	d.tunnelUp = tunnelUpData{}
	d.current = ""
	d.currentSet = settings.VPN{}
	d.lastVerified = time.Time{}
	d.mutex.Unlock()
	if cancel != nil {
		cancel()
	}
}

// TunnelUpData returns the tunnel-up data of the committed transport, already
// marked as prepared since the ladder applied firewall and MTU rules.
func (d *ladderDriver) TunnelUpData() (tunnelUpData, settings.VPN) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	data := d.tunnelUp
	data.prepared = true
	return data, d.currentSet
}

func ladderSettings(base settings.VPN,
	transport transportpkg.Transport,
) settings.VPN {
	settings := base.Copy()
	settings.TypeExplicit = false
	switch transport {
	case transportpkg.WireGuard:
		settings.Type = vpn.Wireguard
		settings.Provider.ServerSelection.VPN = vpn.Wireguard
	case transportpkg.OpenVPNUDP:
		settings.Type = vpn.OpenVPN
		settings.Provider.ServerSelection.VPN = vpn.OpenVPN
		settings.Provider.ServerSelection.OpenVPN.Protocol = constants.UDP
	case transportpkg.OpenVPNTCP:
		settings.Type = vpn.OpenVPN
		settings.Provider.ServerSelection.VPN = vpn.OpenVPN
		settings.Provider.ServerSelection.OpenVPN.Protocol = constants.TCP
	}
	return settings
}

func ladderInterface(settings settings.VPN) string {
	switch settings.Type {
	case vpn.OpenVPN:
		return settings.OpenVPN.Interface
	case vpn.Wireguard:
		return settings.Wireguard.Interface
	default:
		return ""
	}
}

func ladderFailure(transport transportpkg.Transport, err error) error {
	reason := transportpkg.Classify(err, transport)
	return transportpkg.NewFailure(reason, err)
}

var _ egressVerifier = (*verify.Service)(nil)
