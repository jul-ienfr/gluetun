package vpn

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/verify"
	"github.com/qdm12/gluetun/internal/loopstate"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/netlink"
	"github.com/qdm12/gluetun/internal/vpn/state"
	transportpkg "github.com/qdm12/gluetun/internal/vpn/transport"
	"github.com/qdm12/log"
)

// egressVerifier is the subset of the egress verification service used by the
// transport ladder.
type egressVerifier interface {
	Verify(ctx context.Context, request verify.Request) (egress.Verification, error)
}

type Loop struct {
	statusManager  *loopstate.State
	state          *state.State
	providers      Providers
	storage        Storage
	healthSettings settings.Health
	healthChecker  HealthChecker
	healthServer   HealthServer
	// Fixed parameters
	buildInfo        models.BuildInformation
	versionInfo      bool
	ipv6SupportLevel netlink.IPv6SupportLevel
	vpnInputPorts    []uint16 // TODO make changeable through stateful firewall
	// Configurators
	openvpnConf  OpenVPN
	netLinker    NetLinker
	fw           Firewall
	routing      Routing
	portForward  PortForward
	publicip     PublicIPLoop
	dnsLooper    DNSLoop
	boringPoll   Service
	egress       egressVerifier
	transport    *transportpkg.Integration
	transportDrv *ladderDriver
	transMetrics *transportpkg.Metrics
	ladderActive atomic.Bool
	// Other objects
	cmder  Cmder // for OpenVPN and up/down commands
	logger log.LoggerInterface
	client *http.Client
	// Internal channels and values
	stop        <-chan struct{}
	stopped     chan<- struct{}
	start       <-chan struct{}
	running     chan<- models.LoopStatus
	userTrigger bool
	healthDone  <-chan struct{}
	// Internal constant values
	backoffTime time.Duration
}

const (
	defaultBackoffTime = 15 * time.Second
)

func NewLoop(vpnSettings settings.VPN, ipv6SupportLevel netlink.IPv6SupportLevel, vpnInputPorts []uint16,
	providers Providers, storage Storage, boringPoll Service,
	healthSettings settings.Health, healthChecker HealthChecker, healthServer HealthServer,
	openvpnConf OpenVPN, netLinker NetLinker, fw Firewall, routing Routing,
	portForward PortForward, cmder Cmder,
	publicip PublicIPLoop, dnsLooper DNSLoop,
	logger log.LoggerInterface, client *http.Client,
	buildInfo models.BuildInformation, versionInfo bool,
) *Loop {
	start := make(chan struct{})
	running := make(chan models.LoopStatus)
	stop := make(chan struct{})
	stopped := make(chan struct{})

	statusManager := loopstate.New(constants.Stopped, start, running, stop, stopped)
	state := state.New(statusManager, vpnSettings)

	// Initialize healthDone channel to a closed channel so that the first time
	// we call <-l.healthDone it does not block
	healthDone := make(chan struct{})
	close(healthDone)

	return &Loop{
		statusManager:    statusManager,
		state:            state,
		providers:        providers,
		storage:          storage,
		healthSettings:   healthSettings,
		healthChecker:    healthChecker,
		healthServer:     healthServer,
		buildInfo:        buildInfo,
		versionInfo:      versionInfo,
		ipv6SupportLevel: ipv6SupportLevel,
		vpnInputPorts:    vpnInputPorts,
		boringPoll:       boringPoll,
		openvpnConf:      openvpnConf,
		netLinker:        netLinker,
		fw:               fw,
		routing:          routing,
		portForward:      portForward,
		publicip:         publicip,
		dnsLooper:        dnsLooper,
		cmder:            cmder,
		logger:           logger,
		client:           client,
		start:            start,
		running:          running,
		stop:             stop,
		stopped:          stopped,
		userTrigger:      true,
		healthDone:       healthDone,
		backoffTime:      defaultBackoffTime,
	}
}
