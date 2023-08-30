package hbone

import (
	"fmt"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
	"net"
	"os/exec"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "hbone")
)

const (
	listenPort = 15008
)

// Agent needs to be initialized with Init(). In Init(), the Wireguard tunnel
// device will be created and the proper routes set.  During Init(), existing
// peer keys are placed into `restoredPubKeys`.  Once RestoreFinished() is
// called obsolete keys and peers are removed.  UpdatePeer() inserts or updates
// the public key of peer discovered via the node manager.
type Agent struct {
	lock.RWMutex
	ipCache    *ipcache.IPCache
	listenPort int
	listener   net.Listener
	tunIn      *water.Interface
}

func NewAgent() (*Agent, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = "hbone-in"

	ifce, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to make TUN: %v", err)
	}
	if err := exec.Command("ip", "link", "set", ifce.Name(), "up").Run(); err != nil {
		return nil, fmt.Errorf("failed to up TUN: %v", err)
	}
	log.Infof("howardjohn: creating hbone agent")
	return &Agent{
		tunIn:      ifce,
		listenPort: listenPort,
	}, nil
}

// Close is called when the agent stops
func (a *Agent) Close() error {
	a.RLock()
	defer a.RUnlock()

	return nil
}

func (a *Agent) Init(ipcache *ipcache.IPCache, mtuConfig mtu.Configuration) error {
	addIPCacheListener := false
	a.Lock()
	a.ipCache = ipcache
	defer func() {
		// IPCache will call back into OnIPIdentityCacheChange which requires
		// us to release a.mutex before we can add ourself as a listener.
		a.Unlock()
		if addIPCacheListener {
			a.ipCache.AddListener(a)
		}
	}()

	go func() {
		packet := make([]byte, 2000)
		for {
			n, err := a.tunIn.Read(packet)
			if err != nil {
				log.Fatal(err)
			}
			pkt := gopacket.NewPacket(packet[:n], layers.IPProtocolIPv4, gopacket.Default)
			_ = pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if tcpr := pkt.Layer(layers.LayerTypeTCP); tcpr != nil {
				tcp := tcpr.(*layers.TCP)
				log.Infof("TCP packet, body: %+v", tcp)
				if tcp.DstPort != 12345 && tcp.SrcPort != 12345 {
					continue
				}
			} else {
				continue
			}
			//slog.Info("Packet Received", "body", ip)
			//terr := client.proxyTo(bytes.NewReader(packet[:n]), "127.0.0.1:8443", ip.DstIP.String())
			//slog.Info("tunnel", "err", terr)
		}
	}()

	// this is read by the defer statement above
	addIPCacheListener = true

	return nil
}

func (a *Agent) OnIPIdentityCacheChange(modType ipcache.CacheModification, cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP, oldID *ipcache.Identity, newID ipcache.Identity, encryptKey uint8, nodeID uint16, k8sMeta *ipcache.K8sMetadata) {
	log.Infof("IP cache changed")
}

func (a *Agent) OnIPIdentityCacheGC() {
	log.Infof("IP cache GC")
}
