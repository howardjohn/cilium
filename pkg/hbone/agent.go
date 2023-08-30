package hbone

import (
	"bytes"
	"fmt"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ip"
	ippkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
	epManager  endpointmanager.EndpointManager
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
	if err := connector.DisableRpFilter(ifce.Name()); err != nil {
		return nil, fmt.Errorf("failed to disable RP filter: %v", err)
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

//Current state: we get the packets, but do nothing with them. Need to establish the other end, etc.

func (a *Agent) Init(ipcache *ipcache.IPCache, epmanager endpointmanager.EndpointManager) error {
	addIPCacheListener := false
	a.Lock()
	a.ipCache = ipcache
	a.epManager = epmanager
	defer func() {
		// IPCache will call back into OnIPIdentityCacheChange which requires
		// us to release a.mutex before we can add ourself as a listener.
		a.Unlock()
		if addIPCacheListener {
			a.ipCache.AddListener(a)
		}
	}()
	go a.SetupServer()
	client := SetupClient()
	go func() {
		packet := make([]byte, 2000)
		for {
			n, err := a.tunIn.Read(packet)
			if err != nil {
				log.Fatal(err)
			}
			pkt := gopacket.NewPacket(packet[:n], layers.IPProtocolIPv4, gopacket.Default)
			ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if tcpr := pkt.Layer(layers.LayerTypeTCP); tcpr != nil {
				tcp := tcpr.(*layers.TCP)
				log.Infof("TCP packet, body: %+v", tcp)
				//if tcp.DstPort != 12345 && tcp.SrcPort != 12345 {
				//	continue
				//}
			} else {
				//continue
			}
			// TODO: IP needs to be the node IP
			//slog.Info("Packet Received", "body", ip)
			dst := a.EndpointFromIP(ip.DstIP)
			src := a.EndpointFromIP(ip.SrcIP)
			log.Infof("sending request %+v->%+v", src, dst)
			terr := client.proxyTo(bytes.NewReader(packet[:n]), src, dst)
			log.Infof("tunnel: %v", terr)
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
func (a *Agent) EndpointFromIP(connIP net.IP) EndpointInfo {
	res := EndpointInfo{
		PodIP: connIP,
	}
	res.NodeIP = a.hostIPForConnIP(connIP)
	addr, ok := ippkg.AddrFromIP(connIP)
	if ok {
		lbls := a.ipCache.GetIDMetadataByIP(addr)
		for k, v := range lbls {
			if k == "k8s:io.cilium.k8s.policy.serviceaccount" {
				res.ServiceAccount = v.Value
			}
		}
		if meta := a.ipCache.GetK8sMetadata(connIP.String()); meta != nil {
			res.PodName = meta.PodName
			res.Namespace = meta.Namespace
		}
		//if ep := a.epManager.LookupIP(addr); ep != nil {
		//	res.Namespace = ep.K8sNamespace
		//	res.PodName = ep.K8sPodName
		//	for _, lbl := range ep.GetLabels() {
		//		k, v, ok := strings.Cut(lbl, "=")
		//		if !ok {
		//			continue
		//		}
		//		if k == "k8s:io.cilium.k8s.policy.serviceaccount" {
		//			res.ServiceAccount = v
		//		}
		//	}
		//}
	}
	return res
}

func (a *Agent) hostIPForConnIP(connIP net.IP) net.IP {
	hostIP := a.ipCache.GetHostIP(connIP.String())
	if hostIP != nil {
		return hostIP
	}

	// Checking for Cilium's internal IP (cilium_host).
	// This might be the case when checking ingress auth after egress L7 policies are applied and therefore traffic
	// gets rerouted via Cilium's envoy proxy.
	if ip.IsIPv4(connIP) {
		return a.ipCache.GetHostIP(fmt.Sprintf("%s/32", connIP))
	} else if ip.IsIPv6(connIP) {
		return a.ipCache.GetHostIP(fmt.Sprintf("%s/128", connIP))
	}

	return nil
}

type EndpointInfo struct {
	PodIP          net.IP
	NodeIP         net.IP
	Namespace      string
	ServiceAccount string
	PodName        string
}
