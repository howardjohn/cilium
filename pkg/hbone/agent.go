package hbone

import (
	"fmt"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"net"
	"syscall"
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
}

func NewAgent() (*Agent, error) {
	log.Infof("howardjohn: creating hbone agent")
	return &Agent{
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

	l, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", a.listenPort))
	log.Errorf("howardjohn bind: %v", err)
	if err != nil {
		return fmt.Errorf("failed to bind: %v", err)
	}
	fd, err := l.(*net.TCPListener).File()
	if err != nil {
		return fmt.Errorf("file: %v", err)
	}
	log.Errorf("howardjohn bind: %v %v", l.Addr().String(), fd)
	err = syscall.SetsockoptInt(int(fd.Fd()), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
	if err != nil {
		return fmt.Errorf("set transparent: %v", err)
	}

	a.listener = l
	go func() {
		log.Errorf("howardjohn: accept loop...")
		for {
			log.Errorf("howardjohn: start accept...")
			conn, err := l.Accept()
			log.Errorf("howardjohn: accepted")
			if err != nil {
				log.Errorf("failed to listen: %v", err)
				return
			}
			laddr := conn.RemoteAddr().String()
			log.Infof("howardjohn: accepted connection from %v", laddr)
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
