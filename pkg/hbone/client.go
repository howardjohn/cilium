package hbone

import (
	"crypto/tls"
	"fmt"
	"github.com/quic-go/quic-go/http3"
	"io"
	"net/http"
	"time"
)

type TunnelClient struct {
	*http3.RoundTripper
}

func SetupClient() TunnelClient {
	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return TunnelClient{roundTripper}
}

func (t TunnelClient) proxyTo(conn io.Reader, src, dst EndpointInfo) error {
	t0 := time.Now()

	proxyAddress := dst.NodeIP.String() + ":15008"
	destAddress := dst.PodIP.String()

	url := "https://" + proxyAddress
	// Setup a pipe. We could just pass `conn` to `http.NewRequest`, but this has a few issues:
	// * Less visibility into i/o
	// * http will call conn.Close, which will close before we want to (finished writing response).
	r, err := http.NewRequest(http.MethodConnect, url, conn)
	r.URL.Scheme = "https"
	if err != nil {
		return fmt.Errorf("new request: %v", err)
	}
	r.Host = destAddress
	r.Header.Set("X-Forwarded-For", src.PodIP.String())

	//req, _ := httputil.DumpRequestOut(r, true)
	//slog.Info("debug", "req", string(req))

	log := log.WithField("proxy", proxyAddress).WithField("destination", destAddress)
	// Initiate CONNECT.
	log.Info("initiate CONNECT")

	resp, err := t.RoundTrip(r)
	if err != nil {
		return fmt.Errorf("round trip: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("round trip failed: %v", resp.Status)
	}
	log.Info("CONNECT established")

	// TODO bidirectional
	log.Infof("stream closed, runtime: %v", time.Since(t0))

	return nil
}
