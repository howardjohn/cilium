package hbone

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/quic-go/quic-go/http3"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

func (a *Agent) SetupServer() {
	s := &http3.Server{
		Addr: "0.0.0.0:15008",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				if a.handleConnect(w, r) {
					return
				}
			} else {
				log.Error("non-CONNECT", "method", r.Method)
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}),
		TLSConfig: generateTLSConfig(),
	}
	serr := s.ListenAndServe()
	log.Error("server complete", "err", serr)
}

func (a *Agent) handleConnect(w http.ResponseWriter, r *http.Request) bool {
	t0 := time.Now()
	log := log.WithField("host", r.Host)

	//req, err := httputil.DumpRequest(r, true)
	//slog.Info("debug", "resp", string(req), "err", err)

	w.WriteHeader(http.StatusOK)
	// Send headers back immediately so we can start getting the body
	w.(http.Flusher).Flush()
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		src := a.EndpointFromIP(net.ParseIP(xff))
		log = log.WithField("source", fmt.Sprintf("%+v", src))
	} else {
		log = log.WithField("source node", r.RemoteAddr)
	}
	// TODO: get the dest. It is just a packet, I guess we need to parse it and make sure the dest is on our node to avoid SSRF
	log.Info("Received CONNECT")
	n, err := io.Copy(a.tunIn, r.Body)
	//go func() {
	//	// downstream (hbone client) <-- upstream (app)
	//	// TODO: currently we have 1 directional; return traffic is another stream
	//	copyBuffered(w, &bytes.Buffer{}, log.With("name", "dst to w"))
	//	err := r.Body.Close()
	//	if err != nil {
	//		log.Info("connection to hbone client is not closed", "err", err)
	//	}
	//	wg.Done()
	//}()
	//// downstream (hbone client) --> upstream (app)
	//copyBuffered(ifce, r.Body, log.With("name", "body to dst"))

	log.Infof("connection closed, runtime=%v, data=%v, err=%v", time.Since(t0), n, err)
	return false
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h3"},
	}
}

// createBuffer to get a buffer. io.Copy uses 32k.
// experimental use shows ~20k max read with Firefox.
var bufferPoolCopy = sync.Pool{New: func() any {
	return make([]byte, 0, 32*1024)
}}

// CloseWriter is one of possible interfaces implemented by Out to send a FIN, without closing
// the input. Some writers only do this when Close is called.
type CloseWriter interface {
	CloseWrite() error
}

func closeWriter(dst io.Writer) error {
	if cw, ok := dst.(CloseWriter); ok {
		return cw.CloseWrite()
	}
	if c, ok := dst.(io.Closer); ok {
		return c.Close()
	}
	if rw, ok := dst.(http.ResponseWriter); ok {
		// Server side HTTP stream. For client side, FIN can be sent by closing the pipe (or
		// request body). For server, the FIN will be sent when the handler returns - but
		// this only happen after request is completed and body has been read. If server wants
		// to send FIN first - while still reading the body - we are in trouble.

		// That means HTTP2 TCP servers provide no way to send a FIN from server, without
		// having the request fully read.

		// This works for H2 with the current library - but very tricky, if not set as trailer.
		rw.Header().Set("X-Close", "0")
		rw.(http.Flusher).Flush()
		return nil
	}
	log.Info("Server out not Closer nor CloseWriter nor ResponseWriter")
	return nil
}
