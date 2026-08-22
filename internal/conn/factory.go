package conn

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/arash16/dualnet/internal/cipher"
	"github.com/arash16/dualnet/internal/netbind"
	"github.com/arash16/dualnet/internal/peers"
	"github.com/arash16/dualnet/internal/pktbuf"
	"github.com/arash16/dualnet/internal/proto"
	"github.com/arash16/dualnet/internal/wire"
)

// Spec is everything the factory needs to build one connection. The node
// composition root fills it from a config connection plus derived state (cipher key,
// dialer, tun device, id-assignment hooks).
type Spec struct {
	Name      string
	Kind      Kind
	Transport string     // "http" | "udp" (ignored for tun)
	Cipher    string     // "chacha4" | "none"
	Key       [32]byte   // per-connection PSK-derived key
	HTTP      HTTPParams // http transport: carrier customization (paths/headers)

	// Connect connections.
	Dialer   SocketDialer
	RemoteIP string
	Port     int
	MaxAge   time.Duration // http connect-out recycle age
	IDSetter func(wire.Owner)
	InitID   wire.Owner // connect-in: claimed id to start with (0 if none)

	// Listen connections.
	Listen     string // ":port"
	Iface      string // bind interface (optional)
	Multiple   bool
	SessionTTL time.Duration
	MaxPeers   int // multiple listen-out: cap on tracked peers (0 = unbounded)

	// Tun connections.
	Dev     TunDevice
	Pending bool // tun id is set by a remote (hold reads until then)

	// Flush is the node-wide group that flushes buffered write batches on an interval; every
	// connection that buffers writes (tun, connect-out, listen-out) registers its writer with it.
	Flush *pktbuf.FlushGroup

	// OnDrop, if set, is called by a data-receiving connection whenever an inbound
	// packet fails to decrypt or parse (e.g. a PSK mismatch or corruption). Used for
	// stats; must be safe for concurrent use.
	OnDrop func()
}

// Maintainer is implemented by connections with idle peer state the node should GC.
type Maintainer interface{ GC() int }

// New builds a runtime connection from a Spec.
func New(ctx context.Context, s Spec) (Conn, error) {
	switch s.Kind {
	case KindTun:
		return NewTun(s.Name, s.Dev, s.InitID, s.Pending, s.Flush), nil

	case KindConnectOut:
		switch s.Transport {
		case "http":
			sc, err := cipher.NewStream(s.Cipher, s.Key)
			if err != nil {
				return nil, err
			}
			h := s.HTTP.withDefaults(hostPort(s.RemoteIP, s.Port))
			return &httpConnectOut{
				name: s.Name, host: hostPort(s.RemoteIP, s.Port), path: h.UploadPath,
				hostHeader: h.Host, userAgent: h.UserAgent, idHeader: h.IDHeader, headers: h.Headers,
				chanID: ownerHex(randomOwner()), cipher: sc, dialer: s.Dialer, maxAge: s.MaxAge,
			}, nil
		case "udp":
			pc, err := cipher.NewPacket(s.Cipher, s.Key)
			if err != nil {
				return nil, err
			}
			return &udpConnectOut{name: s.Name, addr: hostPort(s.RemoteIP, s.Port), dialer: s.Dialer, cipher: pc}, nil
		case "tcp":
			sc, err := cipher.NewStream(s.Cipher, s.Key)
			if err != nil {
				return nil, err
			}
			c := &tcpConnectOut{name: s.Name, addr: hostPort(s.RemoteIP, s.Port), dialer: s.Dialer, cipher: sc, fg: s.Flush}
			c.w = pktbuf.NewWriter(c.flush, tcpWriteBufSize, streamWriteBatch)
			s.Flush.Add(c.w)
			return c, nil
		}

	case KindConnectIn:
		switch s.Transport {
		case "http":
			sc, err := cipher.NewStream(s.Cipher, s.Key)
			if err != nil {
				return nil, err
			}
			tr := &http.Transport{DialContext: s.Dialer.DialContext, DisableKeepAlives: true}
			h := s.HTTP.withDefaults(hostPort(s.RemoteIP, s.Port))
			return &httpConnectIn{
				name: s.Name, url: urlFor(s.RemoteIP, s.Port, h.DownloadPath),
				hostHeader: h.Host, userAgent: h.UserAgent, idHeader: h.IDHeader, key: s.Key, headers: h.Headers,
				cipher: sc, client: &http.Client{Transport: tr}, idSetter: s.IDSetter, curID: s.InitID,
				onDrop: s.OnDrop,
			}, nil
		case "udp":
			pc, err := cipher.NewPacket(s.Cipher, s.Key)
			if err != nil {
				return nil, err
			}
			return &udpConnectIn{
				name: s.Name, addr: hostPort(s.RemoteIP, s.Port), dialer: s.Dialer, cipher: pc,
				key: s.Key, idSetter: s.IDSetter, refresh: proto.DefaultKeepalive, curID: s.InitID,
				onDrop: s.OnDrop,
			}, nil
		case "tcp":
			sc, err := cipher.NewStream(s.Cipher, s.Key)
			if err != nil {
				return nil, err
			}
			return &tcpConnectIn{
				name: s.Name, addr: hostPort(s.RemoteIP, s.Port), dialer: s.Dialer, cipher: sc,
				key: s.Key, idSetter: s.IDSetter, refresh: proto.DefaultKeepalive, curID: s.InitID,
				onDrop: s.OnDrop,
			}, nil
		}

	case KindListenIn:
		switch s.Transport {
		case "http":
			sc, err := cipher.NewStream(s.Cipher, s.Key)
			if err != nil {
				return nil, err
			}
			ln, err := listenTCP(ctx, s.Iface, s.Listen)
			if err != nil {
				return nil, err
			}
			h := s.HTTP.withDefaults("")
			c := &httpListenIn{
				name: s.Name, cipher: sc, active: make(map[string]*httpInHandle), ln: ln, onDrop: s.OnDrop,
				path: h.UploadPath, idHeader: h.IDHeader,
			}
			c.srv = &http.Server{Handler: http.HandlerFunc(c.serveHTTP), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: httpIdleTimeout}
			return c, nil
		case "udp":
			pc, err := cipher.NewPacket(s.Cipher, s.Key)
			if err != nil {
				return nil, err
			}
			uc, err := bindUDP(ctx, s.Iface, s.Listen)
			if err != nil {
				return nil, err
			}
			return &udpListenIn{name: s.Name, conn: uc, cipher: pc, onDrop: s.OnDrop}, nil
		case "tcp":
			sc, err := cipher.NewStream(s.Cipher, s.Key)
			if err != nil {
				return nil, err
			}
			ln, err := listenTCP(ctx, s.Iface, s.Listen)
			if err != nil {
				return nil, err
			}
			return &tcpListenIn{name: s.Name, ln: ln, cipher: sc, onDrop: s.OnDrop}, nil
		}

	case KindListenOut:
		switch s.Transport {
		case "http":
			sc, err := cipher.NewStream(s.Cipher, s.Key)
			if err != nil {
				return nil, err
			}
			ln, err := listenTCP(ctx, s.Iface, s.Listen)
			if err != nil {
				return nil, err
			}
			h := s.HTTP.withDefaults("")
			c := &httpListenOut{
				name: s.Name, cipher: sc, multiple: s.Multiple, byID: make(map[wire.Owner]*httpDownConn),
				lastTS: make(map[wire.Owner]uint64), key: s.Key, maxPeers: s.MaxPeers, ln: ln,
				path: h.DownloadPath, idHeader: h.IDHeader, fg: s.Flush,
			}
			c.srv = &http.Server{Handler: http.HandlerFunc(c.serveHTTP), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: httpIdleTimeout}
			return c, nil
		case "udp":
			pc, err := cipher.NewPacket(s.Cipher, s.Key)
			if err != nil {
				return nil, err
			}
			uc, err := bindUDP(ctx, s.Iface, s.Listen)
			if err != nil {
				return nil, err
			}
			return &udpListenOut{name: s.Name, conn: uc, cipher: pc, key: s.Key, multiple: s.Multiple, reg: peers.New(s.Multiple, s.SessionTTL, s.MaxPeers)}, nil
		case "tcp":
			sc, err := cipher.NewStream(s.Cipher, s.Key)
			if err != nil {
				return nil, err
			}
			ln, err := listenTCP(ctx, s.Iface, s.Listen)
			if err != nil {
				return nil, err
			}
			return &tcpListenOut{name: s.Name, ln: ln, cipher: sc, key: s.Key, multiple: s.Multiple, reg: peers.New(s.Multiple, s.SessionTTL, s.MaxPeers), fg: s.Flush}, nil
		}
	}
	return nil, fmt.Errorf("conn: unsupported kind/transport %v/%q", s.Kind, s.Transport)
}

func hostPort(ip string, port int) string { return net.JoinHostPort(ip, strconv.Itoa(port)) }

// maxHTTPConns bounds simultaneously-accepted connections on an HTTP listener, so an attacker
// opening many connections (slowloris) cannot exhaust goroutines/memory. With the per-frame read
// deadline reaping stalled bodies, legit clients still get slots as stalled attackers time out.
const maxHTTPConns = 256

// httpIdleTimeout bounds how long an accepted keep-alive connection may sit between requests.
// httpFrameReadTimeout bounds how long a streaming body may stall with no frame before it is torn
// down (a slowloris that sends headers then stalls the chunked body). It is generous so a briefly
// idle-but-alive tunnel is not severed; the client reconnects on its next packet if it is.
const (
	httpIdleTimeout      = 90 * time.Second
	httpFrameReadTimeout = 2 * time.Minute
)

func listenTCP(ctx context.Context, iface, addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: netbind.Control(iface)}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return newLimitListener(ln, maxHTTPConns), nil
}

// limitListener caps concurrently-open connections; excess accepts block until a slot frees when
// an accepted connection is closed. Inlined (rather than pulling golang.org/x/net/netutil) so the
// bound lives next to the servers it protects.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

func newLimitListener(l net.Listener, n int) net.Listener {
	return &limitListener{Listener: l, sem: make(chan struct{}, n)}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
