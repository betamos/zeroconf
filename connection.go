package zeroconf

import (
	"net"
	"net/netip"
	"runtime"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const mdnsPort = 5353

var (
	// Multicast groups used by mDNS
	mdnsGroupIPv4 = net.IPv4(224, 0, 0, 251)
	mdnsGroupIPv6 = net.ParseIP("ff02::fb")

	// mDNS wildcard addresses
	mdnsWildcardAddrIPv4 = &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.0"),
		Port: mdnsPort,
	}
	mdnsWildcardAddrIPv6 = &net.UDPAddr{
		IP:   net.ParseIP("ff02::"),
		Port: mdnsPort,
	}

	// mDNS endpoint addresses
	ipv4Addr = &net.UDPAddr{
		IP:   mdnsGroupIPv4,
		Port: mdnsPort,
	}
	ipv6Addr = &net.UDPAddr{
		IP:   mdnsGroupIPv6,
		Port: mdnsPort,
	}
)

// Shared ipv4 and ipv6 multicast ops.
type conn interface {
	JoinMulticast(net.Interface) error
	ReadMulticast(buf []byte) (n int, src net.Addr, ifIndex int, err error)
	WriteMulticast(buf []byte, iface net.Interface) (n int, err error)
	WriteUnicast(buf []byte, ifIndex int, addr net.Addr) (n int, err error)
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	SetDeadline(time.Time) error
	Close() error
}

type MsgMeta struct {
	*dns.Msg
	Src netip.Addr

	// The index of the interface the message came from. Note this cannot be trusted fully:
	//
	// First, there may be some cases (Windows) where the index isn't provided (and thus, 0).
	// In those cases, we reply to all interfaces to be safe.
	//
	// Secondly, experiments (on Linux w. ethernet and wifi) show that packets sent on
	// one interface may be received on two interfaces. Thus, we shouldn't use iface index
	// as a key or for deduplication.
	//
	// In short: If an index is non-zero, we reply on the same index. If zero, we
	// must respond to all indices.
	IfIndex int
}

type conn4 struct {
	*ipv4.PacketConn
}

var _ conn = &conn4{}

func newConn4() (c *conn4, err error) {
	// IPv4 interfaces

	udpConn, err := net.ListenUDP("udp4", mdnsWildcardAddrIPv4)
	if err != nil {
		return nil, err
	}
	pc := ipv4.NewPacketConn(udpConn)
	_ = pc.SetControlMessage(ipv4.FlagInterface, true)
	_ = pc.SetMulticastTTL(255)
	return &conn4{pc}, nil
}

func (c *conn4) JoinMulticast(iface net.Interface) (err error) {
	return c.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv4})
}

func (c *conn4) ReadMulticast(buf []byte) (n int, src net.Addr, ifIndex int, err error) {
	var cm *ipv4.ControlMessage
	n, cm, src, err = c.ReadFrom(buf)
	if cm != nil {
		ifIndex = cm.IfIndex
	}
	return
}

func (c *conn4) WriteMulticast(buf []byte, iface net.Interface) (int, error) {
	// See https://pkg.go.dev/golang.org/x/net/ipv4#pkg-note-BUG
	// As of Golang 1.18.4
	// On Windows, the ControlMessage for ReadFrom and WriteTo methods of PacketConn is not implemented.
	var wcm ipv4.ControlMessage
	switch runtime.GOOS {
	case "darwin", "ios", "linux":
		wcm.IfIndex = iface.Index
	default:
		if err := c.SetMulticastInterface(&iface); err != nil {
			return 0, err
		}
	}
	return c.WriteTo(buf, &wcm, ipv4Addr)
}

func (c *conn4) WriteUnicast(buf []byte, ifIndex int, addr net.Addr) (int, error) {
	wcm := &ipv4.ControlMessage{IfIndex: ifIndex}
	return c.WriteTo(buf, wcm, addr)
}

type conn6 struct {
	*ipv6.PacketConn
}

var _ conn = &conn6{}

func newConn6() (c *conn6, err error) {
	// TODO: Use `REUSEPORT`, RFC 6762 section 15.1.
	udpConn, err := net.ListenUDP("udp6", mdnsWildcardAddrIPv6)
	if err != nil {
		return nil, err
	}
	pc := ipv6.NewPacketConn(udpConn)
	_ = pc.SetControlMessage(ipv6.FlagInterface, true)
	_ = pc.SetMulticastHopLimit(255)
	return &conn6{pc}, nil
}

func (c *conn6) JoinMulticast(iface net.Interface) (err error) {
	return c.JoinGroup(&iface, &net.UDPAddr{IP: mdnsGroupIPv6})
}

func (c *conn6) ReadMulticast(buf []byte) (n int, src net.Addr, ifIndex int, err error) {
	var cm *ipv6.ControlMessage
	n, cm, src, err = c.ReadFrom(buf)
	if cm != nil {
		ifIndex = cm.IfIndex
	}
	return
}

func (c *conn6) WriteMulticast(buf []byte, iface net.Interface) (int, error) {
	// See https://pkg.go.dev/golang.org/x/net/ipv4#pkg-note-BUG
	// As of Golang 1.18.4
	// On Windows, the ControlMessage for ReadFrom and WriteTo methods of PacketConn is not implemented.
	var wcm ipv6.ControlMessage
	switch runtime.GOOS {
	case "darwin", "ios", "linux":
		wcm.IfIndex = iface.Index
	default:
		if err := c.SetMulticastInterface(&iface); err != nil {
			return 0, err
		}
	}
	return c.WriteTo(buf, &wcm, ipv6Addr)
}

func (c *conn6) WriteUnicast(buf []byte, ifIndex int, addr net.Addr) (int, error) {
	wcm := &ipv6.ControlMessage{IfIndex: ifIndex}
	return c.WriteTo(buf, wcm, addr)
}

func isMulticastInterface(iface net.Interface) bool {
	return (iface.Flags&net.FlagUp) > 0 && (iface.Flags&net.FlagMulticast) > 0
}
