package zeroconf

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Interface struct {
	net.Interface
	v4, v6 []netip.Addr // If no addr, the iface is ignored while communicating
}

// Heuristically compare whether an interface has changed, which can trigger other reactions.
func ifacesEqual(a, b *Interface) bool {
	if a.Index != b.Index || a.Flags != b.Flags || a.Name != b.Name || a.MTU != b.MTU {
		return false
	}
	return slices.Equal(a.v4, b.v4) && slices.Equal(a.v6, b.v6)
}

func (i *Interface) String() string {
	return fmt.Sprintf("%v %v %v", i.Name, i.v4, i.v6)
}

// Client structure encapsulates both IPv4/IPv6 UDP connections.
type dualConn struct {
	c4     *conn4
	c6     *conn6
	ifaces map[int]*Interface // key: iface.Index

	// Used initially and on reload to filter interfaces to use, default = net.Interfaces
	ifacesFn func() ([]net.Interface, error)
}

func newDualConn(ifacesFn func() ([]net.Interface, error), network string) (*dualConn, error) {

	c := &dualConn{
		ifaces:   make(map[int]*Interface),
		ifacesFn: ifacesFn,
	}

	var err4, err6 error
	switch network {
	case "udp":
		c.c4, err4 = newConn4()
		c.c6, err6 = newConn6()
	case "udp4":
		c.c4, err4 = newConn4()
	case "udp6":
		c.c6, err6 = newConn6()
	default:
		return nil, errors.New("invalid network")
	}
	_, err := c.loadIfaces()
	if err := errors.Join(err4, err6, err); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// Load (or reload) ifaces and return whether anything (addresses in particular) have changed.
func (c *dualConn) loadIfaces() (changed bool, err error) {
	ifaces := make(map[int]*Interface) // new ifaces
	netIfaces, err := c.ifacesFn()
	if err != nil {
		return false, err
	}
	for _, netIface := range netIfaces {
		if !isMulticastInterface(netIface) {
			continue
		}
		v4, v6, err := netIfaceAddrs(netIface)
		if err != nil {
			return false, err
		}
		iface := &Interface{Interface: netIface}
		// Join will fail if called multiple times, just attempt for now
		if c.c4 != nil && len(v4) > 0 {
			c.c4.JoinMulticast(netIface)
			iface.v4 = v4
		}
		if c.c6 != nil && len(v6) > 0 {
			c.c6.JoinMulticast(netIface)
			iface.v6 = v6
		}
		if len(iface.v4) > 0 || len(iface.v6) > 0 {
			ifaces[iface.Index] = iface
		}
	}
	changed = !maps.EqualFunc(c.ifaces, ifaces, ifacesEqual)
	c.ifaces = ifaces
	return changed, err
}

func (c *dualConn) conns() (conns []conn) {
	if c.c4 != nil {
		conns = append(conns, c.c4)
	}
	if c.c6 != nil {
		conns = append(conns, c.c6)
	}
	return
}

// Data receiving routine reads from connection, unpacks packets into dns.Msg
// structures and sends them to a given msgCh channel
func (c *dualConn) RunReader(msgCh chan msgMeta) error {
	var wg sync.WaitGroup
	conns := c.conns()
	errs := make([]error, len(conns))
	for idx := range conns {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = recvLoop(conns[idx], msgCh)
		}(idx)
	}
	wg.Wait()
	close(msgCh)
	return errors.Join(errs...)
}

func recvLoop(c conn, msgCh chan msgMeta) error {
	buf := make([]byte, 65536)
	for {
		n, src, ifIndex, err := c.ReadMulticast(buf)
		if err != nil {
			return err
		}
		srcNetip := src.(*net.UDPAddr).AddrPort()

		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			slog.Debug("failed to unpack packet", "src", src, "err", err)
			continue
		}
		msgCh <- msgMeta{msg, srcNetip.Addr().Unmap(), ifIndex}
	}
}

func (c *dualConn) WriteUnicast(msg *dns.Msg, ifIndex int, dst netip.Addr) (err error) {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	dstUdp := net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, mdnsPort))
	if c.c4 != nil && dst.Is4() {
		_, err = c.c4.WriteUnicast(buf, ifIndex, dstUdp)
	} else if c.c6 != nil && dst.Is6() {
		_, err = c.c6.WriteUnicast(buf, ifIndex, dstUdp)
	} else {
		err = fmt.Errorf("no suitable conn unicast msg: ifIndex=%v dst=%v", ifIndex, dst)
	}
	return
}

// Dst addr is only used for ipv4/ipv6 selection. Use nil to write on both.
func (c *dualConn) WriteMulticast(msg *dns.Msg, ifIndex int, dst *netip.Addr) (err error) {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	iface := c.ifaces[ifIndex]
	if iface == nil {
		return fmt.Errorf("iface with idx %v not found", ifIndex)
	}
	is4, is6 := true, true
	if dst != nil {
		is4, is6 = dst.Is4(), dst.Is6()
	}
	var err4, err6 error
	if len(iface.v4) > 0 && is4 {
		_, err4 = c.c4.WriteMulticast(buf, iface.Interface)
	}
	if len(iface.v6) > 0 && is6 {
		_, err6 = c.c6.WriteMulticast(buf, iface.Interface)
	}
	return errors.Join(err4, err6)
}

func (c *dualConn) SetDeadline(dl time.Time) error {
	var errs []error
	for _, conn := range c.conns() {
		errs = append(errs, conn.SetDeadline(dl))
	}
	return errors.Join(errs...)
}

func (c *dualConn) SetReadDeadline(dl time.Time) error {
	var errs []error
	for _, conn := range c.conns() {
		errs = append(errs, conn.SetReadDeadline(dl))
	}
	return errors.Join(errs...)
}

func (c *dualConn) SetWriteDeadline(dl time.Time) error {
	var errs []error
	for _, conn := range c.conns() {
		errs = append(errs, conn.SetWriteDeadline(dl))
	}
	return errors.Join(errs...)
}

func (c *dualConn) Close() error {
	var errs []error
	for _, conn := range c.conns() {
		errs = append(errs, conn.Close())
	}
	return errors.Join(errs...)
}

// Returns mDNS-suitable unicast addresses for a net.Interface
func netIfaceAddrs(iface net.Interface) (v4, v6 []netip.Addr, err error) {
	var v6local []netip.Addr
	ifaceAddrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}
	for _, address := range ifaceAddrs {
		ipnet, ok := address.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if ip.Is4() {
			v4 = append(v4, ip)
		} else if ip.Is6() {
			if ip.IsGlobalUnicast() {
				v6 = append(v6, ip)
			} else if ip.IsLinkLocalUnicast() {
				v6local = append(v6local, ip)
			}
		}
	}
	// 1 ip of each type is enough
	v4, v6 = max1(v4), append(max1(v6), max1(v6local)...)
	return
}

func max1[T any](slice []T) []T {
	if len(slice) > 1 {
		return slice[1:]
	}
	return slice
}
