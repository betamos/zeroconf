package zeroconf

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Interface struct {
	net.Interface
	is4, is6 bool
}

// Client structure encapsulates both IPv4/IPv6 UDP connections.
type dualConn struct {
	c4     *conn4
	c6     *conn6
	ifaces []*Interface
}

func newDualConn(ifaces []net.Interface, ipType IPType) (*dualConn, error) {

	if (ipType&IPv4) == 0 && (ipType&IPv6) == 0 {
		return nil, errors.New("invalid ip type")
	}

	c := new(dualConn)
	var err error
	// IPv4 interfaces
	if (ipType & IPv4) > 0 {
		c.c4, err = newConn4()
		if err != nil {
			return nil, err
		}
	}
	// IPv6 interfaces
	if (ipType & IPv6) > 0 {
		c.c6, err = newConn6()
		if err != nil {
			return nil, err
		}
	}

	if ifaces == nil {
		ifaces, _ = net.Interfaces()
	}
	for _, iface := range ifaces {
		if !isMulticastInterface(iface) {
			continue
		}
		iface2 := &Interface{Interface: iface}
		if c.c4 != nil {
			err = c.c4.JoinMulticast(iface)
			iface2.is4 = err == nil
		}
		if c.c6 != nil {
			err = c.c6.JoinMulticast(iface)
			iface2.is6 = err == nil
		}
		c.ifaces = append(c.ifaces, iface2)
	}

	return c, nil
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

func (c *dualConn) Addrs() (v4, v6 []netip.Addr) {
	var v6local []netip.Addr
	for _, iface := range c.ifaces {
		addrs, _ := iface.Addrs()
		for _, address := range addrs {
			ipnet, ok := address.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			if ip.Is4() && iface.is4 {
				v4 = append(v4, ip)
			} else if ip.Is6() && iface.is6 {
				if ip.IsGlobalUnicast() {
					v6 = append(v6, ip)
				} else if ip.IsLinkLocalUnicast() {
					v6local = append(v6local, ip)
				}
			}
		}
	}
	if len(v6) == 0 {
		v6 = v6local
	}
	return
}

// Data receiving routine reads from connection, unpacks packets into dns.Msg
// structures and sends them to a given msgCh channel
func (c *dualConn) RunReader(msgCh chan MsgMeta) error {
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

func recvLoop(c conn, msgCh chan MsgMeta) error {
	buf := make([]byte, 65536)
	for {
		n, from, ifIndex, err := c.ReadMulticast(buf)
		if err != nil {
			return err
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			// log.Printf("[WARN] mdns: Failed to unpack packet: %v", err)
			continue
		}
		msgCh <- MsgMeta{msg, from, ifIndex}
	}
}

func (c *dualConn) WriteMulticastAll(msg *dns.Msg) error {
	return c.WriteMulticast(msg, 0, nil)
}

func (c *dualConn) WriteUnicast(msg *dns.Msg, ifIndex int, dst net.Addr) (err error) {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	ty := addrType(dst)
	if c.c4 != nil && (ty&IPv4) > 0 {
		_, err = c.c4.WriteUnicast(buf, ifIndex, dst)
	} else if c.c6 != nil && (ty&IPv6) > 0 {
		_, err = c.c6.WriteUnicast(buf, ifIndex, dst)
	} else {
		err = fmt.Errorf("no suitable conn unicast msg: ifIndex=%v dst=%v", ifIndex, dst)
	}
	return
}

// Dst addr is only used for ipv4/ipv6 selection.
func (c *dualConn) WriteMulticast(msg *dns.Msg, ifIndex int, dst net.Addr) error {
	buf, err := msg.Pack()
	if err != nil {
		return err
	}
	for _, iface := range c.ifaces {
		if !(ifIndex == 0 || iface.Index == ifIndex) {
			continue
		}
		ty := addrType(dst)

		// TODO: Log failures
		if c.c4 != nil && iface.is4 && (ty&IPv4) > 0 {
			c.c4.WriteMulticast(buf, iface.Interface)
		}
		if c.c6 != nil && iface.is6 && (ty&IPv6) > 0 {
			c.c6.WriteMulticast(buf, iface.Interface)
		}
	}
	return nil
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
