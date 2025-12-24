package envelope

import (
	"net"
	"net/netip"
)

func addrIP(addr net.Addr) (netip.Addr, bool) {
	switch v := addr.(type) {
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice(v.IP); ok {
			return ip, true
		}
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip, true
}
