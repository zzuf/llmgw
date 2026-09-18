// Package acl evaluates model allow lists using only the TCP peer address.
package acl

import (
	"net"
	"net/netip"
	"slices"
	"strings"
)

func SourceIP(remoteAddr string) netip.Addr {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap().WithZone("")
}
func IPAllowed(ip netip.Addr, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap().WithZone("")
	for _, entry := range allowed {
		if p, err := netip.ParsePrefix(entry); err == nil {
			if p.Addr().Is4In6() {
				if p.Bits() < 96 {
					continue
				}
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			if p.Contains(ip) {
				return true
			}
			continue
		}
		if p, err := netip.ParseAddr(strings.TrimSpace(entry)); err == nil && p.Unmap() == ip {
			return true
		}
	}
	return false
}
func Allowed(ip netip.Addr, ips, keys []string, keyID string) bool {
	return IPAllowed(ip, ips) && (len(keys) == 0 || (keyID != "" && slices.Contains(keys, keyID)))
}
