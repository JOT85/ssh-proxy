package main

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
)

var AllTCP = TCPRange{
	IPNet: &net.IPNet{
		IP:   net.IPv4(0, 0, 0, 0),
		Mask: net.IPv4Mask(0, 0, 0, 0),
	},
	MinPort: 0,
	MaxPort: math.MaxUint16,
}

// TCPRange is an allowed [net.IPNet], with an additional port range.
type TCPRange struct {
	IPNet   *net.IPNet
	MinPort uint16
	MaxPort uint16
}

func (tcpRange *TCPRange) String() string {
	return tcpRange.IPNet.String() + ":" + strconv.FormatUint(uint64(tcpRange.MinPort), 10) + "-" + strconv.FormatUint(uint64(tcpRange.MaxPort), 10)
}

// Contains decides if the provided addr is within the network and port range allowed.
func (tcpRange *TCPRange) Contains(addr *net.TCPAddr) bool {
	if addr.Port < 0 || addr.Port > int(math.MaxUint16) {
		return false
	}
	port := uint16(addr.Port)
	return tcpRange.IPNet.Contains(addr.IP) && tcpRange.MinPort <= port && port <= tcpRange.MaxPort
}

// ParseTCPRange parses a string describing a TCP address+port range, the syntax is:
//
//   - ":123" = any ip, port 123
//   - "*:123" = any ip, port 123
//   - "*:*" = any ip, any port
//   - "*" = any ip, any port
//   - ":123-456" = any ip, port between 123 and 456 (inclusive)
//   - "1.1.1.1:123" = specific ip, port 123
//   - "10.0.0.0/8:123" = CIDR range, port 123
//   - "10.0.0.0/8" = CIDR range, any port
//   - "10.0.0.1" = specific IP, any port
//   - "10.0.0.1:*" = specific IP, any port
func ParseTCPRange(s string) (tcpRange *TCPRange, err error) {
	tcpRange = new(TCPRange)

	lastColon := strings.LastIndex(s, ":")
	if lastColon >= 0 {
		// If there's a colon, take the content after the final colon as the port range
		portRange := s[lastColon+1:]
		s = s[:lastColon]

		hyphenIdx := strings.IndexRune(portRange, '-')
		if hyphenIdx > 0 {
			// If there's a hyphen (that isn't at the start), interpret it as a port range, for
			// example "1024-65535"
			minPort64, err := strconv.ParseUint(portRange[:hyphenIdx], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("failed to parse start port %v from port range %v: %w", portRange[:hyphenIdx], portRange, err)
			}
			tcpRange.MinPort = uint16(minPort64)

			maxPort64, err := strconv.ParseUint(portRange[hyphenIdx+1:], 10, 16)
			if err != nil {
				return nil, fmt.Errorf("failed to parse end port %v from port range %v: %w", portRange[hyphenIdx+1:], portRange, err)
			}
			tcpRange.MaxPort = uint16(maxPort64)
		} else if portRange == "*" {
			tcpRange.MinPort = 0
			tcpRange.MaxPort = math.MaxUint16
		} else {
			// Anything else should just be a single number
			port, err := strconv.ParseUint(portRange, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("failed to parse port range %v as a port number: %w", portRange, err)
			}
			tcpRange.MinPort = uint16(port)
			tcpRange.MaxPort = uint16(port)
		}
	} else {
		// If there's no port range, default to any port
		tcpRange.MinPort = 0
		tcpRange.MaxPort = math.MaxUint16
	}

	if s == "" || s == "*" {
		// If the IP is empty, or *, any IP is allowed
		tcpRange.IPNet = &net.IPNet{
			IP:   net.IPv4(0, 0, 0, 0),
			Mask: net.IPv4Mask(0, 0, 0, 0),
		}
	} else if strings.ContainsRune(s, '/') {
		// If it contains a slash, it's parsed as a CIDR
		_, tcpRange.IPNet, err = net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CIDR %v: %w", s, err)
		}
	} else {
		// Otherwise, it's parsed as a plain IP
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("failed to parse IP %v", s)
		}
		tcpRange.IPNet = &net.IPNet{
			IP:   ip,
			Mask: net.IPv4Mask(255, 255, 255, 255),
		}
	}

	return
}
