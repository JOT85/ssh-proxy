package main

import (
	"net"
	"net/netip"
	"testing"
)

func TestTcpRangeParsing(t *testing.T) {
	checkRange := func(a, b string) {
		result, err := ParseTCPRange(a)
		if err != nil {
			t.Errorf("failed to parse %v: %v", a, err)
		} else if result.String() != b {
			t.Errorf("%v -> %v != %v", a, result.String(), b)
		}
	}

	checkRange("*", "0.0.0.0/0:0-65535")
	checkRange("*:*", "0.0.0.0/0:0-65535")
	checkRange("*:34", "0.0.0.0/0:34-34")
	checkRange("*:34-99", "0.0.0.0/0:34-99")
	checkRange("*:1024-65535", "0.0.0.0/0:1024-65535")
	checkRange("10.0.0.2:1024-65535", "10.0.0.2/32:1024-65535")
	checkRange("10.0.0.2/16:1024-65535", "10.0.0.0/16:1024-65535")
	checkRange("10.3.0.2/16:*", "10.3.0.0/16:0-65535")
	checkRange("10.3.0.2/8", "10.0.0.0/8:0-65535")
	checkRange("10.3.0.2", "10.3.0.2/32:0-65535")
	checkRange("10.3.0.2:22", "10.3.0.2/32:22-22")
}

func TestTcpRangeContains(t *testing.T) {
	includes := func(a, b string) {
		addr := net.TCPAddrFromAddrPort(netip.MustParseAddrPort(b))
		result, err := ParseTCPRange(a)
		if err != nil {
			t.Errorf("failed to parse %v: %v", a, err)
		} else if !result.Contains(addr) {
			t.Errorf("%v -> %v does not contain %v", a, result.String(), b)
		}
	}
	excludes := func(a, b string) {
		addr := net.TCPAddrFromAddrPort(netip.MustParseAddrPort(b))
		result, err := ParseTCPRange(a)
		if err != nil {
			t.Errorf("failed to parse %v: %v", a, err)
		} else if result.Contains(addr) {
			t.Errorf("%v -> %v contains %v", a, result.String(), b)
		}
	}

	includes("*", "1.1.1.1:0")
	includes("*", "1.1.1.1:30")
	includes("*", "1.1.1.1:65535")
	includes("*", "255.255.255.255:65535")
	includes("*", "0.0.0.0:65535")

	includes("*:34", "1.1.1.1:34")
	excludes("*:34", "1.1.1.1:32")
	excludes("*:34", "1.1.1.1:0")
	excludes("*:34", "1.1.1.1:65535")

	excludes("*:34-99", "1.1.1.1:0")
	excludes("*:34-99", "1.1.1.1:32")
	excludes("*:34-99", "1.1.1.1:33")
	includes("*:34-99", "1.1.1.1:34")
	includes("*:34-99", "1.1.1.1:35")
	includes("*:34-99", "1.1.1.1:60")
	includes("*:34-99", "1.1.1.1:98")
	includes("*:34-99", "1.1.1.1:99")
	excludes("*:34-99", "1.1.1.1:100")
	excludes("*:34-99", "1.1.1.1:101")
	excludes("*:34-99", "1.1.1.1:65535")

	includes("10.0.0.2:1024-65535", "10.0.0.2:1024")
	excludes("10.0.0.2:1024-65535", "10.0.0.2:1023")
	excludes("10.0.0.2:1024-65535", "10.0.0.1:1023")
	excludes("10.0.0.2:1024-65535", "10.0.0.1:1024")
	excludes("10.0.0.2:1024-65535", "10.0.0.1:1026")
	includes("10.0.0.2:1024-65535", "10.0.0.2:1026")
	excludes("10.0.0.2:1024-65535", "12.0.0.2:1026")
}
