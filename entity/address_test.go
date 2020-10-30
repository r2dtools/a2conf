package entity

import "testing"

func TestCreateVhostAddressFromString(t *testing.T) {
	type AddrData struct {
		AddrStr,
		Host,
		Port string
	}

	items := []AddrData{
		{"127.0.0.1:8080", "127.0.0.1", "8080"},
		{"172.20.30.50:80", "172.20.30.50", "80"},
		{"*:443", "*", "443"},
		{"172.20.30.40", "172.20.30.40", ""},
		{"[2607:f0d0:1002:11::4]:80", "[2607:f0d0:1002:11::4]", "80"},
		{"[2607:f0d0:1002:11::4]", "[2607:f0d0:1002:11::4]", ""},
	}

	for _, item := range items {
		address := CreateVhostAddressFromString(item.AddrStr)

		if address.Host != item.Host {
			t.Errorf("expected host %s, got %s", item.Host, address.Host)
		}

		if address.Port != item.Port {
			t.Errorf("expected port %s, got %s", item.Port, address.Port)
		}
	}
}

func TestIsWildcardPort(t *testing.T) {
	type AddrData struct {
		AddrStr    string
		isWildcard bool
	}

	items := []AddrData{
		{"127.0.0.1:8080", false},
		{"127.0.0.1", true},
		{"127.0.0.1:*", true},
	}

	for _, item := range items {
		address := CreateVhostAddressFromString(item.AddrStr)

		if address.IsWildcardPort() != item.isWildcard {
			if item.isWildcard {
				t.Error("expected port to be wildcard, got non wildcard")
			} else {
				t.Error("expected port to be non wildcard, got wildcard")
			}
		}
	}
}

func TestGetNomalizedIpv6(t *testing.T) {
	type Ipv6Data struct {
		ipv6Addr, normaliedIpv6 string
	}

	items := []Ipv6Data{
		{"[fd00:dead:beaf::1]:80", "fd00:dead:beaf:0:0:0:0:1"},
		{"[fe80::200:f8ff:fe21:00cf]:80", "fe80:0:0:0:200:f8ff:fe21:cf"},
	}

	for _, item := range items {
		address := CreateVhostAddressFromString(item.ipv6Addr)
		normalizedIpv6 := address.GetNormalizedIpv6()

		if normalizedIpv6 != item.normaliedIpv6 {
			t.Errorf("expected normalized ipv6 %s, got %s", item.normaliedIpv6, normalizedIpv6)
		}
	}
}
