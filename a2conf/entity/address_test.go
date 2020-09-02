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
