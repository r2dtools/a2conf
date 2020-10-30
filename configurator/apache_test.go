package configurator

import "testing"

func TestIsPortListened(t *testing.T) {
	type testData struct {
		port     string
		listened bool
	}

	listens := []string{"80", "1.1.1.1:443", "[2001:db8::a00:20ff:fea7:ccea]:8443"}
	items := []testData{
		{"80", true},
		{"443", true},
		{"8443", true},
		{"8080", false},
	}

	for _, item := range items {
		listened := IsPortListened(listens, item.port)

		if listened != item.listened {
			t.Errorf("expected port %s to listened, but it is not listened", item.port)
		}
	}
}

func TestGetIPFromListen(t *testing.T) {
	type testData struct {
		listen,
		ip string
	}

	items := []testData{
		{"127.0.0.1:80", "127.0.0.1"},
		{"80", ""},
		{"[2001:db8::a00:20ff:fea7:ccea]:80", "[2001:db8::a00:20ff:fea7:ccea]"},
	}

	for _, item := range items {
		ip := GetIPFromListen(item.listen)

		if ip != item.ip {
			t.Errorf("expected ip %s, got %s", item.ip, ip)
		}
	}
}
