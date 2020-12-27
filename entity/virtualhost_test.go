package entity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/unknwon/com"
)

func TestGetVhostNames(t *testing.T) {
	type VHostsData struct {
		aliases    []string
		serverName string
		names      []string
	}

	items := []VHostsData{
		{nil, "https://example.com:8880", []string{"example.com"}},
		{[]string{"alias.tld", "alias2.tls"}, "https://example.com:8880", []string{"alias.tld", "alias2.tls", "example.com"}},
		{[]string{"alias.tld", "alias2.tls"}, "", []string{"alias.tld", "alias2.tls"}},
	}

	for _, item := range items {
		vhost := VirtualHost{
			ServerName: item.serverName,
			Aliases:    item.aliases,
		}
		names, err := vhost.GetNames()

		if err != nil {
			t.Errorf("failed to get vhost names: %v", err)
		}

		if len(names) != len(item.names) {
			t.Errorf("names slices are not equal: expected %v, got %v", item.names, names)
		}

		for _, name := range names {
			if !com.IsSliceContainsStr(item.names, name) {
				t.Errorf("invalid vhost name: %s", name)
			}
		}
	}
}

func TestGetConfigName(t *testing.T) {
	type VHostsData struct {
		filePath, configName string
	}

	items := []VHostsData{
		{"/etc/apache2/sites-available/example.com.conf", "example.com.conf"},
	}

	for _, item := range items {
		vhost := VirtualHost{
			FilePath: item.filePath,
		}
		configName := vhost.GetConfigName()
		assert.Equal(t, item.configName, configName)
	}
}
