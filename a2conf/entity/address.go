package entity

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Address represents virtual host address
type Address struct {
	IsIpv6 bool
	Host   string
	Port   string
}

// CreateVhostAddressFromString parses address string and returns Address structure
func CreateVhostAddressFromString(addrStr string) Address {
	var host, port string
	// ipv6 addresses starts with
	if strings.HasPrefix(addrStr, "[") {
		lastIndex := strings.LastIndex(addrStr, "]")
		host = addrStr[:lastIndex+1]

		if len(addrStr) > lastIndex+2 && string(addrStr[lastIndex+1]) == ":" {
			port = addrStr[lastIndex+2:]
		}

		return Address{
			Host:   host,
			Port:   port,
			IsIpv6: true,
		}
	}

	parts := strings.Split(addrStr, ":")
	host = parts[0]

	if len(parts) > 1 {
		port = parts[1]
	}

	return Address{
		Host: host,
		Port: port,
	}
}

// IsWildcardPort checks if port is wildcard
func (a *Address) IsWildcardPort() bool {
	return a.Port == "*" || a.Port == ""
}

// GetHash returns addr hash based on host an port
func (a *Address) GetHash() string {
	addr := fmt.Sprintf("%s:%s", a.Host, a.Port)

	return base64.StdEncoding.EncodeToString([]byte(addr))
}
