package configurator

import (
	"strings"

	"github.com/unknwon/com"
)

// IsPortListened checks if port in the list
func IsPortListened(listens []string, port string) bool {
	if com.IsSliceContainsStr(listens, port) {
		return true
	}

	for _, listen := range listens {
		// listen can be 1.1.1.1:443 https
		lParts := strings.Split(listen, ":")

		if len(lParts) > 1 {
			p := strings.Split(lParts[len(lParts)-1], " ")

			if p[0] == port {
				return true
			}
		}
	}

	return false
}

// GetIPFromListen returns IP address from Listen directive statement
func GetIPFromListen(listen string) string {
	rListen := com.Reverse(listen)
	rParts := strings.SplitN(rListen, ":", 2)

	if len(rParts) > 1 {
		return com.Reverse(rParts[1])
	}

	return ""
}
