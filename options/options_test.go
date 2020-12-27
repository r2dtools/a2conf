package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetOption(t *testing.T) {
	defaults := GetDefaults()
	assert.Equal(t, defaults[ServerRoot], GetOption(ServerRoot, nil))
	assert.Equal(t, "/server/root", GetOption(ServerRoot, map[string]string{ServerRoot: "/server/root"}))
}
