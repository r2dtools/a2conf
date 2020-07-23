package a2conf

import (
	"fmt"
	"os/exec"
)

// ApacheCtl implements functions to work with apachectl cli utility
type ApacheCtl struct {
	BinPath string
}

// ParseIncludes returns Include directives from httpd process and returns a list of their values.
func (a *ApacheCtl) ParseIncludes() (string, error) {
	params := []string{"-t", "-D", "DUMP_INCLUDES"}

	return a.execCmd(params)
}

func (a *ApacheCtl) execCmd(params []string) (string, error) {
	cmd := exec.Command(a.BinPath, params...)
	output, err := cmd.Output()

	if err != nil {
		return "", fmt.Errorf("could not execute apachectl command: %v", err)
	}

	return string(output), nil
}
