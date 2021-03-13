package apache

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Ctl implements functions to work with apachectl cli utility
type Ctl struct {
	BinPath string
}

// ParseIncludes returns Include directives from httpd process and returns a list of their values.
func (a *Ctl) ParseIncludes() ([]string, error) {
	params := []string{"-t", "-D", "DUMP_INCLUDES"}

	return a.parseCmdOutput(params, `\(.*\) (.*)`, 1)
}

// ParseModules returns a map of the defined variables.
func (a *Ctl) ParseModules() ([]string, error) {
	params := []string{"-t", "-D", "DUMP_MODULES"}

	return a.parseCmdOutput(params, `(.*)_module`, 1)
}

// ParseDefines return the list of loaded module names.
func (a *Ctl) ParseDefines() (map[string]string, error) {
	params := []string{"-t", "-D", "DUMP_RUN_CFG"}
	items, err := a.parseCmdOutput(params, `Define: ([^ \n]*)`, 1)

	if err != nil {
		return nil, err
	}

	variables := make(map[string]string)

	for _, item := range items {
		if item == "DUMP_RUN_CFG" {
			continue
		}

		if strings.Count(item, "=") > 1 {
			return nil, fmt.Errorf("error parsing apache runtime variables")
		}

		parts := strings.Split(item, "=")

		if len(parts) == 1 {
			variables[parts[0]] = ""
		} else {
			variables[parts[0]] = parts[1]
		}
	}

	return variables, nil
}

// GetVersion returns apache version
func (a *Ctl) GetVersion() (string, error) {
	params := []string{"-v"}
	result, err := a.parseCmdOutput(params, `(?i)Apache/([0-9\.]*)`, 1)

	if err != nil {
		return "", err
	}

	if len(result) < 1 {
		return "", errors.New("could not detect apache version")
	}

	return result[0], nil
}

// TestConfiguration checks the syntax of apache configuration files
func (a *Ctl) TestConfiguration() error {
	if _, err := a.execCmd([]string{"-t"}); err != nil {
		return fmt.Errorf("invalid apache configuration: %v", err)
	}

	return nil
}

// Restart restarts apache webserver
func (a *Ctl) Restart() error {
	if _, err := a.execCmd([]string{"-k", "restart"}); err != nil {
		return fmt.Errorf("could not restart apache: %v", err)
	}

	return nil
}

func (a *Ctl) parseCmdOutput(params []string, regexpStr string, captureGroup uint) ([]string, error) {
	output, err := a.execCmd(params)

	if err != nil {
		return nil, err
	}

	reg, err := regexp.Compile(regexpStr)

	if err != nil {
		return nil, err
	}

	items := reg.FindAllSubmatch(output, -1)
	var rItems []string

	for _, item := range items {
		rItems = append(rItems, string(item[captureGroup]))
	}

	return rItems, nil
}

func (a *Ctl) execCmd(params []string) ([]byte, error) {
	cmd := exec.Command(a.getCmd(), params...)
	output, err := cmd.Output()

	if err != nil {
		return nil, err
	}

	return output, nil
}

func (a *Ctl) getCmd() string {
	if a.BinPath == "" {
		return "apache2ctl"
	}

	return a.BinPath
}
