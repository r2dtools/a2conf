package apache

import (
	"fmt"
	"os/exec"

	opts "github.com/r2dtools/a2conf/options"
	"github.com/r2dtools/a2conf/utils"
)

// Site implements functionality for site enabling/disabling
type Site struct {
	DissiteBin, EnsiteBin string
}

// Enable enables site via a2ensite utility
func (s *Site) Enable(siteConfigName string) error {
	if !utils.IsCommandExist("a2ensite") {
		return fmt.Errorf("could not enable site '%s': a2ensite utility is not available", siteConfigName)
	}

	_, err := s.execCmd(s.getEnsiteCmd(), []string{siteConfigName})

	if err != nil {
		return fmt.Errorf("could not enable site '%s': %v", siteConfigName, err)
	}

	return nil
}

// Disable disables site via a2dissite utility
func (s *Site) Disable(siteConfigName string) error {
	if !utils.IsCommandExist("a2dissite") {
		return fmt.Errorf("could not disable site '%s': a2dissite utility is not available", siteConfigName)
	}

	_, err := s.execCmd(s.getDissiteCmd(), []string{siteConfigName})

	if err != nil {
		return fmt.Errorf("could not disable site '%s': %v", siteConfigName, err)
	}

	return nil
}

func (s *Site) execCmd(command string, params []string) ([]byte, error) {
	cmd := exec.Command(command, params...)
	output, err := cmd.Output()

	if err != nil {
		return nil, fmt.Errorf("could not execute '%s' command: %v", command, err)
	}

	return output, nil
}

func (s *Site) getEnsiteCmd() string {
	if s.EnsiteBin == "" {
		return "a2ensite"
	}

	return s.EnsiteBin
}

func (s *Site) getDissiteCmd() string {
	if s.DissiteBin == "" {
		return "a2dissite"
	}

	return s.DissiteBin
}

// GetApacheSite returns Site structure instance
func GetApacheSite(options map[string]string) *Site {
	ensiteBin := opts.GetOption(opts.ApacheEnsite, options)
	dissiteBin := opts.GetOption(opts.ApacheDissite, options)

	return &Site{EnsiteBin: ensiteBin, DissiteBin: dissiteBin}
}
