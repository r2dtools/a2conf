package entity

import (
	"path/filepath"
	"regexp"
)

const (
	stripServerNameRegex = `^(?:.+:\/\/)?([^ :$]*)`
)

// VirtualHost represents Apache virtual host data
type VirtualHost struct {
	FilePath,
	ServerName,
	DocRoot,
	AugPath string
	Addresses map[string]Address
	Aliases   []string
	Ssl,
	Enabled,
	ModMacro bool
	Ancestor *VirtualHost
}

// GetNames returns all names (servername + aliases) of a virtual host
func (vh *VirtualHost) GetNames() ([]string, error) {
	allNames := make(map[string]bool)

	for _, alias := range vh.Aliases {
		allNames[alias] = true
	}

	if vh.ServerName != "" {
		re := regexp.MustCompile(stripServerNameRegex)
		matches := re.FindStringSubmatch(vh.ServerName)

		if len(matches) > 1 {
			allNames[string(matches[1])] = true
		}
	}

	allNamesSlice := make([]string, 0, len(allNames))

	for k := range allNames {
		allNamesSlice = append(allNamesSlice, k)
	}

	return allNamesSlice, nil
}

// GetConfigName returns config name of a virtual hosr
func (vh *VirtualHost) GetConfigName() string {
	return filepath.Base(vh.FilePath)
}
