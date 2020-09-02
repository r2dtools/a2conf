package entity

import (
	"regexp"
)

const (
	stripServerNameRegex = `^(?:.+://)?([^ :$]*)`
)

// VirtualHost represents Apache virtual host data
type VirtualHost struct {
	FilePath,
	ServerName,
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
	var allNames map[string]bool

	for _, alias := range vh.Aliases {
		allNames[alias] = true
	}

	if vh.ServerName != "" {
		re := regexp.MustCompile(stripServerNameRegex)
		matches := re.FindAll([]byte(vh.ServerName), -1)
		allNames[string(matches[0])] = true
	}

	allNamesSlice := make([]string, 0, len(allNames))

	for k := range allNames {
		allNamesSlice = append(allNamesSlice, k)
	}

	return allNamesSlice, nil
}
