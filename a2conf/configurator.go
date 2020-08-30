package a2conf

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	APACHE_MIN_VERSION = "2.4"
)

// ApacheConfigurator manipulates with apache configs
type ApacheConfigurator struct {
	Parser  *Parser
	ctl     *ApacheCtl
	version string
	vhosts  []string
	options map[string]string
}

// GetVhosts returns configured Apache vhosts
func (ac *ApacheConfigurator) GetVhosts() ([]string, error) {
	if ac.vhosts != nil {
		return ac.vhosts, nil
	}

	ac.vhosts = make([]string, 0)

	for vhostPath := range ac.Parser.Paths {
		paths, err := ac.Parser.Augeas.Match(fmt.Sprintf("/files%s//*[label()=~regexp('VirtualHost', 'i')]", vhostPath))

		if err != nil {
			continue
		}

		for _, path := range paths {
			if strings.Contains(strings.ToLower(path), "virtualhost") {
				continue
			}

			ac.vhosts = append(ac.vhosts, path)
			// vhost, err := ac.createVhost()
		}
	}

	return ac.vhosts, nil
}

//func (ac *ApacheConfigurator) createVhost() (interface{}, error) {
//
//}

// GetDefaults returns ApacheConfiguraor default options
func GetDefaults() map[string]string {
	return map[string]string{
		"SERVER_ROOT": "/etc/apache2",
		"VHOST_ROOT":  "/etc/apache2/sites-available",
		"VHOST_FILES": "*",
		"CTL":         "apache2ctl",
	}
}

// GetApacheConfigurator returns ApacheConfigurator instance
func GetApacheConfigurator(options map[string]string) (*ApacheConfigurator, error) {
	parser, err := createParser(options)

	if err != nil {
		return nil, err
	}

	ctl, err := getApacheCtl(options)

	if err != nil {
		return nil, err
	}

	version, err := getApacheVersion(ctl)

	if err != nil {
		return nil, err
	}

	configurator := ApacheConfigurator{
		Parser:  parser,
		ctl:     ctl,
		options: options,
		version: version,
	}

	return &configurator, nil
}

func getOption(name string, options map[string]string) string {
	if option, ok := options[name]; ok {
		return option
	}

	defaults := GetDefaults()

	if def, ok := defaults[name]; ok {
		return def
	}

	return ""
}

// TODO: Add real functionality
func getApacheVersion(ac *ApacheCtl) (string, error) {
	return "2.4", nil
}

func getApacheCtl(options map[string]string) (*ApacheCtl, error) {
	ctlOption := getOption("CTL", options)

	if ctlOption == "" {
		return nil, fmt.Errorf("apache2ctl command/bin path is not specified")
	}

	return &ApacheCtl{BinPath: ctlOption}, nil
}

func createParser(options map[string]string) (*Parser, error) {
	serverRoot := getOption("SERVER_ROOT", options)
	vhostRoot := getOption("VHOST_ROOT", options)
	parser, err := GetParser(serverRoot, vhostRoot)

	if err != nil {
		return nil, err
	}

	vhostFiles := getOption("VHOST_FILES", options)
	vhostFilesPath := filepath.Join(vhostRoot, vhostFiles)

	if vhostFilesPath != "" {
		if err = parser.ParseFile(vhostFilesPath); err != nil {
			return nil, err
		}
	}

	return parser, nil
}
