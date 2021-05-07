package options

import "strings"

const (
	// VhostRoot is apache virtual host root directory
	VhostRoot = "vhost_root"
	// ServerRoot is apache root directory
	ServerRoot = "server_root"
	// VhostFiles specifies config files for virtual host that will be used. By default all config files are used.
	VhostFiles = "vhost_files"
	// ApacheCtl is a command for apache2ctl execution or a path to apache2ctl bin
	ApacheCtl = "ctl"
	// SslVhostlExt postfix for config files of created SSL virtual hosts
	SslVhostlExt = "ssl_vhost_ext"
	// ApacheEnsite is a command for a2ensite command or a pth to a2ensite bin
	ApacheEnsite = "apache_ensite"
	// ApacheDissite is a command for a2dissite command or a pth to a2dissite bin
	ApacheDissite = "apache_dissite"
)

// GetOption returns option value
func GetOption(name string, options map[string]string) string {
	name = strings.ToLower(name)

	if options == nil {
		options = make(map[string]string)
	}

	if option, ok := options[name]; ok {
		return option
	}

	defaults := GetDefaults()

	if def, ok := defaults[name]; ok {
		return def
	}

	return ""
}

// GetDefaults returns ApacheConfigurator default options
func GetDefaults() map[string]string {
	defaults := make(map[string]string)
	defaults[ServerRoot] = ""
	defaults[VhostRoot] = ""
	defaults[VhostFiles] = "*"
	defaults[ApacheCtl] = ""
	defaults[SslVhostlExt] = "-ssl.conf"
	defaults[ApacheEnsite] = "a2ensite"
	defaults[ApacheDissite] = "a2dissite"

	return defaults
}
