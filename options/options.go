package options

const (
	// VhostRoot is apache virtual host root directory
	VhostRoot = "VHOST_ROOT"
	// ServerRoot is apache root directory
	ServerRoot = "SERVER_ROOT"
	// VhostFiles specifies config files for virtual host that will be used. By default all config files are used.
	VhostFiles = "VHOST_FILES"
	// ApacheCtl is a command for apache2ctl execution or a path to apache2ctl bin
	ApacheCtl = "CTL"
	// SslVhostlExt postfix for config files of created SSL virtual hosts
	SslVhostlExt = "SSL_VHOST_EXT"
	// ApacheEnsite is a command for a2ensite command or a pth to a2ensite bin
	ApacheEnsite = "APACHE_ENSITE"
	// ApacheDissite is a command for a2dissite command or a pth to a2dissite bin
	ApacheDissite = "APACHE_DISSITE"
)

// GetOption returns option value
func GetOption(name string, options map[string]string) string {
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
	defaults[ServerRoot] = "/etc/apache2"
	defaults[VhostRoot] = ""
	defaults[VhostFiles] = "*"
	defaults[ApacheCtl] = "apache2ctl"
	defaults[SslVhostlExt] = "-ssl.conf"
	defaults[ApacheEnsite] = "a2ensite"
	defaults[ApacheDissite] = "a2dissite"

	return defaults
}
