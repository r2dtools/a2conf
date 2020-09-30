package a2conf

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/r2dtools/a2conf/entity"
	"github.com/r2dtools/a2conf/utils"
)

const (
	minApacheVersion = "2.4.0"
)

// ApacheConfigurator manipulates with apache configs
type ApacheConfigurator struct {
	Parser  *Parser
	ctl     *ApacheCtl
	version string
	vhosts  []*entity.VirtualHost
	options map[string]string
}

type vhsotNames struct {
	ServerName    string
	ServerAliases []string
}

// GetVhosts returns configured Apache vhosts
func (ac *ApacheConfigurator) GetVhosts() ([]*entity.VirtualHost, error) {
	if ac.vhosts != nil {
		return ac.vhosts, nil
	}

	filePaths := make(map[string]string)
	internalPaths := make(map[string]map[string]bool)
	var vhosts []*entity.VirtualHost

	for vhostPath := range ac.Parser.Paths {
		paths, err := ac.Parser.Augeas.Match(fmt.Sprintf("/files%s//*[label()=~regexp('VirtualHost', 'i')]", vhostPath))

		if err != nil {
			continue
		}

		for _, path := range paths {
			if !strings.Contains(strings.ToLower(path), "virtualhost") {
				continue
			}

			vhost, err := ac.createVhost(path)

			if err != nil {
				continue
			}

			internalPath := utils.GetFilePathFromAugPath(vhost.AugPath)
			realPath, err := filepath.EvalSymlinks(vhost.FilePath)

			if err != nil {
				// TODO: Should we skip already created vhost in this case?
				continue
			}

			if _, ok := filePaths[realPath]; !ok {
				filePaths[realPath] = vhost.FilePath

				if iPaths, ok := internalPaths[realPath]; !ok {
					internalPaths[realPath] = map[string]bool{
						internalPath: true,
					}
				} else {
					if _, ok = iPaths[internalPath]; !ok {
						iPaths[internalPath] = true
					}
				}

				vhosts = append(vhosts, vhost)
			} else if realPath == vhost.FilePath && realPath != filePaths[realPath] {
				// Prefer "real" vhost paths instead of symlinked ones
				// for example: sites-enabled/vh.conf -> sites-available/vh.conf
				// remove old (most likely) symlinked one
				var nVhosts []*entity.VirtualHost

				for _, vh := range vhosts {
					if vh.FilePath == filePaths[realPath] {
						delete(internalPaths[realPath], utils.GetFilePathFromAugPath(vh.AugPath))
					} else {
						nVhosts = append(nVhosts, vh)
					}
				}

				vhosts = nVhosts
				filePaths[realPath] = realPath
				internalPaths[realPath][internalPath] = true
				vhosts = append(vhosts, vhost)
			} else if _, ok = internalPaths[realPath]; !ok {
				internalPaths[realPath][internalPath] = true
				vhosts = append(vhosts, vhost)
			}
		}
	}

	ac.vhosts = vhosts

	return ac.vhosts, nil
}

func (ac *ApacheConfigurator) createVhost(path string) (*entity.VirtualHost, error) {
	args, err := ac.Parser.Augeas.Match(fmt.Sprintf("%s/arg", path))

	if err != nil {
		return nil, err
	}

	addrs := make(map[string]entity.Address)

	for _, arg := range args {
		arg, err = ac.Parser.GetArg(arg)

		if err != nil {
			return nil, err
		}

		addr := entity.CreateVhostAddressFromString(arg)
		addrs[addr.GetHash()] = addr
	}

	var ssl bool
	sslDirectiveMatches, err := ac.Parser.FindDirective("SslEngine", "on", path, false)

	if err != nil {
		return nil, err
	}

	if len(sslDirectiveMatches) > 0 {
		ssl = true
	}

	for _, addr := range addrs {
		if addr.Port == "443" {
			ssl = true
			break
		}
	}

	fPath, err := ac.Parser.Augeas.Get(fmt.Sprintf("/augeas/files%s/path", utils.GetFilePathFromAugPath(path)))

	if err != nil {
		return nil, err
	}

	filename := utils.GetFilePathFromAugPath(fPath)

	if filename == "" {
		return nil, nil
	}

	var macro bool

	if strings.Index(strings.ToLower(path), "/macro/") != -1 {
		macro = true
	}

	vhostEnabled := ac.Parser.IsFilenameExistInOriginalPaths(filename)
	virtualhost := entity.VirtualHost{
		FilePath:  filename,
		AugPath:   path,
		Ssl:       ssl,
		ModMacro:  macro,
		Enabled:   vhostEnabled,
		Addresses: addrs,
	}
	ac.addServerNames(&virtualhost)

	return &virtualhost, err
}

func (ac *ApacheConfigurator) addServerNames(vhost *entity.VirtualHost) error {
	vhostNames, err := ac.getVhostNames(vhost.AugPath)

	if err != nil {
		return err
	}

	for _, alias := range vhostNames.ServerAliases {
		if !vhost.ModMacro {
			vhost.Aliases = append(vhost.Aliases, alias)
		}
	}

	if !vhost.ModMacro {
		vhost.ServerName = vhostNames.ServerName
	}

	return nil
}

func (ac *ApacheConfigurator) getVhostNames(path string) (*vhsotNames, error) {
	serverNameMatch, err := ac.Parser.FindDirective("ServerName", "", path, false)

	if err != nil {
		return nil, err
	}

	serverAliasMatch, err := ac.Parser.FindDirective("ServerAlias", "", path, false)

	if err != nil {
		return nil, err
	}

	var serverAliases []string
	var serverName string

	for _, alias := range serverAliasMatch {
		serverAlias, err := ac.Parser.GetArg(alias)

		if err != nil {
			return nil, err // TODO: may be it is better just to continue ...
		}

		serverAliases = append(serverAliases, serverAlias)
	}

	if len(serverNameMatch) > 0 {
		serverName, err = ac.Parser.GetArg(serverNameMatch[len(serverNameMatch)-1])

		if err != nil {
			return nil, err
		}
	}

	return &vhsotNames{serverName, serverAliases}, nil
}

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
	ctl, err := getApacheCtl(options)

	if err != nil {
		return nil, err
	}

	version, err := ctl.GetVersion()

	if err != nil {
		return nil, err
	}

	isVersionSupported, err := checkApacheMinVersion(version, minApacheVersion)

	if err != nil {
		return nil, err
	}

	if !isVersionSupported {
		return nil, fmt.Errorf("current apache version '%s' is not supported. Minimal supported version is '%s'", version, minApacheVersion)
	}

	parser, err := createParser(ctl, version, options)

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

func getApacheCtl(options map[string]string) (*ApacheCtl, error) {
	ctlOption := getOption("CTL", options)

	if ctlOption == "" {
		return nil, fmt.Errorf("apache2ctl command/bin path is not specified")
	}

	return &ApacheCtl{BinPath: ctlOption}, nil
}

func createParser(apachectl *ApacheCtl, version string, options map[string]string) (*Parser, error) {
	serverRoot := getOption("SERVER_ROOT", options)
	vhostRoot := getOption("VHOST_ROOT", options)
	parser, err := GetParser(apachectl, version, serverRoot, vhostRoot)

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

func checkApacheMinVersion(version, minVersion string) (bool, error) {
	c, err := semver.NewConstraint(">=" + minVersion)

	if err != nil {
		return false, err
	}

	v, err := semver.NewVersion(version)

	if err != nil {
		return false, err
	}

	return c.Check(v), nil
}
