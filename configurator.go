package a2conf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/r2dtools/a2conf/configurator"
	"github.com/r2dtools/a2conf/entity"
	"github.com/r2dtools/a2conf/utils"
	"github.com/unknwon/com"
)

const (
	minApacheVersion = "2.4.0"
	vhostRoot        = "VHOST_ROOT"
	serverRoot       = "SERVER_ROOT"
	vhostFiles       = "VHOST_FILES"
	apacheCtl        = "CTL"
	sslVhostlExt     = "SSL_VHOST_EXT"
)

// ApacheConfigurator manipulates with apache configs
type ApacheConfigurator struct {
	Parser         *Parser
	reverter       *Reverter
	ctl            *ApacheCtl
	version        string
	vhosts         []*entity.VirtualHost
	suitableVhosts map[string]*entity.VirtualHost
	options        map[string]string
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

			internalPath := utils.GetInternalAugPath(vhost.AugPath)
			realPath, err := filepath.EvalSymlinks(vhost.FilePath)

			if _, ok := internalPaths[realPath]; !ok {
				internalPaths[realPath] = make(map[string]bool)
			}

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

			} else if _, ok = internalPaths[realPath][internalPath]; !ok {
				internalPaths[realPath][internalPath] = true
				vhosts = append(vhosts, vhost)
			}
		}
	}

	ac.vhosts = vhosts

	return ac.vhosts, nil
}

// Save saves all changes
func (ac *ApacheConfigurator) Save() error {
	err := ac.Parser.Save(ac.reverter)

	if err != nil {
		return fmt.Errorf("could not save changes: %v", err)
	}

	return nil
}

// DeployCertificate installs certificate to a domain
func (ac *ApacheConfigurator) DeployCertificate(serverName, certPath, certKeyPath, chainPath, fullChainPath string) error {
	var err error
	var vhost *entity.VirtualHost

	if vhost, err = ac.GetSuitableVhost(serverName, true); err != nil {
		return err
	}

	if err = ac.PrepareServerForHTTPS("443", false); err != nil {
		return err
	}

	if _, ok := ac.Parser.Modules["ssl_module"]; !ok {
		return errors.New("could not find ssl_module")
	}

	if err = ac.addDummySSLDirectives(vhost.AugPath); err != nil {
		return err
	}

	if err = ac.cleanSSLVhost(vhost); err != nil {
		return err
	}

	augCertPath, err := ac.Parser.FindDirective("SSLCertificateFile", "", vhost.AugPath, true)
	if err != nil {
		return fmt.Errorf("error while searching directive 'SSLCertificateFile': %v", err)
	}

	augCertKeyPath, err := ac.Parser.FindDirective("SSLCertificateKeyFile", "", vhost.AugPath, true)
	if err != nil {
		return fmt.Errorf("error while searching directive 'SSLCertificateKeyFile': %v", err)
	}

	res, err := utils.CheckMinVersion(ac.version, "2.4.8")
	if err != nil {
		return err
	}

	if !res || (chainPath != "" && fullChainPath == "") {
		if err = ac.Parser.Augeas.Set(augCertPath[len(augCertPath)-1], certPath); err != nil {
			return fmt.Errorf("could not set certificate path for vhost '%s': %v", serverName, err)
		}
		if err = ac.Parser.Augeas.Set(augCertKeyPath[len(augCertKeyPath)-1], certKeyPath); err != nil {
			return fmt.Errorf("could not set certificate key path for vhost '%s': %v", serverName, err)
		}

		if chainPath != "" {
			if err = ac.Parser.AddDirective(vhost.AugPath, "SSLCertificateChainFile", []string{chainPath}); err != nil {
				return fmt.Errorf("could not add 'SSLCertificateChainFile' directive to vhost '%s': %v", serverName, err)
			}
		} else {
			return fmt.Errorf("SSL certificate chain path is required for the current Apache version '%s', but is not specified", ac.version)
		}
	} else {
		if fullChainPath == "" {
			return errors.New("SSL certificate fullchain path is required, but is not specified")
		}

		if err = ac.Parser.Augeas.Set(augCertPath[len(augCertPath)-1], fullChainPath); err != nil {
			return fmt.Errorf("could not set certificate path for vhost '%s': %v", serverName, err)
		}
		if err = ac.Parser.Augeas.Set(augCertKeyPath[len(augCertKeyPath)-1], certKeyPath); err != nil {
			return fmt.Errorf("could not set certificate key path for vhost '%s': %v", serverName, err)
		}
	}

	if !vhost.Enabled {
		if err = ac.EnableSite(vhost); err != nil {
			return err
		}
	}

	return nil
}

// EnableSite enables an available site
func (ac *ApacheConfigurator) EnableSite(vhost *entity.VirtualHost) error {
	if vhost.Enabled {
		return nil
	}

	if !ac.Parser.IsFilenameExistInOriginalPaths(vhost.FilePath) {
		if err := ac.Parser.AddInclude(ac.Parser.ConfigRoot, vhost.FilePath); err != nil {
			return fmt.Errorf("could not enable vhsot '%s': %v", vhost.FilePath, err)
		}

		vhost.Enabled = true
	}

	return nil
}

// PrepareServerForHTTPS prepares server for https
func (ac *ApacheConfigurator) PrepareServerForHTTPS(port string, temp bool) error {
	if err := ac.PrepareHTTPSModules(temp); err != nil {
		return err
	}

	if err := ac.EnsurePortIsListening(port, true); err != nil {
		return err
	}

	return nil
}

// PrepareHTTPSModules enables modules required for https
func (ac *ApacheConfigurator) PrepareHTTPSModules(temp bool) error {
	if _, ok := ac.Parser.Modules["ssl_module"]; ok {
		return nil
	}

	if err := ac.EnableModule("ssl", temp); err != nil {
		return err
	}

	// save all changes before
	if err := ac.Save(); err != nil {
		return err
	}

	if err := ac.Parser.Augeas.Load(); err != nil {
		return err
	}

	ac.Parser.ResetModules()

	return nil
}

// EnableModule enables apache module
func (ac *ApacheConfigurator) EnableModule(module string, temp bool) error {
	return fmt.Errorf("apache needs to have module %s active. please install the module manually", module)
}

// EnsurePortIsListening ensures that the provided port is listening
func (ac *ApacheConfigurator) EnsurePortIsListening(port string, https bool) error {
	var portService string
	var listens []string
	var listenDirs []string

	if https && port != "443" {
		// https://httpd.apache.org/docs/2.4/bind.html
		// Listen 192.170.2.1:8443 https
		// running an https site on port 8443 (if protocol is not specified than 443 is used by default for https)
		portService = fmt.Sprintf("%s %s", port, "https")
	} else {
		portService = port
	}

	listenMatches, err := ac.Parser.FindDirective("Listen", "", "", true)

	if err != nil {
		return err
	}

	for _, lMatch := range listenMatches {
		listen, err := ac.Parser.GetArg(lMatch)

		if err != nil {
			return err
		}

		// listenDirs contains only unique items
		listenDirs = com.AppendStr(listenDirs, listen)
		listens = append(listens, listen)
	}

	if configurator.IsPortListened(listens, port) {
		return nil
	}

	if len(listens) == 0 {
		listenDirs = append(listenDirs, portService)
	}

	for _, listen := range listens {
		lParts := strings.Split(listen, ":")

		// only port is specified -> all interfaces are listened
		if len(lParts) == 1 {
			if !com.IsSliceContainsStr(listenDirs, port) && !com.IsSliceContainsStr(listenDirs, portService) {
				listenDirs = com.AppendStr(listenDirs, portService)
			}
		} else {
			lDir := fmt.Sprintf("%s:%s", configurator.GetIPFromListen(listen), portService)
			listenDirs = com.AppendStr(listenDirs, lDir)
		}
	}

	if https {
		err = ac.addListensForHTTPS(listenDirs, listens, port)
	} else {
		err = ac.addListensForHTTP(listenDirs, listens, port)
	}

	if err != nil {
		return err
	}

	return nil
}

func (ac *ApacheConfigurator) addDummySSLDirectives(vhPath string) error {
	if err := ac.Parser.AddDirective(vhPath, "SSLEngine", []string{"on"}); err != nil {
		return fmt.Errorf("could not add 'SSLEngine' directive to vhost %s: %v", vhPath, err)
	}

	if err := ac.Parser.AddDirective(vhPath, "SSLCertificateFile", []string{"insert_cert_file_path"}); err != nil {
		return fmt.Errorf("could not add 'SSLCertificateFile' directive to vhost %s: %v", vhPath, err)
	}

	if err := ac.Parser.AddDirective(vhPath, "SSLCertificateKeyFile", []string{"insert_key_file_path"}); err != nil {
		return fmt.Errorf("could not add 'SSLCertificateKeyFile' directive to vhost %s: %v", vhPath, err)
	}

	return nil
}

func (ac *ApacheConfigurator) cleanSSLVhost(vhost *entity.VirtualHost) error {
	if err := ac.deduplicateDirectives(vhost.AugPath, []string{"SSLCertificateFile", "SSLCertificateKeyFile"}); err != nil {
		return err
	}

	if err := ac.removeDirectives(vhost.AugPath, []string{"SSLCertificateChainFile"}); err != nil {
		return err
	}

	return nil
}

func (ac *ApacheConfigurator) deduplicateDirectives(vhPath string, directives []string) error {
	for _, directive := range directives {
		directivePaths, err := ac.Parser.FindDirective(directive, "", vhPath, false)

		if err != nil {
			return err
		}

		reg := regexp.MustCompile(`/\w*$`)

		if len(directivePaths) > 1 {
			dps := directivePaths[:len(directivePaths)-1]
			for _, dp := range dps {
				ac.Parser.Augeas.Remove(reg.ReplaceAllString(dp, ""))
			}
		}
	}

	return nil
}

func (ac *ApacheConfigurator) removeDirectives(vhPath string, directives []string) error {
	for _, directive := range directives {
		directivePaths, err := ac.Parser.FindDirective(directive, "", vhPath, false)

		if err != nil {
			return err
		}

		reg := regexp.MustCompile(`/\w*$`)

		for _, directivePath := range directivePaths {
			ac.Parser.Augeas.Remove(reg.ReplaceAllString(directivePath, ""))
		}
	}

	return nil
}

func (ac *ApacheConfigurator) addListensForHTTP(listens []string, listensOrigin []string, port string) error {
	newListens := utils.StrSlicesDifference(listens, listensOrigin)
	augListenPath := GetAugPath(ac.Parser.СonfigListen)

	if com.IsSliceContainsStr(newListens, port) {
		if err := ac.Parser.AddDirective(augListenPath, "Listen", []string{port}); err != nil {
			return fmt.Errorf("could not add port %s to listen config: %v", port, err)
		}
	} else {
		for _, listen := range listens {
			if err := ac.Parser.AddDirective(augListenPath, "Listen", strings.Split(listen, " ")); err != nil {
				return fmt.Errorf("could not add port %s to listen config: %v", port, err)
			}
		}
	}

	return nil
}

func (ac *ApacheConfigurator) addListensForHTTPS(listens []string, listensOrigin []string, port string) error {
	var portService string
	augListenPath := GetAugPath(ac.Parser.СonfigListen)
	newListens := utils.StrSlicesDifference(listens, listensOrigin)

	if port != "443" {
		portService = fmt.Sprintf("%s %s", port, "https")
	} else {
		portService = port
	}

	if com.IsSliceContainsStr(newListens, port) || com.IsSliceContainsStr(newListens, portService) {
		if err := ac.Parser.AddDirectiveToIfModSSL(augListenPath, "Listen", strings.Split(portService, " ")); err != nil {
			return fmt.Errorf("could not add port %s to listen config: %v", port, err)
		}
	} else {
		for _, listen := range listens {
			if err := ac.Parser.AddDirectiveToIfModSSL(augListenPath, "Listen", strings.Split(listen, " ")); err != nil {
				return fmt.Errorf("could not add port %s to listen config: %v", port, err)
			}
		}
	}

	return nil
}

// GetSuitableVhost returns suitable virtual hosts for provided serverName.
// If createIfNoSsl is true then ssl part will be created if neccessary.
func (ac *ApacheConfigurator) GetSuitableVhost(serverName string, createIfNoSsl bool) (*entity.VirtualHost, error) {
	if vhost, ok := ac.suitableVhosts[serverName]; ok {
		return vhost, nil
	}

	vhost, err := ac.FindSuitableVhost(serverName, createIfNoSsl)

	if err != nil {
		return nil, err
	}

	if vhost == nil {
		return nil, fmt.Errorf("could not find suitable virtual host with ServerName: %s", serverName)
	}

	if !createIfNoSsl {
		return vhost, nil
	}

	if !vhost.Ssl {
		serverName := vhost.ServerName
		vhost, err = ac.MakeVhostSsl(vhost)

		if err != nil {
			return nil, fmt.Errorf("could not create ssl virtual host for '%s': %v", serverName, err)
		}
	}

	ac.suitableVhosts[serverName] = vhost

	return vhost, nil
}

// FindSuitableVhost tries to find a suitable virtual host for provided serverName.
func (ac *ApacheConfigurator) FindSuitableVhost(serverName string, createIfNoSsl bool) (*entity.VirtualHost, error) {
	vhosts, err := ac.GetVhosts()

	if err != nil {
		return nil, err
	}

	var suitableVhost *entity.VirtualHost

	for _, vhost := range vhosts {
		if vhost.ModMacro {
			continue
		}

		// Prefer virtual host with ssl
		if vhost.ServerName == serverName && vhost.Ssl {
			return vhost, nil
		}

		if vhost.ServerName == serverName {
			suitableVhost = vhost
		}
	}

	return suitableVhost, nil
}

// MakeVhostSsl makes an ssl virtual host version of a nonssl virtual host
func (ac *ApacheConfigurator) MakeVhostSsl(noSslVhost *entity.VirtualHost) (*entity.VirtualHost, error) {
	noSslFilePath := noSslVhost.FilePath
	sslFilePath, err := ac.getSslVhostFilePath(noSslFilePath)

	if err != nil {
		return nil, fmt.Errorf("could not get config file path for ssl virtual host: %v", err)
	}

	originMatches, err := ac.Parser.Augeas.Match(fmt.Sprintf("/files%s//*[label()=~regexp('VirtualHost', 'i')]", escape(sslFilePath)))

	if err != nil {
		return nil, err
	}

	err = ac.copyCreateSslVhostSkeleton(noSslVhost, sslFilePath)

	if err != nil {
		return nil, fmt.Errorf("could not create config for ssl virtual host: %v", err)
	}

	ac.Parser.Augeas.Load()
	newMatches, err := ac.Parser.Augeas.Match(fmt.Sprintf("/files%s//*[label()=~regexp('VirtualHost', 'i')]", escape(sslFilePath)))

	if err != nil {
		return nil, err
	}

	sslVhostPath := getNewVhostPathFromAugesMatches(originMatches, newMatches)

	if sslVhostPath == "" {
		newMatches, err = ac.Parser.Augeas.Match(fmt.Sprintf("/files%s//*[label()=~regexp('VirtualHost', 'i')]", escape(sslFilePath)))

		if err != nil {
			return nil, err
		}

		sslVhostPath = getNewVhostPathFromAugesMatches(originMatches, newMatches)

		if sslVhostPath == "" {
			return nil, errors.New("could not reverse map the HTTPS VirtualHost to the original")
		}
	}

	ac.updateSslVhostAddresses(sslVhostPath)
	err = ac.Save()

	if err != nil {
		return nil, err
	}

	sslVhost, err := ac.createVhost(sslVhostPath)

	if err != nil {
		return nil, err
	}

	sslVhost.Ancestor = noSslVhost
	ac.vhosts = append(ac.vhosts, sslVhost)

	return sslVhost, nil
}

func (ac *ApacheConfigurator) copyCreateSslVhostSkeleton(noSslVhost *entity.VirtualHost, sslVhostFilePath string) error {
	_, err := os.Stat(sslVhostFilePath)

	if os.IsNotExist(err) {
		ac.reverter.AddFileToDeletion(sslVhostFilePath)
	} else if err == nil {
		ac.reverter.BackupFile(sslVhostFilePath)
	} else {
		return err
	}

	noSslVhostContents, err := ac.getVhostBlockContent(noSslVhost)

	if err != nil {
		return err
	}

	sslVhostContent, _ := disableDangerousForSslRewriteRules(noSslVhostContents)
	sslVhostFile, err := os.OpenFile(sslVhostFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)

	if err != nil {
		return err
	}

	defer sslVhostFile.Close()
	sslContent := []string{
		"<IfModule mod_ssl.c>\n",
		strings.Join(sslVhostContent, "\n"),
		"</VirtualHost>\n",
		"</IfModule>\n",
	}

	for _, line := range sslContent {
		_, err = sslVhostFile.WriteString(line)

		if err != nil {
			return fmt.Errorf("could not write to ssl virtual host file '%s': %v", sslVhostFilePath, err)
		}
	}

	if !ac.Parser.IsFilenameExistInCurrentPaths(sslVhostFilePath) {
		err = ac.Parser.ParseFile(sslVhostFilePath)

		if err != nil {
			return fmt.Errorf("could not parse ssl virtual host file '%s': %v", sslVhostFilePath, err)
		}
	}

	ac.Parser.Augeas.Set(fmt.Sprintf("/augeas/files%s/mtime", escape(sslVhostFilePath)), "0")
	ac.Parser.Augeas.Set(fmt.Sprintf("/augeas/files%s/mtime", escape(noSslVhost.FilePath)), "0")

	return nil
}

func (ac *ApacheConfigurator) getVhostBlockContent(vhost *entity.VirtualHost) ([]string, error) {
	span, err := ac.Parser.Augeas.Span(vhost.AugPath)

	if err != nil {
		return nil, fmt.Errorf("could not get VirtualHost '%s' from the file %s: %v", vhost.ServerName, vhost.FilePath, err)
	}

	file, err := os.Open(span.Filename)

	if err != nil {
		return nil, err
	}

	defer file.Close()
	_, err = file.Seek(int64(span.SpanStart), 0)

	if err != nil {
		return nil, err
	}

	bContent := make([]byte, span.SpanEnd-span.SpanStart)
	_, err = file.Read(bContent)

	if err != nil {
		return nil, err
	}

	content := string(bContent)
	lines := strings.Split(content, "\n")
	removeClosingVhostTag(lines)

	return lines, nil
}

func (ac *ApacheConfigurator) getSslVhostFilePath(noSslVhostFilePath string) (string, error) {
	vhostRoot := getOption(vhostRoot, ac.options)
	var filePath string
	var err error

	if vhostRoot != "" {
		_, err = os.Stat(vhostRoot)

		if err == nil {
			eVhostRoot, err := filepath.EvalSymlinks(vhostRoot)

			if err != nil {
				return "", err
			}

			filePath = filepath.Join(eVhostRoot, filepath.Base(noSslVhostFilePath))
		}
	} else {
		filePath, err = filepath.EvalSymlinks(noSslVhostFilePath)

		if err != nil {
			return "", err
		}
	}

	sslVhostExt := getOption(sslVhostlExt, ac.options)

	if strings.HasSuffix(filePath, ".conf") {
		return filePath[:len(filePath)-len("conf.")] + sslVhostExt, nil
	}

	return filePath + sslVhostExt, nil
}

func (ac *ApacheConfigurator) updateSslVhostAddresses(sslVhostPath string) ([]*entity.Address, error) {
	var sslAddresses []*entity.Address
	sslAddrMatches, err := ac.Parser.Augeas.Match(sslVhostPath + "/arg")

	if err != nil {
		return nil, err
	}

	for _, sslAddrMatch := range sslAddrMatches {
		addrString, err := ac.Parser.GetArg(sslAddrMatch)

		if err != nil {
			return nil, err
		}

		oldAddress := entity.CreateVhostAddressFromString(addrString)
		sslAddress := oldAddress.GetAddressWithNewPort("443") // TODO: it should be passed in an external code
		err = ac.Parser.Augeas.Set(sslAddrMatch, sslAddress.ToString())

		if err != nil {
			return nil, err
		}

		var exists bool

		for _, addr := range sslAddresses {
			if sslAddress.IsEqual(addr) {
				exists = true
				break
			}
		}

		if !exists {
			sslAddresses = append(sslAddresses, sslAddress)
		}
	}

	return sslAddresses, nil
}

func (ac *ApacheConfigurator) isWildcard(serverName string) bool {
	return strings.HasPrefix(serverName, "*.")
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
	docRoot, err := ac.getDocumentRoot(path)

	if err != nil {
		return nil, err
	}

	virtualhost := entity.VirtualHost{
		FilePath:  filename,
		AugPath:   path,
		DocRoot:   docRoot,
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
		return nil, fmt.Errorf("failed searching ServerName directive: %v", err)
	}

	serverAliasMatch, err := ac.Parser.FindDirective("ServerAlias", "", path, false)

	if err != nil {
		return nil, fmt.Errorf("failed searching ServerAlias directive: %v", err)
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

func (ac *ApacheConfigurator) getDocumentRoot(path string) (string, error) {
	var docRoot string
	docRootMatch, err := ac.Parser.FindDirective("DocumentRoot", "", path, false)

	if err != nil {
		return "", fmt.Errorf("could not get vhost document root: %v", err)
	}

	if len(docRootMatch) > 0 {
		docRoot, err = ac.Parser.GetArg(docRootMatch[len(docRootMatch)-1])

		if err != nil {
			return "", fmt.Errorf("could not get vhost document root: %v", err)
		}

		//  If the directory-path is not absolute then it is assumed to be relative to the ServerRoot.
		if !strings.HasPrefix(docRoot, string(filepath.Separator)) {
			docRoot = filepath.Join(ac.Parser.ServerRoot, docRoot)
		}
	}

	return docRoot, nil
}

// GetDefaults returns ApacheConfigurator default options
func GetDefaults() map[string]string {
	defaults := make(map[string]string)
	defaults[serverRoot] = "/etc/apache2"
	defaults[vhostRoot] = ""
	defaults[vhostFiles] = "*"
	defaults[apacheCtl] = "apache2ctl"
	defaults[sslVhostlExt] = "-ssl.conf"

	return defaults
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

	isVersionSupported, err := utils.CheckMinVersion(version, minApacheVersion)

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
		Parser:         parser,
		reverter:       &Reverter{},
		ctl:            ctl,
		options:        options,
		version:        version,
		suitableVhosts: make(map[string]*entity.VirtualHost),
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
	serverRoot := getOption(serverRoot, options)
	vhostRoot := getOption(vhostRoot, options)
	parser, err := GetParser(apachectl, version, serverRoot, vhostRoot)

	if err != nil {
		return nil, err
	}

	vhostFiles := getOption(vhostFiles, options)

	if vhostRoot != "" && vhostFiles != "" {
		vhostFilesPath := filepath.Join(vhostRoot, vhostFiles)

		if err = parser.ParseFile(vhostFilesPath); err != nil {
			return nil, err
		}
	}

	return parser, nil
}

// removeClosingVhostTag removes closing tag </virtualhost> for the virtualhost block
func removeClosingVhostTag(lines []string) {
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		tagIndex := strings.Index(strings.ToLower(line), "</virtualhost>")

		if tagIndex != -1 {
			lines[i] = line[:tagIndex]
			break
		}
	}
}

func disableDangerousForSslRewriteRules(content []string) ([]string, bool) {
	var result []string
	var skipped bool
	linesCount := len(content)

	for i := 0; i < linesCount; i++ {
		line := content[i]
		isRewriteCondition := strings.HasPrefix(strings.TrimSpace(strings.ToLower(line)), "rewritecond")
		isRewriteRule := strings.HasPrefix(strings.TrimSpace(strings.ToLower(line)), "rewriterule")

		if !isRewriteRule && !isRewriteCondition {
			result = append(result, line)
			continue
		}

		isRewriteRuleDangerous := isRewriteRuleDangerousForSsl(line)

		if isRewriteRule && !isRewriteRuleDangerous {
			result = append(result, line)
			continue
		} else if isRewriteRule && isRewriteRuleDangerous {
			skipped = true

			result = append(result, "# "+line)
		}

		if isRewriteCondition {
			var chunk []string

			chunk = append(chunk, line)
			j := i + 1

			for ; j < linesCount; j++ {
				isRewriteRuleNextLine := strings.HasPrefix(strings.TrimSpace(strings.ToLower(content[j])), "rewriterule")

				if isRewriteRuleNextLine {
					break
				}

				chunk = append(chunk, content[j])
			}

			i = j
			chunk = append(chunk, content[j])

			if isRewriteRuleDangerousForSsl(content[j]) {
				skipped = true

				for _, l := range chunk {
					result = append(result, "# "+l)
				}
			} else {
				result = append(result, strings.Join(chunk, "\n"))
			}
		}
	}

	return result, skipped
}

// isRewriteRuleDangerousForSsl checks if provided rewrite rule potentially can not be used for the virtual host with ssl
// e.g:
// RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [L,QSA,R=permanent]
// Copying the above line to the ssl vhost would cause a
// redirection loop.
func isRewriteRuleDangerousForSsl(line string) bool {
	line = strings.TrimSpace(strings.ToLower(line))

	if !strings.HasPrefix(line, "rewriterule") {
		return false
	}

	// According to: https://httpd.apache.org/docs/2.4/rewrite/flags.html
	// The syntax of a RewriteRule is:
	// RewriteRule pattern target [Flag1,Flag2,Flag3]
	// i.e. target is required, so it must exist.
	parts := strings.Split(line, " ")

	if len(parts) < 3 {
		return false
	}

	target := strings.TrimSpace(parts[2])
	target = strings.Trim(target, "'\"")

	return strings.HasPrefix(target, "https://")
}

func escape(filePath string) string {
	filePath = strings.Replace(filePath, ",", "\\,", -1)
	filePath = strings.Replace(filePath, "[", "\\[", -1)
	filePath = strings.Replace(filePath, "]", "\\]", -1)
	filePath = strings.Replace(filePath, "|", "\\|", -1)
	filePath = strings.Replace(filePath, "=", "\\=", -1)
	filePath = strings.Replace(filePath, "(", "\\(", -1)
	filePath = strings.Replace(filePath, ")", "\\)", -1)
	filePath = strings.Replace(filePath, "!", "\\!", -1)

	return filePath
}

func getNewVhostPathFromAugesMatches(originMatches []string, newMatches []string) string {
	var mOriginMatches []string

	for _, originMatch := range originMatches {
		mOriginMatches = append(mOriginMatches, strings.Replace(originMatch, "[1]", "", -1))
	}

	for _, newMatch := range newMatches {
		mNewMatch := strings.Replace(newMatch, "[1]", "", -1)

		if !com.IsSliceContainsStr(mOriginMatches, mNewMatch) {
			return newMatch
		}
	}

	return ""
}
