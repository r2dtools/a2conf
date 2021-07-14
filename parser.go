package a2conf

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/huandu/xstrings"
	"github.com/r2dtools/a2conf/apache"
	"github.com/r2dtools/a2conf/utils"
	"github.com/unknwon/com"
	"honnef.co/go/augeas"
)

const (
	argVarRegex = `\$\{[^ \}]*}`
)

var fnMatchChars = []string{"*", "?", "\\", "[", "]"}
var serverRootPaths = []string{"/etc/httpd", "/etc/apache2"}

// Parser ia a wrapper under the augeas to work with httpd config
type Parser struct {
	Augeas          augeas.Augeas
	ApacheCtl       *apache.Ctl
	ServerRoot      string
	VHostRoot       string
	ConfigRoot      string
	СonfigListen    string
	version         string
	beforeDomReload func(unsavedFiles []string)
	Paths           map[string][]string
	existingPaths   map[string][]string
	variables       map[string]string
	Modules         map[string]bool
}

type directiveFilter struct {
	Name  string
	Value []string
}

// GetParser creates parser instance
func GetParser(apachectl *apache.Ctl, version, serverRoot, vhostRoot string) (*Parser, error) {
	serverRoot, err := getServerRootPath(serverRoot)

	if err != nil {
		return nil, err
	}

	if vhostRoot != "" {
		vhostRoot, err = filepath.Abs(vhostRoot)
		if err != nil {
			return nil, err
		}
	}

	if err != nil {
		return nil, err
	}

	aug, err := augeas.New("/", "", augeas.NoLoad|augeas.NoModlAutoload|augeas.EnableSpan)

	if err != nil {
		return nil, err
	}

	parser := &Parser{
		Augeas:     aug,
		ApacheCtl:  apachectl,
		ServerRoot: serverRoot,
		VHostRoot:  vhostRoot,
		version:    version,
	}

	if err = parser.setLocations(); err != nil {
		parser.Close()

		return nil, err
	}

	if err = parser.ParseFile(parser.ConfigRoot); err != nil {
		parser.Close()

		return nil, fmt.Errorf("could not parse apache config: %v", err)
	}

	if err = parser.UpdateRuntimeVariables(); err != nil {
		return nil, err
	}

	// try to detect apache root config file path (ex. /etc/apache2/apache2.conf), ports.conf file path
	if err = parser.setLocations(); err != nil {
		parser.Close()
		return nil, err
	}

	if parser.existingPaths == nil {
		parser.existingPaths = make(map[string][]string)
	}

	// list of the active include paths, before modifications
	for k, v := range parser.Paths {
		dst := make([]string, len(v))
		copy(dst, v)
		parser.existingPaths[k] = dst
	}

	return parser, nil
}

// Close closes the Parser instance and frees any storage associated with it.
func (p *Parser) Close() {
	if p != nil {
		p.Augeas.Close()
	}
}

// SetBeforeDomReloadCallback sets callback that will be executed before augeas dom load/reload
// It can be used to makes sure that all Augeas dom changes are written to files to avoid
// loss of configuration directives when doing additional augeas parsing,
// causing a possible augeas.load() resulting dom reset
func (p *Parser) SetBeforeDomReloadCallback(callback func(unsavedFiles []string)) {
	p.beforeDomReload = callback
}

// setConfigRoot detects apache root config file
func (p *Parser) setConfigRoot() error {
	configs := []string{"apache2.conf", "httpd.conf", "conf/httpd.conf"}

	for _, config := range configs {
		configRootPath := path.Join(p.ServerRoot, config)
		_, err := os.Stat(configRootPath)

		if err == nil {
			p.ConfigRoot = configRootPath
			return nil
		}
	}

	return fmt.Errorf("could not find any apache config file \"%s\" in the root directory \"%s\"", strings.Join(configs, ", "), p.ConfigRoot)
}

func (p *Parser) setLocations() error {
	var configListen string
	if err := p.setConfigRoot(); err != nil {
		return err
	}

	temp := filepath.Join(p.ServerRoot, "ports.conf")
	if com.IsFile(temp) {
		configListen = temp
	} else {
		configListen = p.ConfigRoot
	}
	p.СonfigListen = configListen

	return nil
}

// ParseFile parses file with Auegause
func (p *Parser) ParseFile(fPath string) error {
	useNew, removeOld := p.checkPath(fPath)

	if p.beforeDomReload != nil {
		unsavedFiles, err := p.GetUnsavedFiles()

		if err != nil {
			return err
		}

		p.beforeDomReload(unsavedFiles)
	}

	if !useNew {
		return nil
	}

	includedPaths, err := p.Augeas.Match(fmt.Sprintf("/augeas/load/Httpd['%s' =~ glob(incl)]", fPath))

	if err != nil {
		return err
	}

	if len(includedPaths) == 0 {
		if removeOld {
			p.removeTransform(fPath)
		}

		p.addTransform(fPath)
		p.Augeas.Load()
	}

	return nil
}

// GetAugeasError return Augeas errors
func (p *Parser) GetAugeasError(errorsToExclude []string) error {
	newErrors, err := p.Augeas.Match("/augeas//error")

	if err != nil {
		return fmt.Errorf("could not get augeas errors: %v", err)
	}

	if len(newErrors) == 0 {
		return nil
	}

	var rootErrors []string

	for _, newError := range newErrors {
		if !com.IsSliceContainsStr(errorsToExclude, newError) {
			rootErrors = append(rootErrors, newError)
		}
	}

	if len(rootErrors) == 0 {
		return nil
	}

	var detailedRootErrors []string

	for _, rError := range rootErrors {
		details, _ := p.Augeas.Get(rError)

		if details == "" {
			detailedRootErrors = append(detailedRootErrors, rError)
		} else {
			detailedRootErrors = append(detailedRootErrors, fmt.Sprintf("%s: %s", rError, details))
		}
	}

	return fmt.Errorf(strings.Join(detailedRootErrors, ", "))
}

// Save saves all chages to the reconfiguratiob files
func (p *Parser) Save(reverter *Reverter) error {
	unsavedFiles, err := p.GetUnsavedFiles()

	if err != nil {
		return err
	}

	if len(unsavedFiles) == 0 {
		return nil
	}

	if reverter != nil {
		if err = reverter.BackupFiles(unsavedFiles); err != nil {
			return err
		}
	}

	if err = p.Augeas.Save(); err != nil {
		return err
	}

	for _, unsavedFile := range unsavedFiles {
		p.Augeas.Remove(fmt.Sprintf("/files/%s", unsavedFile))
	}

	if err = p.Augeas.Load(); err != nil {
		return err
	}

	return nil
}

// GetArg returns argument value and interprets result
func (p *Parser) GetArg(match string) (string, error) {
	value, err := p.Augeas.Get(match)

	if err != nil {
		return "", err
	}

	value = strings.Trim(value, "'\"")
	re := regexp.MustCompile(argVarRegex)
	variables := re.FindAll([]byte(value), -1)

	for _, variable := range variables {
		variableStr := string(variable)
		// Since variable is satisfied regex, it has at least length 3: ${}
		variableKey := variableStr[2 : len(variableStr)-1]
		replaceVariable, ok := p.variables[variableKey]

		if !ok {
			return "", fmt.Errorf("could not parse variable: %s", variableStr)
		}

		value = strings.Replace(value, variableStr, replaceVariable, -1)
	}

	return value, nil
}

// UpdateRuntimeVariables Updates Includes, Defines and Includes from httpd config dump data
func (p *Parser) UpdateRuntimeVariables() error {
	if err := p.UpdateDefines(); err != nil {
		return err
	}

	if err := p.UpdateIncludes(); err != nil {
		return err
	}

	if err := p.UpdateModules(); err != nil {
		return err
	}

	return nil
}

// UpdateDefines Updates the map of known variables in the configuration
func (p *Parser) UpdateDefines() error {
	variables, err := p.ApacheCtl.ParseDefines()

	if err != nil {
		return fmt.Errorf("could not parse defines: %v", err)
	}

	p.variables = variables

	return nil
}

// UpdateIncludes gets includes from httpd process, and add them to DOM if needed
func (p *Parser) UpdateIncludes() error {
	p.FindDirective("Include", "", "", true)
	matches, err := p.ApacheCtl.ParseIncludes()

	if err != nil {
		return fmt.Errorf("could not update inlcludes: %v", err)
	}

	for _, match := range matches {
		if !p.IsFilenameExistInCurrentPaths(match) {
			p.ParseFile(match)
		}
	}

	return nil
}

// UpdateModules gets loaded modules from httpd process, and add them to DOM
func (p *Parser) UpdateModules() error {
	matches, err := p.ApacheCtl.ParseModules()

	if err != nil {
		return err
	}

	for _, module := range matches {
		p.AddModule(strings.TrimSpace(module))
	}

	return nil
}

// ResetModules resets the loaded modules list
func (p *Parser) ResetModules() error {
	p.Modules = make(map[string]bool)
	if err := p.UpdateModules(); err != nil {
		return err
	}

	// p.ParseModules() TODO: apache config should be also parsed for LoadModule directive
	return nil
}

// AddModule shortcut for updating parser modules.
func (p *Parser) AddModule(name string) {
	if p.Modules == nil {
		p.Modules = make(map[string]bool)
	}

	modKey := fmt.Sprintf("%s_module", name)

	if _, ok := p.Modules[modKey]; !ok {
		p.Modules[modKey] = true
	}

	modKey = fmt.Sprintf("mod_%s.c", name)

	if _, ok := p.Modules[modKey]; !ok {
		p.Modules[modKey] = true
	}
}

// FindDirective finds directive in configuration
// directive - directive to look for
// arg - directive value. If empty string then all directives should be considrered
// start - Augeas path that should be used to begin looking for the directive
// exclude - whether or not to exclude directives based on variables and enabled modules
func (p *Parser) FindDirective(directive, arg, start string, exclude bool) ([]string, error) {
	if start == "" {
		start = GetAugPath(p.ConfigRoot)
	}

	regStr := fmt.Sprintf("(%s)|(%s)|(%s)", directive, "Include", "IncludeOptional")
	matches, err := p.Augeas.Match(fmt.Sprintf("%s//*[self::directive=~regexp('%s', 'i')]", start, regStr))

	if err != nil {
		return nil, err
	}

	if exclude {
		matches, err = p.ExcludeDirectives(matches)

		if err != nil {
			return nil, err
		}
	}

	var argSuffix string
	var orderedMatches []string

	if arg == "" {
		argSuffix = "/arg"
	} else {
		argSuffix = fmt.Sprintf("/*[self::arg=~regexp('%s', 'i')]", arg)
	}

	for _, match := range matches {
		dir, err := p.Augeas.Get(match)

		if err != nil {
			return nil, err
		}

		dir = strings.ToLower(dir)

		if dir == "include" || dir == "includeoptional" {
			nArg, err := p.GetArg(match + "/arg")

			if err != nil {
				return nil, err
			}

			nStart, err := p.getIncludePath(nArg)

			if err != nil {
				return nil, err
			}

			nMatches, err := p.FindDirective(directive, arg, nStart, exclude)

			if err != nil {
				return nil, err
			}

			orderedMatches = append(orderedMatches, nMatches...)
		}

		if dir == strings.ToLower(directive) {
			nMatches, err := p.Augeas.Match(match + argSuffix)

			if err != nil {
				return nil, err
			}

			orderedMatches = append(orderedMatches, nMatches...)
		}

	}

	return orderedMatches, nil
}

// ExcludeDirectives excludes directives that are not loaded into the configuration.
func (p *Parser) ExcludeDirectives(matches []string) ([]string, error) {
	var validMatches []string
	filters := []directiveFilter{
		{"ifmodule", p.getModules()},
		{"ifdefine", p.getVariblesNames()},
	}

	for _, match := range matches {
		isPassed := true

		for _, filter := range filters {
			fPassed, err := p.isDirectivePassedFilter(match, filter)

			if err != nil {
				return nil, fmt.Errorf("failed to check the directive '%s' passed the filter '%s'", match, filter.Name)
			}

			if !fPassed {
				isPassed = false
				break
			}
		}

		if isPassed {
			validMatches = append(validMatches, match)
		}
	}

	return validMatches, nil
}

// AddDirective adds directive to the end of the file given by augConfPath
func (p *Parser) AddDirective(augConfPath string, directive string, args []string) error {
	if err := p.Augeas.Set(augConfPath+"/directive[last() + 1]", directive); err != nil {
		return err
	}

	for i, arg := range args {
		if err := p.Augeas.Set(fmt.Sprintf("%s/directive[last()]/arg[%d]", augConfPath, i+1), arg); err != nil {
			return err
		}
	}

	return nil
}

// AddDirectiveToIfModSSL adds directive to the end of the file given by augConfPath within IfModule ssl block
func (p *Parser) AddDirectiveToIfModSSL(augConfPath string, directive string, args []string) error {
	ifModPath, err := p.GetIfModule(augConfPath, "mod_ssl.c", false)

	if err != nil {
		return err
	}

	if err = p.Augeas.Insert(ifModPath+"arg", "directive", false); err != nil {
		return fmt.Errorf("could not insert directive within IfModule SSL block: %v", err)
	}

	nPath := ifModPath + "directive[1]"

	if err = p.Augeas.Set(nPath, directive); err != nil {
		return fmt.Errorf("could not set directive value within IfModule SSL block: %v", err)
	}

	if len(args) == 0 {
		if err = p.Augeas.Set(nPath+"/arg", args[0]); err != nil {
			return fmt.Errorf("could not set directive argument within IfModule SSL block: %v", err)
		}
	} else {
		for i, arg := range args {
			if err = p.Augeas.Set(fmt.Sprintf("%s/arg[%d]", nPath, i+1), arg); err != nil {
				return fmt.Errorf("could not set directive argument within IfModule SSL block: %v", err)
			}
		}
	}

	return nil
}

// AddInclude adds Include directive for a configuration file
func (p *Parser) AddInclude(mainConfigPath string, inclPath string) error {
	matches, err := p.FindDirective("Include", inclPath, "", true)

	if err != nil {
		return fmt.Errorf("failed searching 'Include' directive in the config '%s': %v", mainConfigPath, err)
	}

	if len(matches) == 0 {
		if err = p.AddDirective(GetAugPath(mainConfigPath), "Include", []string{inclPath}); err != nil {
			return fmt.Errorf("could not add 'Include' directive to config '%s': %v", mainConfigPath, err)
		}
	}

	newDir := filepath.Dir(inclPath)
	newFile := filepath.Base(inclPath)

	if _, ok := p.existingPaths[newDir]; !ok {
		p.existingPaths[newDir] = make([]string, 0)
	}

	p.existingPaths[newDir] = append(p.existingPaths[newDir], newFile)

	return nil
}

// GetIfModule returns the path to <IfModule mod> and creates one if it does not exist
func (p *Parser) GetIfModule(augConfPath string, mod string, begining bool) (string, error) {
	ifMods, err := p.Augeas.Match(fmt.Sprintf("%s/IfModule/*[self::arg='%s']", augConfPath, mod))

	if err != nil {
		return "", fmt.Errorf("could not get IfModule directive: %v", err)
	}

	if len(ifMods) == 0 {
		return p.CreateIfModule(augConfPath, mod, begining)
	}

	path, _, _ := xstrings.LastPartition(ifMods[0], "arg")

	return path, nil
}

// CreateIfModule creates a new <IfMod mod> and returns its path
func (p *Parser) CreateIfModule(augConfPath string, mod string, begining bool) (string, error) {
	var argPath, retPath string
	var err error

	if begining {
		argPath = fmt.Sprintf("%s/IfModule[1]/arg", augConfPath)

		if err = p.Augeas.Insert(fmt.Sprintf("%s/directive[1]", augConfPath), "IfModule", true); err != nil {
			return "", fmt.Errorf("could not insert IfModule directive: %v", err)
		}

		retPath = fmt.Sprintf("%s/IfModule[1]/", augConfPath)
	} else {
		path := fmt.Sprintf("%s/IfModule[last() + 1]", augConfPath)
		argPath = fmt.Sprintf("%s/IfModule[last()]/arg", augConfPath)

		if err = p.Augeas.Set(path, ""); err != nil {
			return "", fmt.Errorf("could not set IfModule directive: %v", err)
		}

		retPath = fmt.Sprintf("%s/IfModule[last()]/", augConfPath)
	}

	if err = p.Augeas.Set(argPath, mod); err != nil {
		return "", fmt.Errorf("could not set argument %s: %v", mod, err)
	}

	return retPath, nil
}

// isDirectivePassedFilter checks if directive can pass a filter
func (p *Parser) isDirectivePassedFilter(match string, filter directiveFilter) (bool, error) {
	lMatch := strings.ToLower(match)
	lastMatchIdx := strings.Index(lMatch, filter.Name)

	for lastMatchIdx != -1 {
		endOfIfIdx := strings.Index(lMatch[lastMatchIdx:], "/")

		if endOfIfIdx == -1 {
			endOfIfIdx = len(lMatch)
		} else {
			endOfIfIdx += lastMatchIdx
		}

		expression, err := p.Augeas.Get(match[:endOfIfIdx] + "/arg")

		if err != nil {
			return false, err
		}

		if strings.HasPrefix(expression, "!") {
			if com.IsSliceContainsStr(filter.Value, expression[1:]) {
				return false, nil
			}
		} else {
			if !com.IsSliceContainsStr(filter.Value, expression) {
				return false, nil
			}
		}

		lastMatchIdx = strings.Index(lMatch[endOfIfIdx:], filter.Name)

		if lastMatchIdx != -1 {
			lastMatchIdx += endOfIfIdx
		}
	}

	return true, nil
}

// getIncludePath converts Apache Include directive to Augeas path
func (p *Parser) getIncludePath(arg string) (string, error) {
	arg = p.convertPathFromServerRootToAbs(arg)
	info, err := os.Stat(arg)

	if err == nil && info.IsDir() {
		p.ParseFile(filepath.Join(arg, "*"))
	} else {
		p.ParseFile(arg)
	}

	argParts := strings.Split(arg, "/")

	for index, part := range argParts {
		for _, char := range part {
			if com.IsSliceContainsStr(fnMatchChars, string(char)) {
				argParts[index] = fmt.Sprintf("* [label()=~regexp('%s')]", p.fnMatchToRegex(part))
				break
			}
		}
	}

	arg = strings.Join(argParts, "/")

	return GetAugPath(arg), nil
}

func (p *Parser) fnMatchToRegex(fnMatch string) string {
	regex := utils.TranslateFnmatchToRegex(fnMatch)

	return regex[4 : len(regex)-2]
}

// convertPathFromServerRootToAbs convert path to absolute if it is relative to server root
func (p *Parser) convertPathFromServerRootToAbs(path string) string {
	path = strings.Trim(path, "'\"")

	if strings.HasPrefix(path, "/") {
		path = filepath.Clean(path)
	} else {
		path = filepath.Clean(filepath.Join(p.ServerRoot, path))
	}

	return path
}

// GetModules returns loaded modules from httpd process
func (p *Parser) getModules() []string {
	modules := make([]string, 0)

	for module := range p.Modules {
		modules = append(modules, module)
	}

	return modules
}

func (p *Parser) getVariblesNames() []string {
	names := make([]string, len(p.variables))

	for name := range p.variables {
		names = append(names, name)
	}

	return names
}

// Checks if fPath exists in augeas paths
// We should try to append a new fPath to augeas
// parser paths, and/or remove the old one with more
// narrow matching.
func (p *Parser) checkPath(fPath string) (useNew, removeOld bool) {
	filename := filepath.Base(fPath)
	dirname := filepath.Dir(fPath)
	exisingMatches, ok := p.Paths[dirname]

	if !ok {
		return true, false
	}

	removeOld = filename == "*"

	for _, existingMatch := range exisingMatches {
		if existingMatch == "*" {
			return false, removeOld
		}
	}

	return true, removeOld
}

// Remove a transform from Augeas
func (p *Parser) removeTransform(fPath string) {
	dirnameToRemove := filepath.Dir(fPath)
	existedFilenames := p.Paths[dirnameToRemove]

	for _, filename := range existedFilenames {
		pathToRemove := filepath.Join(dirnameToRemove, filename)
		includesToRemove, err := p.Augeas.Match(fmt.Sprintf("/augeas/load/Httpd/incl [. ='%s']", pathToRemove))

		if err == nil && len(includesToRemove) > 0 {
			p.Augeas.Remove(includesToRemove[0])
		}
	}

	delete(p.Paths, dirnameToRemove)
}

// Add a transform to Augeas
func (p *Parser) addTransform(fPath string) error {
	lastInclude, err := p.Augeas.Match("/augeas/load/Httpd/incl [last()]")
	dirnameToAdd := filepath.Dir(fPath)
	fileNameToAdd := filepath.Base(fPath)

	if err != nil {
		return err
	}

	if len(lastInclude) > 0 {
		p.Augeas.Insert(lastInclude[0], "incl", false)
		p.Augeas.Set("/augeas/load/Httpd/incl[last()]", fPath)
	} else {
		p.Augeas.Set("/augeas/load/Httpd/lens", "Httpd.lns")
		p.Augeas.Set("/augeas/load/Httpd/incl", fPath)
	}

	if p.Paths == nil {
		p.Paths = make(map[string][]string)
	}

	paths := append(p.Paths[dirnameToAdd], fileNameToAdd)
	p.Paths[dirnameToAdd] = paths

	return nil
}

//GetUnsavedFiles returns unsaved paths
func (p *Parser) GetUnsavedFiles() ([]string, error) {
	// Current save method
	saveMethod, err := p.Augeas.Get("/augeas/save")

	if err != nil {
		return nil, err
	}

	// See https://github.com/hercules-team/augeas/wiki/Change-how-files-are-saved
	if err = p.Augeas.Set("/augeas/save", "noop"); err != nil {
		return nil, err
	}

	if err = p.Augeas.Save(); err != nil {
		p.Augeas.Set("/augeas/save", saveMethod)
		return nil, err
	}

	saveErr := p.GetAugeasError(nil)
	p.Augeas.Set("/augeas/save", saveMethod)

	if saveErr != nil {
		return nil, saveErr
	}

	var paths []string
	matchesToSave, err := p.Augeas.Match("/augeas/events/saved")

	if err != nil {
		return nil, err
	}

	for _, matchToSave := range matchesToSave {
		pathToSave, err := p.Augeas.Get(matchToSave)

		if err != nil {
			return nil, err
		}

		paths = append(paths, pathToSave[6:])
	}

	return paths, nil
}

// IsFilenameExistInCurrentPaths checks if the file path is parsed by current Augeas parser config
func (p *Parser) IsFilenameExistInCurrentPaths(filename string) bool {
	return p.isFilenameExistInPaths(filename, p.Paths)
}

// IsFilenameExistInOriginalPaths checks if the file path is parsed by existing Apache config
func (p *Parser) IsFilenameExistInOriginalPaths(filename string) bool {
	return p.isFilenameExistInPaths(filename, p.existingPaths)
}

func (p *Parser) isFilenameExistInPaths(filename string, paths map[string][]string) bool {
	for dir, fNames := range paths {
		for _, fName := range fNames {
			isMatch, err := path.Match(path.Join(dir, fName), filename)

			if err != nil {
				continue
			}

			if isMatch {
				return true
			}
		}
	}

	return false
}

// GetRootAugPath returns Augeas path of the root configuration
func (p *Parser) GetRootAugPath() (string, error) {
	return GetAugPath(p.ConfigRoot), nil
}

// GetAugPath returns Augeas path for the file full path
func GetAugPath(fullPath string) string {
	return fmt.Sprintf("/files/%s", fullPath)
}

func getServerRootPath(serverRootPath string) (string, error) {
	if serverRootPath != "" {
		return filepath.Abs(serverRootPath)
	}

	// check default paths
	for _, serverRootPath := range serverRootPaths {
		if com.IsDir(serverRootPath) {
			return filepath.Abs(serverRootPath)
		}
	}

	return "", fmt.Errorf("could not find server root path")
}
