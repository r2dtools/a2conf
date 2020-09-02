package a2conf

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/r2dtools/a2conf/a2conf/utils"
	"honnef.co/go/augeas"
)

const (
	argVarRegex = `\$\{[^ \}]*}`
)

var fnMatchChars = []string{"*", "?", "\\", "[", "]"}

// Parser ia a wrapper under the augeas to work with httpd config
type Parser struct {
	Augeas          augeas.Augeas
	ApacheCtl       *ApacheCtl
	ServerRoot      string
	VHostRoot       string
	configRoot      string
	version         string
	beforeDomReload func(unsavedFiles []string)
	Paths           map[string][]string
	existingPaths   map[string][]string
	variables       map[string]string
	modules         map[string]bool
}

type directiveFilter struct {
	Name  string
	Value []string
}

// GetParser creates parser instance
func GetParser(apachectl *ApacheCtl, serverRoot, version string, vhostRoot string) (*Parser, error) {
	serverRoot, err := filepath.Abs(serverRoot)

	if err != nil {
		return nil, err
	}

	vhostRoot, err = filepath.Abs(vhostRoot)

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
	configRoot, err := parser.getConfigRoot()

	if err != nil {
		parser.Close()

		return nil, err
	}

	if err = parser.ParseFile(configRoot); err != nil {
		parser.Close()

		return nil, fmt.Errorf("could not parse apache config: %v", err)
	}

	// TODO: check apache version
	parser.UpdateRuntimeVariables()

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

func (p *Parser) getConfigRoot() (string, error) {
	if p.configRoot != "" {
		return p.configRoot, nil
	}

	configs := []string{"apache2.conf", "httpd.conf", "conf/httpd.conf"}

	for _, config := range configs {
		configRootPath := path.Join(p.ServerRoot, config)
		_, err := os.Stat(configRootPath)

		if err != nil {
			p.configRoot = configRootPath

			return p.configRoot, nil
		}
	}

	return "", fmt.Errorf("could not find any apache config file \"%s\" in the root directory \"%s\"", strings.Join(configs, ", "), p.configRoot)
}

// ParseFile parses file with Auegause
func (p *Parser) ParseFile(fPath string) error {
	useNew, removeOld := p.checkPath(fPath)

	if p.beforeDomReload != nil {
		unsavedFiles, err := p.getUnsavedFiles()

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
		if !utils.SliceContainsString(errorsToExclude, newError) {
			rootErrors = append(rootErrors, newError)
		}
	}

	if len(rootErrors) > 0 {
		return fmt.Errorf(strings.Join(rootErrors, ", "))
	}

	return nil
}

// Save saves all chages to the reconfiguratiob files
func (p *Parser) Save() error {
	unsavedFiles, err := p.getUnsavedFiles()

	if err != nil {
		return err
	}

	if len(unsavedFiles) == 0 {
		return nil
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
func (p *Parser) UpdateRuntimeVariables() {
	p.UpdateDefines()
	p.UpdateIncludes()
	p.UpdateModules()
}

// UpdateDefines Updates the map of known variables in the configuration
func (p *Parser) UpdateDefines() {
	p.variables, _ = p.ApacheCtl.ParseDefines()
}

// UpdateIncludes gets includes from httpd process, and add them to DOM if needed
func (p *Parser) UpdateIncludes() {
	p.FindDirective("Include", "", "", false)
	matches, err := p.ApacheCtl.ParseIncludes()

	if err != nil {
		// TODO: add logging
	}

	for _, match := range matches {
		if !p.IsFilenameExistInCurrentPaths(match) {
			p.ParseFile(match)
		}
	}
}

// UpdateModules gets loaded modules from httpd process, and add them to DOM
func (p *Parser) UpdateModules() {
	matches, _ := p.ApacheCtl.ParseModules()

	for _, module := range matches {
		p.AddModule(strings.TrimSpace(module))
	}
}

// AddModule shortcut for updating parser modules.
func (p *Parser) AddModule(name string) {
	if p.modules == nil {
		p.modules = make(map[string]bool)
	}

	modKey := fmt.Sprintf("%s_module", name)

	if _, ok := p.modules[modKey]; !ok {
		p.modules[modKey] = true
	}

	modKey = fmt.Sprintf("mod_%s.c", name)

	if _, ok := p.modules[modKey]; !ok {
		p.modules[modKey] = true
	}
}

// FindDirective finds directive in configuration
// directive - directive to look for
// arg - directive value. If empty string then all directives should be considrered
// start - Augeas path that should be used to begin looking for the directive
// exclude - whether or not to exclude directives based on variables and enabled modules
func (p *Parser) FindDirective(directive, arg, start string, exclude bool) ([]string, error) {
	if start == "" {
		start = GetAugPath(p.configRoot)
	}

	regStr := fmt.Sprintf("(%s)|(%s)|(%s)", directive, "Include", "IncludeOptional")
	matches, err := p.Augeas.Match(fmt.Sprintf("%s//*[self::directive=~regexp('%s', 'i')]", start, regStr))

	if err != nil {
		return nil, err
	}

	if exclude {
		matches = p.ExcludeDirectives(matches)
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
func (p *Parser) ExcludeDirectives(matches []string) []string {
	var validMatches []string

	filters := []directiveFilter{
		{"ifmodule", p.getModules()},
		{"ifdefine", p.getVariblesNames()},
	}

	for _, match := range matches {
		isPassed := true

		for _, filter := range filters {
			if !p.isDirectivePassedFilter(match, filter) {
				isPassed = false
				break
			}
		}

		if isPassed {
			validMatches = append(validMatches, match)
		}
	}

	return validMatches
}

// isDirectivePassedFilter checks if directive can pass a filter
func (p *Parser) isDirectivePassedFilter(match string, filter directiveFilter) bool {
	lMatch := strings.ToLower(match)
	lastMAtchIds := strings.Index(lMatch, filter.Name)

	for lastMAtchIds != -1 {

	}

	return true
}

// getIncludePath converts Apache Include directive to Augeas path
func (p *Parser) getIncludePath(arg string) (string, error) {
	arg = p.convertPathFromServerRootToAbs(arg)
	info, err := os.Stat(arg)

	if os.IsNotExist(err) {
		return "", err
	}

	if info.IsDir() {
		p.ParseFile(filepath.Join(arg, "*"))
	} else {
		p.ParseFile(arg)
	}

	argParts := strings.Split(arg, "/")

	for index, part := range argParts {
		for _, char := range part {
			if utils.SliceContainsString(fnMatchChars, string(char)) {
				argParts[index] = fmt.Sprintf("* [label()=~regexp('%s')]", p.fnMatchToRegex(part))
				break
			}
		}
	}

	arg = strings.Join(argParts, "/")

	return GetAugPath(arg), nil
}

func (p *Parser) fnMatchToRegex(fnMatch string) string {
	return utils.TranslateFnmatchToRegex(fnMatch)
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
	modules := make([]string, len(p.modules))

	for module := range p.modules {
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
// We should try to append the new fPath to augeas
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

// Returns unsaved paths
func (p *Parser) getUnsavedFiles() ([]string, error) {
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
		return nil, err
	}

	// Return previous save method
	if err = p.Augeas.Set("/augeas/save", saveMethod); err != nil {
		return nil, err
	}

	var paths []string
	pathsToSave, err := p.Augeas.Match("/augeas/events/saved")

	if err != nil {
		return nil, err
	}

	for _, pathToSave := range pathsToSave {
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
	configRoot, err := p.getConfigRoot()

	if err != nil {
		return "", err
	}

	return GetAugPath(configRoot), nil
}

// GetAugPath returns Augeas path for the file full path
func GetAugPath(fullPath string) string {
	return fmt.Sprintf("/files/%s", fullPath)
}
