package a2conf

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/r2dtools/a2conf/a2conf/utils"
	"honnef.co/go/augeas"
)

// Parser ia a wrapper under the augeas to work with httpd config
type Parser struct {
	Augeas          augeas.Augeas
	Root            string
	configRoot      string
	beforeDomReload func(unsavedFiles []string)
	paths           map[string][]string
	existingPaths   map[string][]string
}

var parser *Parser

// GetParser creates parser instance
func GetParser(root string) (*Parser, error) {
	if parser == nil {
		root, err := filepath.Abs(root)

		if err != nil {
			return nil, err
		}

		aug, err := augeas.New("/", "", augeas.None)

		if err != nil {
			return nil, err
		}

		parser = &Parser{
			Augeas: aug,
			Root:   root,
		}
		configRoot, err := parser.getConfigRoot()

		if err != nil {
			Close()

			return nil, err
		}

		if err = parser.ParseFile(configRoot); err != nil {
			Close()

			return nil, fmt.Errorf("could not parse apache config: %v", err)
		}
	}

	return parser, nil
}

// Close closes the Parser instance and frees any storage associated with it.
func Close() {
	if parser != nil {
		parser.Augeas.Close()
		parser = nil
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
	configs := []string{"apache2.conf", "httpd.conf", "conf/httpd.conf"}

	for _, config := range configs {
		configPath := path.Join(p.Root, config)
		_, err := os.Stat(configPath)

		if err == nil {
			return configPath, nil
		}
	}

	return "", fmt.Errorf("could not find any apache config file \"%s\" in the root directory \"%s\"", strings.Join(configs, ", "), p.Root)
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

// Checks if fPath exists in augeas paths
// We should try to append the new fPath to augeas
// parser paths, and / or remove the old one with more
// narrow matching.
func (p *Parser) checkPath(fPath string) (useNew, removeOld bool) {
	filename := filepath.Base(fPath)
	dirname := filepath.Dir(fPath)
	exisingMatches, ok := p.paths[dirname]

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
	existedFilenames := p.paths[dirnameToRemove]

	for _, filename := range existedFilenames {
		pathToRemove := filepath.Join(dirnameToRemove, filename)
		includesToRemove, err := p.Augeas.Match(fmt.Sprintf("/augeas/load/Httpd/incl [. ='%s']", pathToRemove))

		if err == nil && len(includesToRemove) > 0 {
			p.Augeas.Remove(includesToRemove[0])
		}
	}

	delete(p.paths, dirnameToRemove)
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

	paths := append(p.paths[dirnameToAdd], fileNameToAdd)
	p.paths[dirnameToAdd] = paths

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
