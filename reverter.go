package a2conf

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/r2dtools/a2conf/apache"
	"github.com/r2dtools/a2conf/logger"
	"github.com/unknwon/com"
)

type rollbackError struct {
	err error
}

func (re *rollbackError) Error() string {
	return fmt.Sprintf("rollback failed: %v", re.err)
}

// Reverter reverts change back for configuration files of virtual hosts
type Reverter struct {
	filesToDelete    []string
	filesToRestore   map[string]string
	configsToDisable []string
	apacheSite       *apache.Site
	logger           logger.Logger
}

// SetLogger sets logger
func (r *Reverter) SetLogger(logger logger.Logger) {
	r.logger = logger
}

// AddFileToDeletion marks file to delete on rollback
func (r *Reverter) AddFileToDeletion(filePath string) {
	r.filesToDelete = append(r.filesToDelete, filePath)
}

// BackupFiles makes files backups
func (r *Reverter) BackupFiles(filePaths []string) error {
	for _, filePath := range filePaths {
		if err := r.BackupFile(filePath); err != nil {
			return fmt.Errorf("could not make file '%s' backup: %v", filePath, err)
		}
	}

	return nil
}

// BackupFile makes file backup. The file content will be restored on rollback.
func (r *Reverter) BackupFile(filePath string) error {
	bFilePath := r.getBackupFilePath(filePath)

	if _, ok := r.filesToRestore[filePath]; ok {
		r.logger.Debug(fmt.Sprintf("file '%s' is already backed up.", filePath))
		return nil
	}

	// Skip file backup if it should be removed
	if com.IsSliceContainsStr(r.filesToDelete, filePath) {
		r.logger.Debug(fmt.Sprintf("file '%s' will be removed on rollback. Skip its backup.", filePath))
		return nil
	}

	content, err := ioutil.ReadFile(filePath)

	if err != nil {
		return err
	}

	err = ioutil.WriteFile(bFilePath, content, 0644)

	if err != nil {
		return err
	}

	if r.filesToRestore == nil {
		r.filesToRestore = make(map[string]string)
	}

	r.filesToRestore[filePath] = bFilePath

	return nil
}

// AddSiteConfigToDisable marks apache site config as needed to be disabled on rollback
func (r *Reverter) AddSiteConfigToDisable(siteConfigName string) {
	r.configsToDisable = append(r.configsToDisable, siteConfigName)
}

// Rollback rollback all changes
func (r *Reverter) Rollback() error {
	// Disable all enabled before sites
	// Note: only hosts enabled via a2ensite utility are in this slice
	for _, siteConfigToDisable := range r.configsToDisable {
		if err := r.apacheSite.Disable(siteConfigToDisable); err != nil {
			return &rollbackError{err}
		}
	}

	// remove created files
	for _, fileToDelete := range r.filesToDelete {
		_, err := os.Stat(fileToDelete)

		if os.IsNotExist(err) {
			r.logger.Debug(fmt.Sprintf("file '%s' does not exist. Skip its deletion.", fileToDelete))
			continue
		}

		if err != nil {
			return &rollbackError{err}
		}

		err = os.Remove(fileToDelete)

		if err != nil {
			return &rollbackError{err}
		}
	}

	if r.filesToRestore == nil {
		return nil
	}

	// restore the content of backed up files
	for originFilePath, bFilePath := range r.filesToRestore {
		bContent, err := ioutil.ReadFile(bFilePath)

		if err != nil {
			return &rollbackError{err}
		}

		err = ioutil.WriteFile(originFilePath, bContent, 0644)

		if err != nil {
			return &rollbackError{err}
		}

		if err := os.Remove(bFilePath); err != nil {
			r.logger.Error(fmt.Sprintf("could not remove file '%s' on reverter rollback: %v", bFilePath, err))
		}

		delete(r.filesToRestore, originFilePath)
	}

	return nil
}

// Commit commits changes. All *.back files will be removed.
func (r *Reverter) Commit() error {
	for filePath, bFilePath := range r.filesToRestore {
		if com.IsFile(bFilePath) {
			if err := os.Remove(bFilePath); err != nil {
				r.logger.Error(fmt.Sprintf("could not remove file '%s' on reverter commit: %v", bFilePath, err))
			}
		}

		delete(r.filesToRestore, filePath)
	}

	r.filesToDelete = nil

	return nil
}

func (r *Reverter) getBackupFilePath(filePath string) string {
	return filePath + ".back"
}
