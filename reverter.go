package a2conf

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/unknwon/com"
)

// Reverter reverts change back for configuration files of virtual hosts
type Reverter struct {
	filesToDelete  []string
	filesToRestore map[string]string
}

// AddFileToDeletion marks file to delete on rollback
func (r *Reverter) AddFileToDeletion(filePath string) {
	r.filesToDelete = append(r.filesToDelete, filePath)
}

// BackupFiles makes files backups
func (r *Reverter) BackupFiles(filePaths []string) error {
	for _, filePath := range filePaths {
		if err := r.BackupFile(filePath); err != nil {
			return fmt.Errorf("could make file '%s' backup: %v", filePath, err)
		}
	}

	return nil
}

// BackupFile makes file backup. The file content will be restored on rollback.
func (r *Reverter) BackupFile(filePath string) error {
	bFilePath := r.getBackupFilePath(filePath)

	if _, ok := r.filesToRestore[filePath]; ok {
		// TODO: add logging
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

// Rollback rollback all changes
func (r *Reverter) Rollback() error {
	// remove created files
	for _, fileToDelete := range r.filesToDelete {
		_, err := os.Stat(fileToDelete)

		if os.IsNotExist(err) {
			continue
		}

		if err != nil {
			return err
		}

		err = os.Remove(fileToDelete)

		if err != nil {
			return err
		}
	}

	if r.filesToRestore == nil {
		return nil
	}

	// restore the content of backed up files
	for originFilePath, bFilePath := range r.filesToRestore {
		bContent, err := ioutil.ReadFile(bFilePath)

		if err != nil {
			return err
		}

		err = ioutil.WriteFile(originFilePath, bContent, 0644)

		if err != nil {
			return err
		}

		os.Remove(bFilePath)
	}

	return nil
}

// Commit commits changes. All *.back files will be removed.
func (r *Reverter) Commit() error {
	for filePath, bFilePath := range r.filesToRestore {
		if com.IsFile(bFilePath) {
			os.Remove(bFilePath)
		}

		delete(r.filesToRestore, filePath)
	}

	r.filesToDelete = nil

	return nil
}

func (r *Reverter) getBackupFilePath(filePath string) string {
	return filePath + ".back"
}
