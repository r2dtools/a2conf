package a2conf

import (
	"io/ioutil"
	"testing"

	"github.com/r2dtools/a2conf/apache"
	"github.com/r2dtools/a2conf/logger"
	"github.com/stretchr/testify/assert"
	"github.com/unknwon/com"
)

func TestReverterRollback(t *testing.T) {
	reverter := getReverter()
	fileToBackup := "/tmp/fileToRemove"
	createFile(t, fileToBackup)
	err := reverter.BackupFiles([]string{fileToBackup})
	assert.Nilf(t, err, "could not backup files: %v", err)
	bFileToBackup := reverter.getBackupFilePath(fileToBackup)
	assert.Equalf(t, true, com.IsExist(bFileToBackup), "backed up file '%s' does not exist", bFileToBackup)
	err = reverter.Rollback()
	assert.Nilf(t, err, "revert error: %v", err)
	assert.Equalf(t, false, com.IsExist(bFileToBackup), "backed up file '%s' steel exists", bFileToBackup)

	reverter.AddFileToDeletion(fileToBackup)
	assert.Equalf(t, true, com.IsExist(fileToBackup), "file '%s' does not exist", fileToBackup)
	err = reverter.Rollback()
	assert.Nilf(t, err, "revert error: %v", err)
	assert.Equalf(t, false, com.IsExist(fileToBackup), "file '%s' steel exists", fileToBackup)
}

func TestReverterCommit(t *testing.T) {
	reverter := getReverter()
	fileToBackup := "/tmp/fileToRemove"
	createFile(t, fileToBackup)
	err := reverter.BackupFiles([]string{fileToBackup})
	assert.Nilf(t, err, "could not backup files: %v", err)
	bFileToBackup := reverter.getBackupFilePath(fileToBackup)
	assert.Equalf(t, true, com.IsExist(bFileToBackup), "backed up file '%s' does not exist", bFileToBackup)
	err = reverter.Commit()
	assert.Nilf(t, err, "revert error: %v", err)
	assert.Equalf(t, false, com.IsExist(bFileToBackup), "backed up file '%s' steel exists", bFileToBackup)
	assert.Equalf(t, true, com.IsExist(fileToBackup), "file '%s' does not exist", fileToBackup)
}

func getReverter() *Reverter {
	logger := logger.NilLogger{}
	apacheSite := apache.Site{}
	reverter := Reverter{logger: &logger, apacheSite: &apacheSite}

	return &reverter
}

func createFile(t *testing.T, path string) {
	err := ioutil.WriteFile(path, []byte("content"), 0644)
	assert.Nilf(t, err, "could not create tmp file: %v", err)
	assert.Equal(t, true, com.IsExist(path), "create file does not exist")
}
