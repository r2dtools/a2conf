package utils

import (
	"path/filepath"
	"testing"
)

func TestGetFilePathFromAugPath(t *testing.T) {
	type testData struct {
		augPath,
		filePath,
		prefix string
	}

	items := []testData{
		{"../test_data/aug_path/aug_file", "../test_data/aug_path/aug_file", "/files"},
		{"../test_data/aug_path/aug_file/internal_path_1/internal_path_2", "../test_data/aug_path/aug_file", "/files"},
		{"../test_data/aug_path/aug_file", "", ""},
	}

	for _, item := range items {
		augPath := getAbsPath(item.augPath, t)
		augPath = filepath.Join(item.prefix, augPath)
		filePath := getAbsPath(item.filePath, t)
		fPath := GetFilePathFromAugPath(augPath)

		if fPath != filePath {
			t.Errorf("expected %s, got %s", filePath, fPath)
		}

	}
}

func getAbsPath(path string, t *testing.T) string {
	if path == "" {
		return ""
	}

	path, err := filepath.Abs(path)

	if err != nil {
		t.Errorf("failed to get absolute path: %v", err)
	}

	return path
}
