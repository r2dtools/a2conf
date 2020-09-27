package utils

import "testing"

func TestTranslateFnmatchToRegex(t *testing.T) {
	items := []string{"*.txt", "fnmatch_*.go"}
	expectedItesms := []string{"(?s:.*\\.txt)$", "(?s:fnmatch_.*\\.go)$"}

	for index, item := range items {
		tItem := TranslateFnmatchToRegex(item)

		if tItem != expectedItesms[index] {
			t.Errorf("expected %s, got %s", expectedItesms[index], tItem)
		}
	}
}
