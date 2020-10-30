package utils

import (
	"testing"

	"github.com/unknwon/com"
)

func TestStrSlicesDifference(t *testing.T) {
	type testData struct {
		a, b, diff []string
	}

	items := []testData{
		{[]string{"a", "b", "c", "d"}, []string{"a", "d"}, []string{"b", "c"}},
		{[]string{"a", "d"}, []string{"a", "b", "c", "d"}, []string{}},
		{[]string{"a", "b", "c", "d"}, []string{"e", "f"}, []string{"a", "b", "c", "d"}},
	}

	for _, item := range items {
		diff := StrSlicesDifference(item.a, item.b)

		if !com.CompareSliceStr(diff, item.diff) {
			t.Errorf("expected %v, got %v", item.diff, diff)
		}
	}
}
