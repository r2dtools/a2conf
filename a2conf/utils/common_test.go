package utils

import "testing"

type scTestItem struct {
	values   []string
	search   string
	contains bool
}

var scTests = []scTestItem{
	{[]string{"test1", "test 2", "test_3"}, "test 2", true},
	{[]string{"test1", "test 2", "test_3"}, "test 4", false},
	{[]string{}, "test 2", false},
	{nil, "test 2", false},
}

func TestSliceContains(t *testing.T) {
	for _, item := range scTests {
		sContains := SliceContainsString(item.values, item.search)

		if sContains != item.contains {
			t.Error(
				"for", item.values,
				"expected", item.contains,
				"actual", sContains,
			)
		}
	}
}
