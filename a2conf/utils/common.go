package utils

// SliceContainsString checks if slice contains a string
func SliceContainsString(s []string, value string) bool {
	for _, v := range s {
		if v == value {
			return true
		}
	}

	return false
}
