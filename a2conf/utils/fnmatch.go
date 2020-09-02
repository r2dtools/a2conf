package utils

import (
	"fmt"
	"regexp"
	"strings"
)

// Translate converts a shell PATTERN to a regular expression string
func TranslateFnmatchToRegex(fnmatchStr string) string {
	i, n := 0, len(fnmatchStr)
	var res string

	for i < n {
		c := string(fnmatchStr[i])
		i++

		if c == "*" {
			res = res + ".*"
		} else if c == "?" {
			res = res + "."
		} else if c == "[" {
			j := i

			if j < n && string(fnmatchStr[j]) == "!" {
				j++
			}

			if j < n && string(fnmatchStr[j]) == "]" {
				j++
			}

			for j < n && string(fnmatchStr[j]) != "]" {
				j++
			}

			if j >= n {
				res = res + "//["
			} else {
				stuff := strings.Replace(fnmatchStr[i:j], "//", "////", -1)
				i = j + 1

				if string(stuff[0]) == "!" {
					stuff = "^" + stuff[1:]
				} else if string(stuff[0]) == "^" {
					stuff = "\\" + stuff
				}

				res = fmt.Sprintf("%s[%s]", res, stuff)
			}
		} else {
			res = res + regexp.QuoteMeta(c)
		}
	}

	return fmt.Sprintf("(?s:%s)$", res)
}
