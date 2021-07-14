package utils

import (
	"os/exec"

	"github.com/Masterminds/semver"
)

// StrSlicesDifference returns all elements of the first slice which do not present in the second one
func StrSlicesDifference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	var diff []string

	for _, x := range b {
		mb[x] = struct{}{}
	}

	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}

	return diff
}

// CheckMinVersion checks if version is higher or equal than minVersion
func CheckMinVersion(version, minVersion string) (bool, error) {
	c, err := semver.NewConstraint(">=" + minVersion)

	if err != nil {
		return false, err
	}

	v, err := semver.NewVersion(version)

	if err != nil {
		return false, err
	}

	return c.Check(v), nil
}

// IsCommandExist checks if command exists via which linus command
func IsCommandExist(name string) bool {
	cmd := exec.Command("which", name)
	if _, err := cmd.Output(); err == nil {
		return true
	}

	return false
}
