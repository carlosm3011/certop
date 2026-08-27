//go:build !unix

package probe

import "strings"

func isRefused(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "refused")
}
