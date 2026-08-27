//go:build unix

package probe

import (
	"errors"
	"syscall"
)

func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
