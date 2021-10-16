// +build !windows

package core

import (
	"os/exec"
)

func ExecuteCommand(name string, args ...string) ([]byte, error) {
	proc := exec.Command(name, args...)
	return proc.Output()
}
