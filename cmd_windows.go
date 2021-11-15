// +build windows

package core

import (
	"os/exec"
	"syscall"
)

func ExecuteCommand(name string, args ...string) ([]byte, error) {
	proc := exec.Command(name, args...)
	proc.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return proc.CombinedOutput()
}

func RunCommand(name string, args ...string) error {
	proc := exec.Command(name, args...)
	proc.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return proc.Run()
}
