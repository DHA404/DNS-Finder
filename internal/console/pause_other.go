//go:build !windows

// Package console contains the platform-specific console handling needed when
// the program is launched by double-clicking the executable rather than from
// an existing shell.
package console

// PauseOnExit is a no-op outside Windows: a terminal emulator on Unix does not
// tear the window down the moment the process exits, so there is nothing to
// hold open.
func PauseOnExit(string) {}
