// Package console contains the platform-specific console handling needed when
// the program is launched by double-clicking the executable rather than from
// an existing shell.
package console

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
)

// PauseOnExit keeps the console window open when the program was launched by a
// double-click (or a launcher such as Listary) rather than from an existing
// shell. In that situation Windows creates a console solely for this process
// and destroys it the instant the process exits, so the user never sees the
// results.
//
// The heuristic is GetConsoleProcessList: a console owned only by us reports a
// single attached process, whereas a console inherited from cmd.exe or
// PowerShell reports at least two (the shell and us). In the latter case the
// window survives on its own and pausing would just be annoying, so we do
// nothing.
func PauseOnExit(msg string) {
	if !ownsConsole() {
		return
	}
	fmt.Print(msg)
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

// ownsConsole reports whether this process is the only one attached to its
// console, which indicates it was started from outside an existing terminal.
func ownsConsole() bool {
	// Pass a one-element buffer; the call returns the real number of attached
	// processes, which is all we need. A zero return means no console.
	var pids [1]uint32
	r, _, _ := procGetConsoleProcessList.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)),
	)
	return r == 1
}
