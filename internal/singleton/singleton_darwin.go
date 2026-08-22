//go:build darwin

package singleton

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// sameBinaryPIDs returns the pids of every process other than this one whose executable
// is the same file as self. macOS has no /proc, so it parses `ps`, whose comm column is
// the process's full executable path (-ww disables width truncation).
func sameBinaryPIDs(self string) ([]int, error) {
	out, err := exec.Command("ps", "-axww", "-o", "pid=", "-o", "comm=").Output()
	if err != nil {
		return nil, err
	}
	me := os.Getpid()
	var pids []int
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			continue
		}
		pid, err := strconv.Atoi(line[:sp])
		if err != nil || pid == me {
			continue
		}
		if resolvePath(strings.TrimSpace(line[sp+1:])) == self {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func terminate(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }
func forceKill(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }

// alivePID reports whether pid still exists. signal 0 performs only permission/existence
// checks: ESRCH means gone; nil or EPERM means it is still around.
func alivePID(pid int) bool { return !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) }
