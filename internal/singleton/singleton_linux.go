//go:build linux

package singleton

import (
	"errors"
	"os"
	"strconv"
	"syscall"
)

// sameBinaryPIDs returns the pids of every process other than this one whose executable
// is the same file as self, read from the /proc/<pid>/exe symlink.
func sameBinaryPIDs(self string) ([]int, error) {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	me := os.Getpid()
	var pids []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == me {
			continue // not a pid dir, or ourselves
		}
		exe, err := os.Readlink("/proc/" + e.Name() + "/exe")
		if err != nil {
			continue // kernel thread, a process we may not inspect, or already gone
		}
		if resolvePath(exe) == self {
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
