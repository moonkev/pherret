//go:build darwin

package scan

/*
#cgo LDFLAGS: -lproc
#include <libproc.h>
#include <stdlib.h>
#include <string.h>

// Returns the number of bytes needed to list all FDs for pid, or -1 on error.
static int list_fds_size(int pid) {
    return proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
}

// Fills buf (capacity cap) with proc_fdinfo structs. Returns bytes written or -1.
static int list_fds(int pid, struct proc_fdinfo *buf, int cap) {
    return proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buf, cap);
}

// Resolves a vnode FD to a full path. Returns 0 on success, -1 on error.
static int fd_vnode_path(int pid, int fd, char *out, int outlen) {
    struct vnode_fdinfowithpath info;
    memset(&info, 0, sizeof(info));
    int r = proc_pidinfo(pid, PROC_PIDFDVNODEPATHINFO, (uint64_t)fd,
                         &info, PROC_PIDFDVNODEPATHINFO_SIZE);
    if (r <= 0) return -1;
    strlcpy(out, info.pvip.vip_path, outlen);
    return 0;
}

// Reads the current working directory path. Returns 0 on success, -1 on error.
static int pid_cwd(int pid, char *out, int outlen) {
    struct proc_vnodepathinfo info;
    memset(&info, 0, sizeof(info));
    int r = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0,
                         &info, PROC_PIDVNODEPATHINFO_SIZE);
    if (r <= 0) return -1;
    strlcpy(out, info.pvi_cdir.vip_path, outlen);
    return 0;
}

// Reads the executable path. Returns 0 on success, -1 on error.
static int pid_exe(int pid, char *out) {
    int r = proc_pidpath(pid, out, PROC_PIDPATHINFO_MAXSIZE);
    return r > 0 ? 0 : -1;
}

// Reads the real UID for a pid. Returns -1 on error.
static int pid_uid(int pid) {
    struct proc_bsdinfo info;
    int r = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, PROC_PIDTBSDINFO_SIZE);
    if (r <= 0) return -1;
    return (int)info.pbi_ruid;
}
*/
import "C"

import (
	"fmt"
	"regexp"
	"unsafe"

	"golang.org/x/sys/unix"
)

type darwinNativeScanner struct{}

func NewScanner() Scanner {
	return &darwinNativeScanner{}
}

func (s *darwinNativeScanner) Scan(re *regexp.Regexp) ([]Match, int, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list processes: %w", err)
	}

	uidUserCache := map[uint32]string{}
	var out []Match
	skipped := 0

	for _, kp := range procs {
		pid := int(kp.Proc.P_pid)
		if pid <= 0 {
			continue
		}

		uid := uint32(kp.Eproc.Pcred.P_ruid)
		username := lookupUsername(uidUserCache, uid)
		cwd := readDarwinCWD(pid)
		exe := readDarwinExe(pid)

		hits, err := listDarwinVnodeFDs(pid, re)
		if err != nil {
			skipped++
			continue
		}

		for _, h := range hits {
			out = append(out, Match{
				UID:  uid,
				User: username,
				PID:  pid,
				CWD:  cwd,
				Exe:  exe,
				FD:   h.fd,
				Path: h.path,
			})
		}
	}

	sortMatches(out)
	return out, skipped, nil
}

type fdHit struct {
	fd   string
	path string
}

func listDarwinVnodeFDs(pid int, re *regexp.Regexp) ([]fdHit, error) {
	needed := C.list_fds_size(C.int(pid))
	if needed < 0 {
		return nil, fmt.Errorf("proc_pidinfo LISTFDS failed for pid %d", pid)
	}
	if needed == 0 {
		return nil, nil
	}

	fdSize := C.int(unsafe.Sizeof(C.struct_proc_fdinfo{}))
	// Pad by one entry to handle new FDs opened between the two calls.
	buf := make([]C.struct_proc_fdinfo, int(needed)/int(fdSize)+1)

	written := C.list_fds(C.int(pid), &buf[0], C.int(int(needed)+int(fdSize)))
	if written <= 0 {
		return nil, fmt.Errorf("proc_pidinfo LISTFDS fill failed for pid %d", pid)
	}

	count := int(written) / int(fdSize)
	pathBuf := make([]C.char, 4096) // MAXPATHLEN

	var hits []fdHit
	for i := 0; i < count; i++ {
		fi := buf[i]
		if fi.proc_fdtype != C.PROX_FDTYPE_VNODE {
			continue
		}

		if C.fd_vnode_path(C.int(pid), C.int(fi.proc_fd), &pathBuf[0], C.int(len(pathBuf))) != 0 {
			continue
		}

		path := C.GoString(&pathBuf[0])
		if path == "" || !re.MatchString(path) {
			continue
		}

		hits = append(hits, fdHit{
			fd:   fmt.Sprintf("%d", int(fi.proc_fd)),
			path: path,
		})
	}

	return hits, nil
}

func readDarwinCWD(pid int) string {
	buf := make([]C.char, 4096)
	if C.pid_cwd(C.int(pid), &buf[0], C.int(len(buf))) != 0 {
		return "<unavailable>"
	}
	return C.GoString(&buf[0])
}

func readDarwinExe(pid int) string {
	buf := make([]C.char, 4096)
	if C.pid_exe(C.int(pid), &buf[0]) != 0 {
		return "<unavailable>"
	}
	return C.GoString(&buf[0])
}
