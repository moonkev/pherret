//go:build linux

package scan

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type linuxProcScanner struct{}

func NewScanner() Scanner {
	return &linuxProcScanner{}
}

func (s *linuxProcScanner) Scan(re *regexp.Regexp) ([]Match, int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, 0, err
	}

	uidUserCache := map[uint32]string{}
	var out []Match
	skipped := 0

	for _, e := range entries {
		if !e.IsDir() || !isNumeric(e.Name()) {
			continue
		}

		pid, _ := strconv.Atoi(e.Name())
		procRoot := filepath.Join("/proc", e.Name())

		uid, err := readUID(procRoot)
		if err != nil {
			skipped++
			continue
		}

		username := lookupUsername(uidUserCache, uid)
		cwd := readLinkOrUnknown(filepath.Join(procRoot, "cwd"))
		exe := readLinkOrUnknown(filepath.Join(procRoot, "exe"))

		fdDir := filepath.Join(procRoot, "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			skipped++
			continue
		}

		for _, fdEntry := range fdEntries {
			fdPath := filepath.Join(fdDir, fdEntry.Name())
			target, err := os.Readlink(fdPath)
			if err != nil {
				// FD can disappear between ReadDir and Readlink while the process runs.
				continue
			}
			if !re.MatchString(target) {
				continue
			}

			out = append(out, Match{
				UID:      uid,
				User:     username,
				PID:      pid,
				CWD:      cwd,
				Exe:      exe,
				FD:       fdEntry.Name(),
				OpenPath: target,
			})
		}
	}

	sortMatches(out)
	return out, skipped, nil
}

func readUID(procRoot string) (uint32, error) {
	statusPath := filepath.Join(procRoot, "status")
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return 0, err
	}
	return parseUIDFromStatus(data)
}

func parseUIDFromStatus(data []byte) (uint32, error) {
	lines := bytes.Split(data, []byte{'\n'})
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("Uid:")) {
			fields := strings.Fields(string(line))
			if len(fields) < 2 {
				return 0, errors.New("malformed Uid line")
			}
			n, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				return 0, err
			}
			return uint32(n), nil
		}
	}
	return 0, errors.New("Uid line not found")
}

func readLinkOrUnknown(path string) string {
	v, err := os.Readlink(path)
	if err != nil {
		return "<unavailable>"
	}
	return v
}
