package scan

import (
	"os/user"
	"regexp"
	"sort"
	"strconv"
)

type Match struct {
	UID  uint32 `json:"uid"`
	User string `json:"user"`
	PID  int    `json:"pid"`
	CWD  string `json:"cwd"`
	Exe  string `json:"exe"`
	FD   string `json:"fd"`
	Path string `json:"path"`
}

type Scanner interface {
	Scan(re *regexp.Regexp) ([]Match, int, error)
}

func sortMatches(matches []Match) {
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].PID != matches[j].PID {
			return matches[i].PID < matches[j].PID
		}
		return matches[i].FD < matches[j].FD
	})
}

func lookupUsername(cache map[uint32]string, uid uint32) string {
	if name, ok := cache[uid]; ok {
		return name
	}

	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		cache[uid] = "unknown"
		return "unknown"
	}
	cache[uid] = u.Username
	return u.Username
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
