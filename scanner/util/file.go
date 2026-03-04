package util

import (
	"bufio"
	"fmt"
	"hafiye/defaultconfigs"
	"io"
	"io/fs"
	"os"
	"strings"
)

// FILE FUNCTIONS
func ReadAllLines(r io.Reader) ([]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func LoadFromConfig(configRef string) ([]string, error) {
	b, src, err := ReadConfigBytes(configRef)
	if err != nil {
		return nil, fmt.Errorf("cannot read identifiers (%s): %w", src, err)
	}

	rawLines := strings.Split(string(b), "\n")
	out := make([]string, 0, len(rawLines))

	for _, ln := range rawLines {
		s := strings.TrimSpace(ln)
		if s == "" {
			continue
		}
		out = append(out, s)
	}

	return out, nil
}

func ReadConfigBytes(configRef string) ([]byte, string, error) {
	if strings.HasPrefix(configRef, "file:") {
		p := strings.TrimPrefix(configRef, "file:")
		b, err := os.ReadFile(p)
		return b, "file:" + p, err
	} else if strings.HasPrefix(configRef, "embedded:") {
		p := strings.TrimPrefix(configRef, "embedded:")
		b, err := fs.ReadFile(defaultconfigs.FS, p)
		return b, "embedded:" + p, err
	} else {
		return nil, "", fmt.Errorf("invalid config source: %s", configRef)
	}
}

func AbsOffsetToLineCol(lines []string, abs int) (lineNo0 int, col int) {
	if abs < 0 {
		return -1, -1
	}
	remain := abs
	for i := 0; i < len(lines); i++ {
		lineLen := len(lines[i])
		if remain <= lineLen {
			return i, remain
		}
		remain -= lineLen
		if i != len(lines)-1 {
			remain -= 1 // '\n'
		}
		if remain < 0 {
			return -1, -1
		}
	}
	return -1, -1
}
