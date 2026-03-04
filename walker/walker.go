package walker

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"hafiye/defaultconfigs"
	"hafiye/gutil"
)

type Rule struct {
	ID          string
	Description string
	Value       string
}

type byteReader struct{ b []byte }

func CollectFiles(rootDir string, ignoreConfigRef string) ([]string, []string, error) {
	ignoreRegexes, err := loadIgnorePathRegexes(ignoreConfigRef)
	if err != nil {
		return nil, nil, err
	}

	var files []string
	var keyFiles []string

	keyExts := []string{
		".pfx",
		".p12",
		".p8",
		".pkcs8",
		".pkcs12",
		".key",
		".ppk",
		".pvk",
		".snk",
		".jks",
		".keystore",
		".bcfks",
		".kdb",
		".sth",
		".ewallet.p12",
	}

	scanRootAbs, rootBase, errAbs := gutil.GetScanRootAbsAndRootBase(rootDir)
	if errAbs != nil {
		return nil, nil, errAbs
	}

	err = filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			fmt.Fprintf(os.Stderr, "WARNING: cannot access path: %s (%v)\n", path, walkErr)
			return nil
		}

		if isSymlink(d) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		// normalize: Windows '\' -> '/'
		norm := filepath.ToSlash(path)

		if matchAny(ignoreRegexes, norm) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			return nil
		}

		lowerName := strings.ToLower(norm)
		for _, kext := range keyExts {
			if strings.HasSuffix(lowerName, kext) {
				keyFiles = append(keyFiles, gutil.MakeDisplayPath(scanRootAbs, rootBase, path))
				return nil
			}
		}

		files = append(files, path)
		return nil
	})

	if err != nil {
		return nil, nil, err
	}
	return files, keyFiles, nil
}

func loadIgnorePathRegexes(ignoreConfigRef string) ([]*regexp.Regexp, error) {
	b, src, err := readConfigBytes(ignoreConfigRef)
	if err != nil {
		return nil, fmt.Errorf("cannot read ignore-paths (%s): %w", src, err)
	}

	parsed, err := parseRuleBlocks(bytesReader(b))
	if err != nil {
		return nil, fmt.Errorf("cannot parse ignore-paths (%s): %w", src, err)
	}

	var out []*regexp.Regexp
	for _, rule := range parsed {
		rx, err := regexp.Compile(rule.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid regex in ignore-paths (%s) rule id=%q: %w", src, rule.ID, err)
		}
		out = append(out, rx)
	}
	return out, nil
}

func readConfigBytes(configRef string) ([]byte, string, error) {
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

func parseRuleBlocks(r io.Reader) ([]Rule, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024), 1024*1024)

	var (
		out    []Rule
		cur    Rule
		inRule bool
	)

	flush := func(lineNo int) error {
		if !inRule {
			return nil
		}
		if strings.TrimSpace(cur.ID) == "" || strings.TrimSpace(cur.Value) == "" {
			return fmt.Errorf("rule missing required fields near line %d (id and value are required)", lineNo)
		}
		out = append(out, cur)
		cur = Rule{}
		inRule = false
		return nil
	}

	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		if line == "[[rule]]" {
			if err := flush(lineNo); err != nil {
				return nil, err
			}
			inRule = true
			continue
		}

		if !inRule {
			return nil, fmt.Errorf("line %d: found key-value outside of [[rule]] block: %q", lineNo, line)
		}

		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("line %d: expected 'key = value' but got: %q", lineNo, line)
		}

		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])

		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}

		switch key {
		case "id":
			cur.ID = val
		case "description":
			cur.Description = val
		case "value":
			cur.Value = val
		default:
			return nil, fmt.Errorf("line %d: unknown key %q (allowed: id, description, value)", lineNo, key)
		}
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}

	if err := flush(lineNo); err != nil {
		return nil, err
	}

	return out, nil
}

func bytesReader(b []byte) *byteReader { return &byteReader{b: b} }
func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

func isSymlink(d fs.DirEntry) bool {
	return d.Type()&fs.ModeSymlink != 0
}

func matchAny(rxs []*regexp.Regexp, s string) bool {
	for _, rx := range rxs {
		if rx.MatchString(s) {
			return true
		}
	}
	return false
}
