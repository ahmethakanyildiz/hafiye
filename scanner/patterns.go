package scanner

import (
	"bufio"
	"fmt"
	"hafiye/scanner/util"
	"io"
	"os"
	"regexp"
	"strings"
)

func ScanPatterns(scanRoot string, paths []string, patternsConfigRef string, findings *[]util.Finding, workers int) error {
	if len(paths) == 0 {
		return nil
	}

	rules, err := loadRulesFromConfig(patternsConfigRef)
	if err != nil {
		return err
	}

	compiled, err := compileValueRegexes(rules)
	if err != nil {
		return err
	}

	if findings != nil && *findings == nil {
		*findings = make([]util.Finding, 0, 128)
	}

	err = util.RunScan(scanRoot, paths, workers, findings, func(absPath string, displayPath string, results chan<- util.Finding) error {
		return scanFileWithRegexes(absPath, displayPath, compiled, results)
	})
	if err != nil {
		return err
	}

	return nil
}

func loadRulesFromConfig(configRef string) ([]util.PatternRule, error) {
	b, src, err := util.ReadConfigBytes(configRef)
	if err != nil {
		return nil, fmt.Errorf("cannot read patterns (%s): %w", src, err)
	}
	rules, err := parseRuleBlocks(strings.NewReader(string(b)))
	if err != nil {
		return nil, fmt.Errorf("cannot parse patterns (%s): %w", src, err)
	}
	return rules, nil
}

func parseRuleBlocks(r io.Reader) ([]util.PatternRule, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024), 1024*1024)

	var (
		out    []util.PatternRule
		cur    util.PatternRule
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
		cur = util.PatternRule{}
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

func compileValueRegexes(rules []util.PatternRule) ([]util.IDRRule, error) {
	out := make([]util.IDRRule, 0, len(rules))
	for _, r := range rules {
		rx, err := regexp.Compile(r.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid regex in rule id=%q: %w", r.ID, err)
		}
		out = append(out, util.IDRRule{
			ID:          r.ID,
			Description: r.Description,
			RX:          rx,
		})
	}
	return out, nil
}

func scanFileWithRegexes(path string, displayPath string, rules []util.IDRRule, results chan<- util.Finding) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	lines, err := util.ReadAllLines(f)
	if err != nil {
		return err
	}

	fileText := strings.Join(lines, "\n")

	for _, cr := range rules {
		subIdx := cr.RX.FindAllStringSubmatchIndex(fileText, -1)
		if subIdx == nil {
			continue
		}

		for _, idx := range subIdx {
			secret, secretStartAbs, snippet, ok := extractSecretAndStart(fileText, lines, idx)
			if !ok {
				continue
			}
			if secret == "" || secretStartAbs < 0 {
				continue
			}

			lineNo0, _ := util.AbsOffsetToLineCol(lines, secretStartAbs)
			if lineNo0 < 0 || lineNo0 >= len(lines) {
				continue
			}

			instanceID := util.ComputeInstanceID(displayPath, snippet, secret, cr.ID)

			results <- util.Finding{
				Path:        displayPath,
				Line:        lineNo0 + 1,
				LineText:    lines[lineNo0],
				Secret:      secret,
				RuleID:      cr.ID,
				InstanceId:  instanceID,
				Description: cr.Description,
			}
		}
	}

	return nil
}

func extractSecretAndStart(fileText string, lines []string, idx []int) (string, int, string, bool) {
	if len(idx) < 2 || idx[0] < 0 || idx[1] < 0 {
		return "", -1, "", false
	}

	startAbs := idx[0]
	endAbs := idx[1]

	secret := fileText[startAbs:endAbs]
	if secret == "" {
		return "", -1, "", false
	}

	// --- snippet üretimi ---
	startLine0, _ := util.AbsOffsetToLineCol(lines, startAbs)
	endProbe := endAbs - 1
	if endProbe < startAbs {
		endProbe = startAbs
	}
	endLine0, _ := util.AbsOffsetToLineCol(lines, endProbe)

	if startLine0 < 0 || endLine0 < 0 {
		return "", -1, "", false
	}

	// 1 satır önce ve sonra
	winStart := startLine0 - 1
	if winStart < 0 {
		winStart = 0
	}

	winEnd := endLine0 + 1
	if winEnd >= len(lines) {
		winEnd = len(lines) - 1
	}

	snippet := strings.Join(lines[winStart:winEnd+1], "\n")

	return secret, startAbs, snippet, true
}
