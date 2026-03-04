package scanner

import (
	"fmt"
	"hafiye/scanner/util"
	"os"
	"regexp"
	"strings"
)

func ScanIdentifiers(scanRoot string, paths []string, identifiersConfigRef string, enablePrefixForAssIdentifiers bool, ignoreMatchesConfigRef string, findings *[]util.Finding, workers int) error {
	if len(paths) == 0 {
		return nil
	}

	ids, err := util.LoadFromConfig(identifiersConfigRef)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}

	idAlternation := buildIDAlternation(ids)
	rules, err := compileIdentifierRegexes(idAlternation, enablePrefixForAssIdentifiers)
	if err != nil {
		return err
	}

	ignoreRules, err := loadIgnoreRulesFromConfig(ignoreMatchesConfigRef)
	if err != nil {
		return err
	}

	if findings != nil && *findings == nil {
		*findings = make([]util.Finding, 0, 128)
	}

	err = util.RunScan(scanRoot, paths, workers, findings, func(absPath string, displayPath string, results chan<- util.Finding) error {
		return scanFileWithIdentifierRegexes(absPath, displayPath, rules, ignoreRules, results)
	})
	if err != nil {
		return err
	}

	return nil
}

func buildIDAlternation(ids []string) string {
	escaped := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		escaped = append(escaped, regexp.QuoteMeta(id))
	}
	return strings.Join(escaped, "|")
}

func compileIdentifierRegexes(idAlt string, enablePrefixForAssIdentifiers bool) ([]util.CompiledIdentifierRule, error) {
	var assignRegex string = ""
	if enablePrefixForAssIdentifiers {
		assignRegex = `(?i)^.*(?:"((?:IDLIST))"|'((?:IDLIST))'|((?:IDLIST)))\s*(?::|===|==|=)\s*(?:"([^"]*)"|'([^']*)'|([^\s]+))`
	} else {
		assignRegex = `(?i)(?:^|[^A-Za-z0-9_\-])(?:"((?:IDLIST))"|'((?:IDLIST))'|((?:IDLIST)))\s*(?::|===|==|=)\s*(?:"([^"]*)"|'([^']*)'|([^\s]+))`
	}
	const (
		kindAssign  = "assign"
		kindXMLElem = "xml_elem"
		kindXMLKV   = "xml_kv_attr"
	)

	templates := []struct {
		id         string
		desc       string
		kind       string
		templateRX string
	}{ // Be careful when you add new regex. If regexes are similar, reappear warning appears even there is no duplicate.
		{
			id:         "IDENT_ASSIGN",
			desc:       "Identifier-based assignment",
			kind:       kindAssign,
			templateRX: assignRegex,
		},
		{
			id:         "IDENT_XML_ELEM",
			desc:       "Identifier-based XML/HTML element content",
			kind:       kindXMLElem,
			templateRX: `(?i)<\s*((?:IDLIST))\s*>\s*([^<\s][^<]*?)\s*<\s*/\s*((?:IDLIST))\s*>`,
		},
		{
			id:         "IDENT_XML_KV_ATTR",
			desc:       "Identifier-based XML/HTML key/value attribute pair (key|name=ID, value=secret)",
			kind:       kindXMLKV,
			templateRX: `(?is)<[^>]*?\b(key|name|id|param)\s*=\s*(?:"((?:IDLIST))"|'((?:IDLIST))'|((?:IDLIST)))[^>]*?\bvalue\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>]+))`,
		},
	}

	out := make([]util.CompiledIdentifierRule, 0, len(templates))
	for _, t := range templates {
		rxText := strings.ReplaceAll(t.templateRX, "IDLIST", idAlt)
		rx, err := regexp.Compile(rxText)
		if err != nil {
			return nil, fmt.Errorf("invalid identifier regex %s: %w", t.id, err)
		}
		out = append(out, util.CompiledIdentifierRule{
			ID:          t.id,
			Description: t.desc,
			RX:          rx,
			Kind:        t.kind,
		})
	}

	return out, nil
}

func loadIgnoreRulesFromConfig(configRef string) ([]util.IDRRule, error) {
	b, src, err := util.ReadConfigBytes(configRef)
	if err != nil {
		return nil, fmt.Errorf("cannot read ignore rules (%s): %w", src, err)
	}

	lines := strings.Split(string(b), "\n")

	var (
		inRule  bool
		curID   string
		curDesc string
		curRX   string
		out     []util.IDRRule
	)

	flush := func(lineNo int) error {
		if !inRule {
			return nil
		}
		if strings.TrimSpace(curID) == "" || strings.TrimSpace(curRX) == "" {
			return fmt.Errorf("ignore rule missing required fields near line %d (id and regex are required)", lineNo)
		}
		rx, err := regexp.Compile(curRX)
		if err != nil {
			return fmt.Errorf("invalid ignore rule regex id=%q: %w", curID, err)
		}
		out = append(out, util.IDRRule{ID: curID, Description: curDesc, RX: rx})
		curID, curDesc, curRX = "", "", ""
		inRule = false
		return nil
	}

	for i, raw := range lines {
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || strings.HasPrefix(line, ";") {
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
			continue
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
			curID = val
		case "description":
			curDesc = val
		case "regex":
			curRX = val
		}
	}

	if err := flush(len(lines) + 1); err != nil {
		return nil, err
	}

	return out, nil
}

func scanFileWithIdentifierRegexes(path string, displayPath string, rules []util.CompiledIdentifierRule, ignoreRules []util.IDRRule, results chan<- util.Finding) error {
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

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		for _, r := range rules {
			if r.Kind != "assign" {
				continue
			}

			subIdx := r.RX.FindAllStringSubmatchIndex(line, -1)
			if subIdx == nil {
				continue
			}

			for _, idx := range subIdx {
				identifier, secret, secretStart, ok := extractIdentifierAndSecret(line, r.Kind, idx)
				if !ok {
					continue
				}

				identifierNorm := strings.ToLower(strings.TrimSpace(identifier))
				if identifierNorm == "" || secret == "" || secretStart < 0 {
					continue
				}

				if isIgnoredSecret(secret, ignoreRules) {
					continue
				}

				instanceID := util.ComputeInstanceID(displayPath, lines[i], secret, r.Kind)

				results <- util.Finding{
					Path:        displayPath,
					Line:        i + 1,
					LineText:    line,
					Secret:      secret,
					RuleID:      r.Kind,
					InstanceId:  instanceID,
					Description: r.Description,
				}
			}
		}
	}

	for _, r := range rules {
		if r.Kind != "xml_elem" && r.Kind != "xml_kv_attr" {
			continue
		}

		subIdx := r.RX.FindAllStringSubmatchIndex(fileText, -1)
		if subIdx == nil {
			continue
		}

		for _, idx := range subIdx {
			identifier, secret, secretStartAbs, ok := extractIdentifierAndSecret(fileText, r.Kind, idx)
			fullText, okForFM := ExtractMatchOrWholeLine(fileText, lines, idx)
			if !ok || !okForFM {
				continue
			}

			identifierNorm := strings.ToLower(strings.TrimSpace(identifier))
			if identifierNorm == "" || secret == "" || secretStartAbs < 0 {
				continue
			}

			if isIgnoredSecret(secret, ignoreRules) {
				continue
			}

			lineNo0, _ := util.AbsOffsetToLineCol(lines, secretStartAbs)
			if lineNo0 < 0 || lineNo0 >= len(lines) {
				continue
			}

			instanceID := util.ComputeInstanceID(displayPath, fullText, secret, r.Kind)

			results <- util.Finding{
				Path:        displayPath,
				Line:        lineNo0 + 1,
				LineText:    lines[lineNo0],
				Secret:      secret,
				RuleID:      r.Kind,
				InstanceId:  instanceID,
				Description: r.Description,
			}
		}
	}

	return nil
}

func extractIdentifierAndSecret(line string, kind string, idx []int) (identifier string, secret string, secretStart int, ok bool) {
	switch kind {
	case "xml_elem":
		// groups: 1=openTag, 2=value, 3=closeTag
		// full + 3 groups => idx len should be >= 8
		if len(idx) < 8 {
			return "", "", -1, false
		}
		// g1
		if idx[2] < 0 || idx[3] < 0 {
			return "", "", -1, false
		}
		// g2
		if idx[4] < 0 || idx[5] < 0 {
			return "", "", -1, false
		}
		// g3
		if idx[6] < 0 || idx[7] < 0 {
			return "", "", -1, false
		}

		openTag := strings.TrimSpace(line[idx[2]:idx[3]])
		closeTag := strings.TrimSpace(line[idx[6]:idx[7]])
		if openTag == "" || closeTag == "" {
			return "", "", -1, false
		}
		if !strings.EqualFold(openTag, closeTag) {
			return "", "", -1, false
		}

		identifier = openTag
		secretStart = idx[4]
		secret = strings.TrimSpace(line[idx[4]:idx[5]])
		if secret == "" {
			return "", "", -1, false
		}
		return identifier, secret, secretStart, true
	case "xml_kv_attr":
		// full + 7 groups => idx len >= 16 (2 + 2*7)
		if len(idx) < 16 {
			return "", "", -1, false
		}

		// identifier (ID) is first present among g2/g3/g4:
		// g1 is key-attr name (key|name|id|param) - we don't need it as identifier
		if idx[4] >= 0 && idx[5] >= 0 { // g2
			identifier = line[idx[4]:idx[5]]
		} else if idx[6] >= 0 && idx[7] >= 0 { // g3
			identifier = line[idx[6]:idx[7]]
		} else if idx[8] >= 0 && idx[9] >= 0 { // g4
			identifier = line[idx[8]:idx[9]]
		} else {
			return "", "", -1, false
		}
		identifier = strings.TrimSpace(identifier)
		if identifier == "" {
			return "", "", -1, false
		}

		// secret is first present among g5/g6/g7
		if idx[10] >= 0 && idx[11] >= 0 { // g5
			secretStart = idx[10]
			secret = line[idx[10]:idx[11]]
		} else if idx[12] >= 0 && idx[13] >= 0 { // g6
			secretStart = idx[12]
			secret = line[idx[12]:idx[13]]
		} else if idx[14] >= 0 && idx[15] >= 0 { // g7
			secretStart = idx[14]
			secret = line[idx[14]:idx[15]]
		} else {
			return "", "", -1, false
		}

		secret = strings.TrimSpace(secret)
		if secret == "" {
			return "", "", -1, false
		}

		return identifier, secret, secretStart, true
	default:
		// IDENT_ASSIGN (merged JSON + assignment)
		// groups: 1="ID", 2='ID', 3=ID, 4="secret", 5='secret', 6=secret
		// full + 6 groups => idx len must be >= 14 (2 + 2*6)
		if len(idx) < 14 {
			return "", "", -1, false
		}

		// identifier: first present among g1/g2/g3
		if idx[2] >= 0 && idx[3] >= 0 {
			identifier = line[idx[2]:idx[3]]
		} else if idx[4] >= 0 && idx[5] >= 0 {
			identifier = line[idx[4]:idx[5]]
		} else if idx[6] >= 0 && idx[7] >= 0 {
			identifier = line[idx[6]:idx[7]]
		} else {
			return "", "", -1, false
		}
		identifier = strings.TrimSpace(identifier)
		if identifier == "" {
			return "", "", -1, false
		}

		// secret: first present among g4/g5/g6
		if idx[8] >= 0 && idx[9] >= 0 {
			secretStart = idx[8]
			secret = line[idx[8]:idx[9]]
		} else if idx[10] >= 0 && idx[11] >= 0 {
			secretStart = idx[10]
			secret = line[idx[10]:idx[11]]
		} else if idx[12] >= 0 && idx[13] >= 0 {
			secretStart = idx[12]
			secret = line[idx[12]:idx[13]]
		} else {
			return "", "", -1, false
		}

		secret = strings.TrimSpace(secret)
		if secret == "" {
			return "", "", -1, false
		}

		return identifier, secret, secretStart, true
	}
}

func ExtractMatchOrWholeLine(text string, lines []string, idx []int) (out string, ok bool) {
	if len(idx) < 2 || idx[0] < 0 || idx[1] < 0 || idx[1] <= idx[0] {
		return "", false
	}

	full := text[idx[0]:idx[1]]

	// Multiline mi?
	if strings.Contains(full, "\n") {
		return full, true
	}

	// Tek satır → bulunduğu satırı tamamen döndür
	lineNo0, _ := util.AbsOffsetToLineCol(lines, idx[0])
	if lineNo0 < 0 || lineNo0 >= len(lines) {
		return "", false
	}

	return lines[lineNo0], true
}

func isIgnoredSecret(secret string, rules []util.IDRRule) bool {
	if secret == "" || len(rules) == 0 {
		return false
	}
	for _, r := range rules {
		if r.RX.MatchString(secret) {
			return true
		}
	}
	return false
}
