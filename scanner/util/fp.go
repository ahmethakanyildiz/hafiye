package util

import (
	"encoding/json"
	"math"
	"regexp"
	"strings"
	"sync"

	randomforest "github.com/malaschitz/randomForest"

	"hafiye/defaultconfigs"
)

const embeddedModelPath = "configs/model.json"

type rfModelBundle struct {
	FeatureColumns []string        `json:"feature_columns"`
	ForestJSON     json.RawMessage `json:"forest_json"`
}

var (
	rfOnce   sync.Once
	rfForest randomforest.Forest
	rfErr    error
)

var FeatureColumns = []string{
	"len",
	"entropy",
	"letter_ratio",
	"digit_ratio",
	"code_like_symbol_ratio",
	"normal_symbol_ratio",
	"unique_ratio",
	"longest_same_char_run",
	"dot_chain_depth",
	"dash_chain_depth",
	"underscore_chain_depth",
	"like_function_call",
	"op_count",
	"has_string_concat",
	"has_closed_paranthesis_statement",
	"endswith_codelikespecial",
	"non_ascii_present",
	"common_ngram_ratio",
	"camel_transition_density",
	"class_change_ratio",
}

var likeFunctionCallRe = regexp.MustCompile(
	`(?:[A-Za-z_][A-Za-z0-9_]*)(?:\[[^\[\]]*\]|\.(?:[A-Za-z_][A-Za-z0-9_]*|\[[^\[\]]*\]))*\s*\(`,
)

var closedParenRe = regexp.MustCompile(`\([^\(\)]*\)|\[[^\[\]]*\]|\{[^\{\}]*\}`)

var twoCharOps = map[string]struct{}{
	"||": {}, "&&": {}, "??": {}, "?:": {}, "==": {}, "!=": {}, "<=": {}, ">=": {}, "->": {}, "=>": {}, "<<": {}, ">>": {},
}

var codeLikeSymbols = map[byte]struct{}{
	';': {}, '(': {}, '{': {}, '[': {}, ',': {},
}

var commonBigrams = map[string]struct{}{
	"th": {}, "he": {}, "in": {}, "er": {}, "an": {}, "re": {}, "on": {}, "at": {}, "en": {}, "nd": {},
	"ti": {}, "es": {}, "or": {}, "te": {}, "of": {}, "to": {}, "it": {}, "is": {}, "st": {}, "as": {},
	"hi": {}, "se": {}, "et": {}, "ou": {}, "ea": {}, "ng": {}, "ha": {},
}

var commonTrigrams = map[string]struct{}{
	"the": {}, "and": {}, "ing": {}, "ion": {}, "ent": {}, "her": {}, "tha": {}, "ere": {}, "tio": {}, "for": {},
	"nde": {}, "has": {}, "nce": {},
}

func FilterFindings(findings []Finding, commonPasswordsRef string, threshold float64) ([]Finding, error) {
	cps, errCps := LoadFromConfig(commonPasswordsRef)
	if errCps != nil {
		return nil, errCps
	}

	rfOnce.Do(loadRFModel)
	if rfErr != nil {
		return nil, rfErr
	}

	if threshold <= 0 {
		threshold = 0.5
	}

	kept := make([]Finding, 0, len(findings))

	for _, f := range findings {
		featObj := computeFeatures(f.Secret)

		feat := featObj.toFloat64Slice()
		votes := rfForest.Vote(feat)

		if len(votes) < 2 {
			continue
		}

		scoreSecret := votes[1]
		if f.RuleID != "assign" || scoreSecret >= threshold || isInCps(cps, f.Secret) {
			kept = append(kept, f)
		}
	}

	return kept, nil
}

func loadRFModel() {
	b, err := defaultconfigs.FS.ReadFile(embeddedModelPath)
	if err != nil {
		rfErr = err
		return
	}

	var bundle rfModelBundle
	if err := json.Unmarshal(b, &bundle); err != nil {
		rfErr = err
		return
	}

	if len(bundle.FeatureColumns) > 0 && !sameStringSlice(bundle.FeatureColumns, FeatureColumns) {
		rfErr = &json.UnsupportedValueError{
			Str: "model.feature_columns mismatch with util.FeatureColumns",
		}
		return
	}

	if err := rfForest.UnmarshalJSON(bundle.ForestJSON); err != nil {
		rfErr = err
		return
	}
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isInCps(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

func computeFeatures(raw string) rfFeatures {
	v := normalizeValue(raw)
	l := len(v)
	if l == 0 {
		return rfFeatures{}
	}

	digitCnt, alnumCnt, codeLikeCnt, letterCnt := 0, 0, 0, 0
	uniq := make(map[byte]struct{}, l)

	for i := 0; i < len(v); i++ {
		ch := v[i]
		if isASCIILetter(ch) {
			alnumCnt++
			letterCnt++
		} else if isASCIIDigit(ch) {
			digitCnt++
			alnumCnt++
		}
		if _, ok := codeLikeSymbols[ch]; ok {
			codeLikeCnt++
		}
		uniq[ch] = struct{}{}
	}

	return rfFeatures{
		Len:                           l,
		Entropy:                       shannonEntropyBitsPerChar(v),
		LetterRatio:                   float64(letterCnt) / float64(l),
		DigitRatio:                    float64(digitCnt) / float64(l),
		CodeLikeSymbolRatio:           float64(codeLikeCnt) / float64(l),
		NormalSymbolRatio:             float64(l-alnumCnt) / float64(l),
		UniqueRatio:                   float64(len(uniq)) / float64(l),
		LongestSameCharRun:            longestSameCharRun(v),
		DotChainDepth:                 dotChainDepth(v),
		DashChainDepth:                dashChainDepth(v),
		UnderscoreChainDepth:          underscoreChainDepth(v),
		LikeFunctionCall:              likeFunctionCallRe.FindStringIndex(v) != nil,
		OpCount:                       opCount(v),
		HasStringConcat:               hasStringConcat(v),
		HasClosedParanthesisStatement: hasClosedParanthesisStatement(v),
		EndsWithCodeLikeSpecial:       endsWithCodeLikeSpecial(v),
		NonASCIIPresent:               nonASCIIPresent(v),
		CommonNgramRatio:              commonNgramRatio(v),
		CamelTransitionDensity:        camelTransitionDensity(v),
		ClassChangeRatio:              ClassChangeRatio(v),
	}
}

func normalizeValue(s string) string {
	v := strings.TrimSpace(s)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			v = strings.TrimSpace(v[1 : len(v)-1])
		}
	}
	return v
}

func (f rfFeatures) toFloat64Slice() []float64 {
	return []float64{
		float64(f.Len),
		f.Entropy,
		f.LetterRatio,
		f.DigitRatio,
		f.CodeLikeSymbolRatio,
		f.NormalSymbolRatio,
		f.UniqueRatio,
		float64(f.LongestSameCharRun),
		float64(f.DotChainDepth),
		float64(f.DashChainDepth),
		float64(f.UnderscoreChainDepth),
		boolTo01(f.LikeFunctionCall),
		float64(f.OpCount),
		boolTo01(f.HasStringConcat),
		boolTo01(f.HasClosedParanthesisStatement),
		boolTo01(f.EndsWithCodeLikeSpecial),
		boolTo01(f.NonASCIIPresent),
		f.CommonNgramRatio,
		f.CamelTransitionDensity,
		f.ClassChangeRatio,
	}
}

func boolTo01(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

//HELPERS

func shannonEntropyBitsPerChar(s string) float64 {
	if s == "" {
		return 0.0
	}
	b := []byte(s)
	if len(b) == 0 {
		return 0.0
	}
	var freq [256]int
	for _, by := range b {
		freq[by]++
	}
	n := float64(len(b))
	ent := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * (math.Log(p) / math.Log(2))
	}
	return ent
}

func isASCIILetter(b byte) bool { return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') }
func isASCIIDigit(b byte) bool  { return b >= '0' && b <= '9' }

func longestSameCharRun(s string) int {
	if s == "" {
		return 0
	}
	best, cur := 1, 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			cur++
			if cur > best {
				best = cur
			}
		} else {
			cur = 1
		}
	}
	return best
}

func isASCIILower(b byte) bool { return b >= 'a' && b <= 'z' }
func isASCIIUpper(b byte) bool { return b >= 'A' && b <= 'Z' }

func camelTransitionDensity(s string) float64 {
	for i := 0; i < len(s); i++ {
		if !isASCIILetter(s[i]) {
			return 0.0
		}
	}
	if len(s) < 2 {
		return 0.0
	}
	trans := 0
	prev := s[0]
	for i := 1; i < len(s); i++ {
		cur := s[i]
		if isASCIILower(prev) && isASCIIUpper(cur) {
			trans++
		}
		prev = cur
	}
	return float64(trans) / float64(len(s)-1)
}

func chainDepthBySep(s string, sep byte) int {
	parts := strings.Split(s, string(sep))
	best, cur := 0, 0
	for _, p := range parts {
		if p == "" {
			cur = 0
			continue
		}
		if cur == 0 {
			cur = 1
		} else {
			cur++
		}
		if cur > best {
			best = cur
		}
	}
	return best
}

func dotChainDepth(s string) int {
	return chainDepthBySep(s, '.')
}

func dashChainDepth(s string) int {
	return chainDepthBySep(s, '-')
}

func underscoreChainDepth(s string) int {
	return chainDepthBySep(s, '_')
}

func opCount(s string) int {
	cnt := 0
	i := 0
	for i < len(s) {
		if i+1 < len(s) {
			if _, ok := twoCharOps[s[i:i+2]]; ok {
				cnt++
				i += 2
				continue
			}
		}
		i++
	}
	return cnt
}

func hasStringConcat(s string) bool {
	patterns := []string{
		`+"`, `"+`,
		`+'`, `'+`,
		`+ +`, "+\t+",
		`' + '`, `" + "`,
	}
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func hasClosedParanthesisStatement(s string) bool {
	return closedParenRe.FindStringIndex(s) != nil
}

func endsWithCodeLikeSpecial(s string) bool {
	if s == "" {
		return false
	}
	last := s[len(s)-1]
	return last == ';' || last == '(' || last == '[' || last == '{' || last == ','
}

func nonASCIIPresent(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

func commonNgramRatio(s string) float64 {
	t := strings.ToLower(s)
	if len(t) < 2 {
		return 0.0
	}
	total, hit := 0, 0

	for i := 0; i < len(t)-1; i++ {
		bg := t[i : i+2]
		total++
		if _, ok := commonBigrams[bg]; ok {
			hit++
		}
	}
	if len(t) >= 3 {
		for i := 0; i < len(t)-2; i++ {
			tg := t[i : i+3]
			total++
			if _, ok := commonTrigrams[tg]; ok {
				hit++
			}
		}
	}
	if total == 0 {
		return 0.0
	}
	return float64(hit) / float64(total)
}

func charClass(b byte) byte {
	if isASCIILetter(b) {
		return 'L'
	}
	if isASCIIDigit(b) {
		return 'D'
	}
	return 'O'
}

func ClassChangeRatio(s string) float64 {
	if len(s) < 2 {
		return 0.0
	}
	changes := 0
	prev := charClass(s[0])
	for i := 1; i < len(s); i++ {
		cur := charClass(s[i])
		if cur != prev {
			changes++
			prev = cur
		}
	}
	return float64(changes) / float64(len(s)-1)
}
