package util

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// HASH FUNCTION
func ComputeInstanceID(path string, snippet string, secret string, ruleId string) string {
	var b strings.Builder
	b.Grow(len(path) + len(snippet) + len(secret) + len(ruleId) + 3)

	b.WriteString(path)
	b.WriteByte('|')
	b.WriteString(snippet)
	b.WriteByte('|')
	b.WriteString(secret)
	b.WriteByte('|')
	b.WriteString(ruleId)

	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func DedupFindings(findings *[]Finding) {
	if findings == nil || len(*findings) == 0 {
		return
	}

	firstIndex := make(map[string]int, len(*findings))
	dupCount := make(map[string]int, 64)

	for i, f := range *findings {
		if f.InstanceId == "" {
			continue
		}
		if _, ok := firstIndex[f.InstanceId]; !ok {
			firstIndex[f.InstanceId] = i
		}
		dupCount[f.InstanceId]++
	}

	for id, cnt := range dupCount {
		if cnt <= 1 {
			continue
		}
		fi := firstIndex[id]
		more := cnt - 1
		msg := fmt.Sprintf("There are exactly %d more rule identical occurrences of this finding in this file.", more)

		if (*findings)[fi].Description == "" {
			(*findings)[fi].Description = msg
		} else {
			(*findings)[fi].Description = (*findings)[fi].Description + " (" + msg + ")"
		}
	}

	out := make([]Finding, 0, len(*findings))
	seen := make(map[string]bool, len(firstIndex))

	for _, f := range *findings {
		if f.InstanceId == "" {
			out = append(out, f)
			continue
		}
		if !seen[f.InstanceId] {
			seen[f.InstanceId] = true
			out = append(out, f)
		}
	}

	*findings = out
}

func DedupByPathLineText(findings *[]Finding) {
	if findings == nil || len(*findings) == 0 {
		return
	}

	makeKey := func(f Finding) string {
		return f.Path + "\x00" + strconv.Itoa(f.Line) + "\x00" + f.LineText
	}

	seen := make(map[string]struct{}, len(*findings))
	out := make([]Finding, 0, len(*findings))

	for _, f := range *findings {
		key := makeKey(f)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}

	*findings = out
}

func RemoveByPathLineText(a, b []Finding) []Finding {
	makeKey := func(f Finding) string {
		return f.Path + "\x00" + strconv.Itoa(f.Line) + "\x00" + f.LineText
	}

	toRemove := make(map[string]struct{}, len(b))
	for _, f := range b {
		toRemove[makeKey(f)] = struct{}{}
	}

	result := make([]Finding, 0, len(a))
	for _, f := range a {
		if _, exists := toRemove[makeKey(f)]; !exists {
			result = append(result, f)
		}
	}

	return result
}
