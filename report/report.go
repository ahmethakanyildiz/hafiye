package report

import (
	"encoding/json"
	"hafiye/scanner/util"
	"os"
	"sort"
	"strings"
)

// WriteSARIFReport findings'ten SARIF 2.1.0 üretir ve outFilename'e yazar.
func WriteSARIFReport(findings []util.Finding, outFilename string) error {
	// 1) Benzersiz artifact listesi + path -> index map'i üret
	artifactURIs, uriToIndex := buildArtifacts(findings)

	report := sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name: "Hafiye",
					},
				},
				Artifacts: buildSarifArtifacts(artifactURIs),
				Results:   make([]sarifResult, 0, len(findings)),
			},
		},
	}

	for _, f := range findings {
		startLine := f.Line
		if startLine <= 0 {
			// SARIF line numbers are 1-based; 0/negatif gelirse 1'e çekelim.
			startLine = 1
		}
		endLine := computeEndLine(startLine, f.LineText)

		uri := normalizePathToURI(f.Path)

		// Eğer bir şekilde artifacts listesine girmediyse index basmayalım (spec'e daha uygun)
		var idxPtr *int
		if idx, ok := uriToIndex[uri]; ok {
			idxCopy := idx
			idxPtr = &idxCopy
		}

		res := sarifResult{
			Message: sarifMessage{
				Text: f.Description,
			},
			RuleID: "Hardcoded Credentials",
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI:   uri,
							Index: idxPtr, // <-- index eklendi
						},
						Region: sarifRegion{
							StartLine: startLine,
							EndLine:   endLine,
							Snippet: sarifSnippet{
								Text: f.Secret,
							},
						},
					},
				},
			},
			PartialFingerprints: sarifPartialFingerprints{
				"InstanceId": f.InstanceId, // örneğinizle aynı key
			},
		}

		report.Runs[0].Results = append(report.Runs[0].Results, res)
	}

	// JSON yazımı (pretty)
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	// Dosyaya yaz
	return os.WriteFile(outFilename, b, 0o644)
}

func normalizePathToURI(path string) string {
	// SARIF için separator "/" olsun
	return strings.ReplaceAll(path, `\`, `/`)
}

// findings içindeki path'lerden benzersiz uri listesi ve uri->index map döndürür
func buildArtifacts(findings []util.Finding) ([]string, map[string]int) {
	seen := make(map[string]struct{}, len(findings))
	uris := make([]string, 0, 128)

	for _, f := range findings {
		u := normalizePathToURI(f.Path)
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		uris = append(uris, u)
	}

	// Stabil index için sıralamak iyi pratik (deterministic output)
	sort.Strings(uris)

	m := make(map[string]int, len(uris))
	for i, u := range uris {
		m[u] = i
	}
	return uris, m
}

func buildSarifArtifacts(artifactURIs []string) []sarifArtifact {
	out := make([]sarifArtifact, 0, len(artifactURIs))
	for _, u := range artifactURIs {
		out = append(out, sarifArtifact{
			Location: sarifArtifactLocation{
				URI: u,
			},
		})
	}
	return out
}

// startLine + (lineCount-1)
func computeEndLine(startLine int, lineText string) int {
	// CRLF -> LF normalize
	s := strings.ReplaceAll(lineText, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")

	if s == "" {
		return startLine
	}

	// satır sayısı = '\n' sayısı + 1
	lineCount := 1 + strings.Count(s, "\n")
	if lineCount <= 1 {
		return startLine
	}
	return startLine + (lineCount - 1)
}

/* ---------------- SARIF structs (min gerekli alanlar) ---------------- */

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Results   []sarifResult   `json:"results"`
	Tool      sarifTool       `json:"tool,omitempty"`
	Artifacts []sarifArtifact `json:"artifacts,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name string `json:"name"`
}

type sarifArtifact struct {
	Location sarifArtifactLocation `json:"location"`
}

type sarifResult struct {
	Message             sarifMessage             `json:"message"`
	RuleID              string                   `json:"ruleId"`
	Locations           []sarifLocation          `json:"locations"`
	PartialFingerprints sarifPartialFingerprints `json:"partialFingerprints,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI   string `json:"uri"`
	Index *int   `json:"index,omitempty"`
}

type sarifRegion struct {
	StartLine int          `json:"startLine"`
	EndLine   int          `json:"endLine"`
	Snippet   sarifSnippet `json:"snippet"`
	// startColumn / endColumn yok (istenmedi)
}

type sarifSnippet struct {
	Text string `json:"text"`
}

// SARIF spec'te partialFingerprints bir "property bag" gibi kullanılır.
// Örneğinizde "InstanceId" key'i ile gidiyor; o yüzden map en doğru yaklaşım.
type sarifPartialFingerprints map[string]string
