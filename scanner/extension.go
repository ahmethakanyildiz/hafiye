package scanner

import "hafiye/scanner/util"

func BuildKeyFileFindings(keyFiles []string) []util.Finding {
	findings := make([]util.Finding, 0, len(keyFiles))

	for _, path := range keyFiles {
		f := util.Finding{
			Path:        path,
			Line:        0,
			LineText:    " ",
			Secret:      " ",
			RuleID:      "keyfile",
			InstanceId:  util.ComputeInstanceID(path, " ", " ", "keyfile"),
			Description: "Sensitive key/keystore file detected based on file extension.",
		}
		findings = append(findings, f)
	}

	return findings
}
