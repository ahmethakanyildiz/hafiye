package gutil

import "path/filepath"

func GetScanRootAbsAndRootBase(scanRoot string) (string, string, error) {
	scanRootAbs, err := filepath.Abs(scanRoot)
	if err != nil {
		return "", "", err
	}
	scanRootAbs = filepath.Clean(scanRootAbs)

	rootBase := filepath.Base(scanRootAbs)

	return scanRootAbs, rootBase, err
}

func MakeDisplayPath(rootAbs, rootBase, filePath string) string {
	absFile, err := filepath.Abs(filePath)
	if err != nil {
		return filepath.Clean(filePath)
	}

	rel, err := filepath.Rel(rootAbs, absFile)
	if err != nil {
		return filepath.Clean(absFile)
	}

	return filepath.Join(rootBase, rel)
}

func NormalizePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return filepath.Clean(abs)
}
