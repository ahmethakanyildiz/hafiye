package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"hafiye/report"
	"hafiye/scanner"
	"hafiye/scanner/util"
	"hafiye/walker"
)

type CLIOptions struct {
	Dir                              string
	Identifiers                      string
	Patterns                         string
	IgnorePaths                      string
	IgnoreMatches                    string
	CommonPasswords                  string
	Out                              string
	PrintTerminal                    bool
	DontMask                         bool
	EnablePrefixForAssignIdentifiers bool
	MLThreshold                      float64
	DisableMLVerification            bool
}

func main() {
	// DIR
	dirShort := flag.String("d", "", "Directory which will be scanned (shorthand)")
	dirLong := flag.String("dir", "", "Directory which will be scanned")

	// IDENTIFIERS
	identShort := flag.String("i", "", "Identifiers file (shorthand)")
	identLong := flag.String("identifiers", "", "Identifiers file")

	// PATTERNS
	patShort := flag.String("p", "", "Pattern rules file (shorthand)")
	patLong := flag.String("patterns", "", "Pattern rules file")

	// IGNORE PATHS
	ipShort := flag.String("ip", "", "Ignore path rules file (shorthand)")
	ipLong := flag.String("ignore-paths", "", "Ignore path rules file")

	// IGNORE MATCHES
	inShort := flag.String("in", "", "Ignore match rules file (shorthand)")
	inLong := flag.String("ignore-matches", "", "Ignore match rules file")

	// IGNORE MATCHES
	cpShort := flag.String("cp", "", "Common passwords file (shorthand)")
	cpLong := flag.String("common-passwords", "", "Common passwords file")

	// OUT
	outShort := flag.String("o", "hafiye.sarif", "SARIF output file (shorthand)")
	outLong := flag.String("out", "", "SARIF output file")

	// TERMINAL
	tShort := flag.Bool("t", false, "Print SARIF output to terminal (shorthand)")
	tLong := flag.Bool("print-in-terminal", false, "Print SARIF output to terminal")

	// DONT MASK
	dmShort := flag.Bool("dm", false, "Disable masking (shorthand)")
	dmLong := flag.Bool("dont-mask", false, "Disable masking")

	//ENABLE PREFIX FOR ASSIGN IDENTIFIER
	epShort := flag.Bool("ep", false, "Enable prefix for assign identifiers (shorthand)")
	epLong := flag.Bool("enable-prefix-for-assign-idenitifers", false, "Enable prefix for assign identifiers")

	//ML OPTIONS
	thShort := flag.Float64("th", 0.4, "ML threshold (shorthand)")
	thLong := flag.Float64("ml-threshold", 0.4, "ML threshold")

	dvShort := flag.Bool("dv", false, "Disable ML verification for assign identifiers (shorthand)")
	dvLong := flag.Bool("disable-ml-verification-for-assign-identifiers", false, "Disable ML verification for assign identifiers")

	flag.Usage = func() {
		fmt.Println(`
 ___  ___  ________  ________ ___      ___    ___ _______      
|\  \|\  \|\   __  \|\  _____\\  \    |\  \  /  /|\  ___ \     
\ \  \\\  \ \  \|\  \ \  \__/\ \  \   \ \  \/  / | \   __/|    
 \ \   __  \ \   __  \ \   __\\ \  \   \ \    / / \ \  \_|/__  
  \ \  \ \  \ \  \ \  \ \  \_| \ \  \   \/  /  /   \ \  \_|\ \ 
   \ \__\ \__\ \__\ \__\ \__\   \ \__\__/  / /      \ \_______\
    \|__|\|__|\|__|\|__|\|__|    \|__|\___/ /        \|_______|
                                     \|___|/`)
		fmt.Fprintln(os.Stderr, "Hafiye - Secret Scanner (v1.2)")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  hafiye -d <dir> [options]")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Options:")
		fmt.Fprintln(os.Stderr, "  -d,  --dir <path>                               			Directory which will be scanned (required)")
		fmt.Fprintln(os.Stderr, "  -i,  --identifiers <file>                       			Identifiers file")
		fmt.Fprintln(os.Stderr, "  -p,  --patterns <file>                          			Pattern rules file")
		fmt.Fprintln(os.Stderr, "  -ip, --ignore-paths <file>                      			Ignore path rules file")
		fmt.Fprintln(os.Stderr, "  -in, --ignore-matches <file>                    			Ignore match rules file")
		fmt.Fprintln(os.Stderr, "  -cp, --common-passwords <file>                  			Common passwords file")
		fmt.Fprintln(os.Stderr, "  -o,  --out <file>                               			SARIF output file (default: hafiye.sarif)")
		fmt.Fprintln(os.Stderr, "  -t,  --print-in-terminal                        			Print SARIF output to terminal")
		fmt.Fprintln(os.Stderr, "  -dm, --dont-mask                                			Disable masking (prints secrets in cleartext)")
		fmt.Fprintln(os.Stderr, "  -ep, --enable-prefix-for-assign-idenitifers     			Enable prefix for assign identifiers (It can increase FPs)")
		fmt.Fprintln(os.Stderr, "  -th, --ml-threshold                             			ML Threshold (It can increase FPs or FNs)")
		fmt.Fprintln(os.Stderr, "  -th, --disable-ml-verification-for-assign-identifiers    Disable ML verification for assign identifiers (It will increase FPs significantly)")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  hafiye -d ./myproj/.")
		fmt.Fprintln(os.Stderr, "  hafiye --dir .\\myproj\\. --print-in-terminal")
		fmt.Fprintln(os.Stderr)
	}

	enforceNoSingleDashLongOptions()
	flag.Parse()

	//CHECKS FOR AMBIGIOUS
	if err := disallowAmbiguousString("dir", "d", "dir"); err != nil {
		fatalUsage(err)
	}
	if err := disallowAmbiguousString("identifiers", "i", "identifiers"); err != nil {
		fatalUsage(err)
	}
	if err := disallowAmbiguousString("patterns", "p", "patterns"); err != nil {
		fatalUsage(err)
	}
	if err := disallowAmbiguousString("ignore-paths", "ip", "ignore-paths"); err != nil {
		fatalUsage(err)
	}
	if err := disallowAmbiguousString("ignore-matches", "in", "ignore-matches"); err != nil {
		fatalUsage(err)
	}
	if err := disallowAmbiguousString("common-passwords", "cp", "common-passwords"); err != nil {
		fatalUsage(err)
	}
	if err := disallowAmbiguousString("out", "o", "out"); err != nil {
		fatalUsage(err)
	}
	if err := disallowAmbiguousBool("print-in-terminal", "t", "print-in-terminal"); err != nil {
		fatalUsage(err)
	}
	if err := disallowAmbiguousBool("dont-mask", "dm", "dont-mask"); err != nil {
		fatalUsage(err)
	}
	if err := disallowAmbiguousBool("enable-prefix-for-assign-idenitifers", "ep", "enable-prefix-for-assign-idenitifers"); err != nil {
		fatalUsage(err)
	}
	if err := disallowAmbiguousFloat("th", "ml-threshold", "th", "ml-threshold"); err != nil {
		fatalUsage(err)
	}
	if err := disallowAmbiguousBool("disable-ml-verification-for-assign-identifiers", "dv", "disable-ml-verification-for-assign-identifiers"); err != nil {
		fatalUsage(err)
	}

	opts := CLIOptions{
		Dir:                              pickString("dir", "d", "dir", *dirShort, *dirLong),
		Identifiers:                      pickString("identifiers", "i", "identifiers", *identShort, *identLong),
		Patterns:                         pickString("patterns", "p", "patterns", *patShort, *patLong),
		IgnorePaths:                      pickString("ignore-paths", "ip", "ignore-paths", *ipShort, *ipLong),
		IgnoreMatches:                    pickString("ignore-matches", "in", "ignore-matches", *inShort, *inLong),
		CommonPasswords:                  pickString("common-passwords", "cp", "common-passwords", *cpShort, *cpLong),
		Out:                              pickString("out", "o", "out", *outShort, *outLong),
		PrintTerminal:                    pickBool("t", "print-in-terminal", *tShort, *tLong),
		DontMask:                         pickBool("dm", "dont-mask", *dmShort, *dmLong),
		EnablePrefixForAssignIdentifiers: pickBool("ep", "enable-prefix-for-assign-idenitifers", *epShort, *epLong),
		MLThreshold:                      pickFloat("th", "ml-threshold", *thShort, *thLong),
		DisableMLVerification:            pickBool("dv", "disable-ml-verification-for-assign-identifiers", *dvShort, *dvLong),
	}

	if opts.Dir == "" {
		fatalUsage(fmt.Errorf("missing required option: -d/--dir"))
	}

	opts.Identifiers = createConfigPath(opts.Identifiers, "configs/identifiers.txt")
	opts.Patterns = createConfigPath(opts.Patterns, "configs/patterns.regex")
	opts.IgnorePaths = createConfigPath(opts.IgnorePaths, "configs/ignore-paths.regex")
	opts.IgnoreMatches = createConfigPath(opts.IgnoreMatches, "configs/ignore-matches.regex")
	opts.CommonPasswords = createConfigPath(opts.CommonPasswords, "configs/common-passwords.txt")

	paths, keyFiles, err := walker.CollectFiles(opts.Dir, opts.IgnorePaths)
	if err != nil {
		fmt.Println(err)
	} else {
		//SCANNING STARTS HERE
		extFindings := scanner.BuildKeyFileFindings(keyFiles)
		var findings []util.Finding
		errPattern := scanner.ScanPatterns(opts.Dir, paths, opts.Patterns, &findings, 10)
		var findingsIdentifier []util.Finding
		errIdentifier := scanner.ScanIdentifiers(opts.Dir, paths, opts.Identifiers, opts.EnablePrefixForAssignIdentifiers, opts.IgnoreMatches, &findingsIdentifier, 10)

		if errPattern != nil || errIdentifier != nil {
			if errPattern != nil {
				fmt.Println(errPattern)
			}
			if errIdentifier != nil {
				fmt.Println(errIdentifier)
			}
		} else {
			util.DedupByPathLineText(&findings) // It removes same findings which are found with different patterns from pattern findings list
			var findingsIdentifierNew []util.Finding
			var errMl error
			if opts.DisableMLVerification {
				findingsIdentifierNew = findingsIdentifier
				errMl = nil
			} else {
				findingsIdentifierNew, errMl = util.FilterFindings(findingsIdentifier, opts.CommonPasswords, opts.MLThreshold)
			}
			findings = util.RemoveByPathLineText(findings, findingsIdentifierNew) // It removes same findings which are found with pattern and identifier FROM pattern findings list (It keeps identifier copy)
			if errMl != nil {
				fmt.Println(errMl)
			} else {
				allFindings := make([]util.Finding, 0, len(findings)+len(findingsIdentifierNew))
				allFindings = append(allFindings, findings...)
				allFindings = append(allFindings, findingsIdentifierNew...)
				allFindings = append(allFindings, extFindings...)
				util.DedupFindings(&allFindings) // It removes findings which has same instance id and keeps first one and add count to its description
				if !opts.DontMask {
					for i := range allFindings {
						allFindings[i].Secret = maskSecret(allFindings[i].Secret)
					}
				}
				if opts.PrintTerminal {
					fmt.Println(`
 ___  ___  ________  ________ ___      ___    ___ _______      
|\  \|\  \|\   __  \|\  _____\\  \    |\  \  /  /|\  ___ \     
\ \  \\\  \ \  \|\  \ \  \__/\ \  \   \ \  \/  / | \   __/|    
 \ \   __  \ \   __  \ \   __\\ \  \   \ \    / / \ \  \_|/__  
  \ \  \ \  \ \  \ \  \ \  \_| \ \  \   \/  /  /   \ \  \_|\ \ 
   \ \__\ \__\ \__\ \__\ \__\   \ \__\__/  / /      \ \_______\
    \|__|\|__|\|__|\|__|\|__|    \|__|\___/ /        \|_______|
                                     \|___|/
Hafiye - Secret Scanner (v1.2)`)
					if len(allFindings) == 0 {
						fmt.Println("Congratulations, there is no secret leak in your project!")
					} else {
						fmt.Printf("Findings (%d) --------------------------------------------------\n", len(allFindings))
						for _, f := range allFindings {
							fmt.Printf("RuleID: %s\n", f.RuleID)
							fmt.Printf("Path: %s\n", f.Path)
							fmt.Printf("Line: %d\n", f.Line)
							fmt.Printf("Secret: %s\n", f.Secret)
							fmt.Printf("Description: %s\n", f.Description)
							fmt.Println("---------------------------------------------------------------")
						}
					}
				} else {
					report.WriteSARIFReport(allFindings, opts.Out)
				}
			}
		}
	}
}

func enforceNoSingleDashLongOptions() {
	longNames := map[string]bool{
		"dir":                                  true,
		"identifiers":                          true,
		"patterns":                             true,
		"ignore-paths":                         true,
		"ignore-matches":                       true,
		"common-passwords":                     true,
		"out":                                  true,
		"print-in-terminal":                    true,
		"dont-mask":                            true,
		"enable-prefix-for-assign-idenitifers": true,
		"help":                                 true,
		"ml-threshold":                         true,
		"disable-ml-verification-for-assign-identifiers": true,
	}

	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			name := strings.TrimPrefix(arg, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
			}
			if longNames[name] {
				fatalUsage(fmt.Errorf("flag provided but not defined: %s", arg))
			}
		}
	}
}

func disallowAmbiguousString(name, shortName, longName string) error {
	shortProvided := wasProvided(shortName)
	longProvided := wasProvided(longName)

	if shortProvided && longProvided {
		return fmt.Errorf("ambiguous usage: use either -%s or --%s (not both)", shorthandOf(name), name)
	}
	return nil
}

func disallowAmbiguousFloat(shortName, longName, shorthand, long string) error {
	shortProvided := wasProvided(shortName)
	longProvided := wasProvided(longName)

	if shortProvided && longProvided {
		return fmt.Errorf("ambiguous usage: use either -%s or --%s (not both)", shorthand, long)
	}
	return nil
}

func disallowAmbiguousBool(name, shortName, longName string) error {
	shortProvided := wasProvided(shortName)
	longProvided := wasProvided(longName)

	if shortProvided && longProvided {
		return fmt.Errorf("ambiguous usage: use either -%s or --%s (not both)", shorthandOf(name), name)
	}
	return nil
}

func wasProvided(name string) bool {
	provided := false
	flag.CommandLine.Visit(func(f *flag.Flag) {
		if f.Name == name {
			provided = true
		}
	})
	return provided
}

func shorthandOf(name string) string {
	switch name {
	case "dir":
		return "d"
	case "identifiers":
		return "i"
	case "patterns":
		return "p"
	case "ignore-paths":
		return "ip"
	case "ignore-matches":
		return "in"
	case "common-passwords":
		return "cp"
	case "out":
		return "o"
	case "disable-ml-verification-for-assign-identifiers":
		return "dv"
	default:
		return name
	}
}

func fatalUsage(err error) {
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	flag.Usage()
	os.Exit(2)
}

func pickString(name, shortName, longName string, shortVal, longVal string) string {
	if wasProvided(longName) {
		return longVal
	}
	// long verilmediyse short'a düş
	return shortVal
}

func pickBool(shortName, longName string, shortVal, longVal bool) bool {
	if wasProvided(longName) {
		return longVal
	}
	return shortVal
}

func pickFloat(shortName, longName string, shortVal, longVal float64) float64 {
	if wasProvided(longName) {
		return longVal
	}
	return shortVal
}

func createConfigPath(userPath string, embeddedPath string) string {
	if userPath != "" {
		return "file:" + userPath
	}
	return "embedded:" + embeddedPath
}

func maskSecret(s string) string {
	if s == "" {
		return s
	}

	r := []rune(s)
	n := len(r)

	switch {
	case n > 20:
		return string(r[:10]) + "..." + string(r[n-10:])
	case n > 10 && n <= 20:
		return string(r[:5]) + "..." + string(r[n-5:])
	case n > 4 && n <= 10:
		return string(r[:2]) + "..." + string(r[n-2:])
	default: // n <= 4
		return s
	}
}
