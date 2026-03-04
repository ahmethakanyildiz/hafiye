## HAFIYE: Secret Scanner
<img src="https://raw.githubusercontent.com/ahmethakanyildiz/hafiye/refs/heads/main/hafiye_logo.png" width="200">

Hafiye is a lightweight yet powerful secret scanning tool written in Go, designed to detect hardcoded credentials and sensitive data across source code repositories with high precision and low noise. It combines regex-based pattern detection, identifier-aware scanning, entropy and code-like heuristics, and optional machine learning-based false positive reduction to improve accuracy. Hafiye supports configurable rules, ignore mechanisms, cross-platform execution, and parallel scanning for performance. It generates standardized SARIF 2.1.0 reports for seamless integration with security platforms and CI/CD pipelines, while offering flexible CLI options for customization and automation.

### Usage
```

 ___  ___  ________  ________ ___      ___    ___ _______
|\  \|\  \|\   __  \|\  _____\\  \    |\  \  /  /|\  ___ \
\ \  \\\  \ \  \|\  \ \  \__/\ \  \   \ \  \/  / | \   __/|
 \ \   __  \ \   __  \ \   __\\ \  \   \ \    / / \ \  \_|/__
  \ \  \ \  \ \  \ \  \ \  \_| \ \  \   \/  /  /   \ \  \_|\ \
   \ \__\ \__\ \__\ \__\ \__\   \ \__\__/  / /      \ \_______\
    \|__|\|__|\|__|\|__|\|__|    \|__|\___/ /        \|_______|
                                     \|___|/
Hafiye - Secret Scanner (v1.3)

Usage:
  hafiye -d <dir> [options]

Options:
  -d,  --dir <path>                                                     Directory which will be scanned (required)
  -i,  --identifiers <file>                                             Identifiers file
  -p,  --patterns <file>                                                Pattern rules file
  -ip, --ignore-paths <file>                                            Ignore path rules file
  -in, --ignore-matches <file>                                          Ignore match rules file
  -cp, --common-passwords <file>                                        Common passwords file
  -o,  --out <file>                                                     SARIF output file (default: hafiye.sarif)
  -t,  --print-in-terminal                                              Print SARIF output to terminal
  -dm, --dont-mask                                                      Disable masking (prints secrets in cleartext)
  -ep, --enable-prefix-for-assign-idenitifers                           Enable prefix for assign identifiers (It can increase FPs)
  -th, --ml-threshold                                                   ML Threshold (It can increase FPs or FNs)
  -th, --disable-ml-verification-for-assign-identifiers                 Disable ML verification for assign identifiers (It will increase FPs significantly)

Examples:
  hafiye -d ./myproj/.
  hafiye --dir .\myproj\. --print-in-terminal
```

### Build

You can build Hafiye simply with this commands (in Windows):

for Windows
```
$env:GOOS="windows"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"; go build -o hafiye.exe ./cmd/hafiye
```

for Linux
```
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"; go build -o hafiye ./cmd/hafiye
```
