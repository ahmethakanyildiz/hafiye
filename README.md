## HAFIYE: Secret Scanner
<img src="https://raw.githubusercontent.com/ahmethakanyildiz/hafiye/refs/heads/main/hafiye_banner.png">

Hafiye is a lightweight yet powerful secret scanning tool written in Go, designed to detect hardcoded credentials and sensitive data across source code repositories with high precision and low noise. It combines regex-based pattern detection, identifier-aware scanning, entropy and code-like heuristics, and optional machine learning-based false positive reduction to improve accuracy. Hafiye supports configurable rules, ignore mechanisms, cross-platform execution, and parallel scanning for performance. It generates standardized SARIF 2.1.0 reports for seamless integration with security platforms and CI/CD pipelines, while offering flexible CLI options for customization and automation.

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

### Background

Hafiye basically has three scanner types. The first decides based on file extension. When it sees extensions like .p12 or .pfx, it reports them directly as findings without inspecting the content. The second performs pattern-based scanning, meaning it returns anything that matches a regex. For pattern-based scanning, Gitleaks' token regexes were taken as the basis. The third type, called identifier, performs assignment-based scanning. It currently has three sub-features: **assign**, **XML element**, and **XML key-value** pair. All three of these features rely on regexes, and the identifiers are embedded into those regexes. These identifiers have default values, but they can also be customized through the identifiers parameter, where each line in the file is treated as a separate identifier. In the XML element method, for the password identifier, it captures an expression like **< password > my_secret < / password >** and extracts my_secret as the secret. A similar logic applies to the XML key-value pair method. In the assign type, for the password identifier, it looks for **password = my_secret** and extracts my_secret as the secret.

<img src="https://raw.githubusercontent.com/ahmethakanyildiz/hafiye/refs/heads/main/hafiye_logic.png">

The assign type of identifier method can produce a large number of false positives. In particular, it often reports many code fragments as findings. Because of this, false positive elimination was added for this category. A machine learning (ML) model was used for this purpose, and Random Forest was chosen as the model. Various features were defined, such as length, entropy, letter ratio, digit ratio, and dot split count, based on the assumption that some of them would be more common in real secrets while others would be more common in false positives. With the trained model, the aim was to filter out false positive findings that resemble code fragments, such as **edge.toString();** (although something like this could still technically be a secret, handling findings with this logic manually would require reviewing too many false positives. For users who prefer this more paranoid approach, false positive elimination was made optional and can be disabled. In that form, it can be thought of as something like a version of Gitleaks without entropy.). You can access the mini label-train-predict project prepared for the main project at [hafiye-label-train-predict](https://github.com/ahmethakanyildiz/hafiye-label-train-predict), and with predict, you can check whether a given secret would be considered a real secret or a false positive according to Hafiye's false positive elimination logic as:

```
go run . predict --model model.json --value YOUR_SECRET
```
