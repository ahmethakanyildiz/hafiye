package util

import "regexp"

// FINDING STRUCT
type Finding struct {
	Path        string
	Line        int
	LineText    string
	Secret      string
	RuleID      string
	InstanceId  string
	Description string
}

// RANDOM FOREST FEATURES
type rfFeatures struct {
	Len                           int
	Entropy                       float64
	LetterRatio                   float64
	DigitRatio                    float64
	CodeLikeSymbolRatio           float64
	NormalSymbolRatio             float64
	UniqueRatio                   float64
	LongestSameCharRun            int
	DotChainDepth                 int
	DashChainDepth                int
	UnderscoreChainDepth          int
	LikeFunctionCall              bool
	OpCount                       int
	HasStringConcat               bool
	HasClosedParanthesisStatement bool
	EndsWithCodeLikeSpecial       bool
	NonASCIIPresent               bool
	CommonNgramRatio              float64
	CamelTransitionDensity        float64
	ClassChangeRatio              float64
}

//IDR RULE
type IDRRule struct {
	ID          string
	Description string
	RX          *regexp.Regexp
}

//PATTERN RULE
type PatternRule struct {
	ID          string
	Description string
	Value       string
}

//COMPILED IDENTIFIER RULE
type CompiledIdentifierRule struct {
	ID          string
	Description string
	RX          *regexp.Regexp
	Kind        string
}
