package validation

type Mode string

const (
	PolicyGateMode   Mode = "policy"
	AnalysisGateMode Mode = "analysis"
	BreakGlassMode   Mode = "breakglass"
)

func IsValidMode(mode Mode) bool {
	switch mode {
	case PolicyGateMode, AnalysisGateMode, BreakGlassMode:
		return true
	}

	return false
}
