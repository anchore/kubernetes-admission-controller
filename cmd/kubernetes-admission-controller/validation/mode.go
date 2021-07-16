package validation

type Mode string

const (
	PolicyGateMode   Mode = "policy"
	AnalysisGateMode Mode = "analysis"
	BreakGlassMode   Mode = "breakglass"
)
