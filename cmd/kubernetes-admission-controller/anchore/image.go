package anchore

type Image struct {
	Digest         string
	AnalysisStatus string
}

const ImageStatusAnalyzed = "analyzed"
