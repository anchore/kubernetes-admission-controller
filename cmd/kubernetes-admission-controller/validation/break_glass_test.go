package validation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBreakGlass(t *testing.T) {
	result := BreakGlass()
	assert.True(t, result.IsValid)
}
