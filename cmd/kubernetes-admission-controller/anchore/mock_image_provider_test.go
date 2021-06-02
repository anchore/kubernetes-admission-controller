package anchore

import "github.com/stretchr/testify/mock"

type mockImageProvider struct {
	mock.Mock
}

func (m *mockImageProvider) Get(string) (Image, error) {
	panic("shouldn't be needed for testing")
}

func (m *mockImageProvider) Analyze(imageReference string) error {
	args := m.Called(imageReference)
	return args.Error(0)
}

func (m *mockImageProvider) DoesPolicyCheckPass(string, string, string) (bool, error) {
	panic("shouldn't be needed for testing")
}
