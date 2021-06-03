package anchore

import "github.com/stretchr/testify/mock"

type mockImageBackend struct {
	mock.Mock
}

func (m *mockImageBackend) Get(string) (Image, error) {
	panic("shouldn't be needed for testing")
}

func (m *mockImageBackend) Analyze(imageReference string) error {
	args := m.Called(imageReference)
	return args.Error(0)
}

func (m *mockImageBackend) DoesPolicyCheckPass(string, string, string) (bool, error) {
	panic("shouldn't be needed for testing")
}
