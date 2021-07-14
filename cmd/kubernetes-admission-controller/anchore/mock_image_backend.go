package anchore

import "github.com/stretchr/testify/mock"

type MockImageBackend struct {
	mock.Mock
}

func (m *MockImageBackend) Get(asUser Credential, imageReference string) (Image, error) {
	args := m.Called(asUser, imageReference)
	return args.Get(0).(Image), args.Error(1)
}

func (m *MockImageBackend) Analyze(asUser Credential, imageReference string) error {
	args := m.Called(asUser, imageReference)
	return args.Error(0)
}

func (m *MockImageBackend) DoesPolicyCheckPass(asUser Credential, imageDigest, imageTag, policyBundleID string) (bool, error) {
	args := m.Called(asUser, imageDigest, imageTag, policyBundleID)
	return args.Bool(0), args.Error(1)
}
