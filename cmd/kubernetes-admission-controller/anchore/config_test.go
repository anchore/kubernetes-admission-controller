package anchore

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSelectUserCredential(t *testing.T) {
	users := []Credential{
		{Username: "admin", Password: "admin-password"},
		{Username: "second-user", Password: "second-user-password"},
	}

	testCases := []struct {
		name               string
		users              []Credential
		selectedUsername   string
		expectedCredential Credential
		isErrorExpected    bool
	}{
		{
			name:               "returns the credential matching the selected username",
			users:              users,
			selectedUsername:   "second-user",
			expectedCredential: Credential{Username: "second-user", Password: "second-user-password"},
			isErrorExpected:    false,
		},
		{
			name:               "errors when the selected username has no configured credential",
			users:              users,
			selectedUsername:   "missing-user",
			expectedCredential: Credential{},
			isErrorExpected:    true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			credential, err := SelectUserCredential(testCase.users, testCase.selectedUsername)

			assert.Equal(t, testCase.expectedCredential, credential)

			if testCase.isErrorExpected {
				// The caller (Hook.evaluateImage) turns this error into a denial, so
				// the error must identify the username that had no credential.
				assert.ErrorContains(t, err, testCase.selectedUsername)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
