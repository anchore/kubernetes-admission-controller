package anchore

import "fmt"

type AuthConfiguration struct {
	Users []Credential
}

type Credential struct {
	Username string
	Password string
}

func SelectUserCredential(users []Credential, selectedUsername string) (Credential, error) {
	for _, user := range users {
		if user.Username == selectedUsername {
			return user, nil
		}
	}

	return Credential{}, fmt.Errorf("no user credentials provided for username %q", selectedUsername)
}

type PolicyReference struct {
	Username string // TODO: These two values shouldn't be tied together.
	// We have use for Username in many more contexts than we do for PolicyBundleId.
	// Note that this change would impact user configurations.

	PolicyBundleId string
}
