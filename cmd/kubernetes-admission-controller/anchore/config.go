package anchore

type AuthConfiguration struct {
	Users []Credential
}

type Credential struct {
	Username string
	Password string
}

type PolicyReference struct {
	Username string // TODO: These two values shouldn't be tied together.
	// We have use for Username in many more contexts than we do for PolicyBundleId.
	// Note that this change would impact user configurations.

	PolicyBundleId string
}
