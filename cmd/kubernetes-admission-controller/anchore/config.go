package anchore

type AuthConfiguration struct {
	Users []Credential
}

type Credential struct {
	Username string
	Password string
}

type ClientConfiguration struct {
	Username       string
	PolicyBundleId string
}
