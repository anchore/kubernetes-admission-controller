package client

import (
	"time"
)

// A login credential mapped to a user identity. For password credentials, the username to present for Basic auth is the user's username from the user record
type AccessCredential struct {

	// The type of credential
	Type_ string `json:"type"`

	// The credential value (e.g. the password)
	Value string `json:"value"`

	// The timestamp of creation of the credential
	CreatedAt string `json:"created_at,omitempty"`

	// The uuid of the user that created this credential
	CreatedBy string `json:"created_by,omitempty"`
}

// Account information
type Account struct {

	// The account identifier, not updatable after creation
	Name string `json:"name"`

	// The user type (admin vs user). If not specified in a POST request, 'user' is default
	Type_ string `json:"type,omitempty"`

	// State of the account. Disabled accounts prevent member users from logging in, deleting accounts are disabled and pending deletion and will be removed once all owned resources are garbage collected by the system
	State string `json:"state,omitempty"`

	// Optional email address associated with the account
	Email string `json:"email,omitempty"`

	// The timestamp when the account was created
	CreatedAt time.Time `json:"created_at,omitempty"`

	// The timestamp of the last update to the account metadata itself (not users or creds)
	LastUpdated time.Time `json:"last_updated,omitempty"`

	// The uuid of the user that created this account
	CreatedBy string `json:"created_by,omitempty"`
}

// A username, password pair that can be used to authenticate with the service as a specific user
type User struct {

	// The username to authenticate with
	Username string `json:"username"`

	// The timestampt the user record was created
	CreatedAt time.Time `json:"created_at,omitempty"`

	// The timestamp of the last update to this record
	LastUpdated time.Time `json:"last_updated,omitempty"`

	// The uuid of the user that created this user
	CreatedBy string `json:"created_by,omitempty"`
}

// An account to create/add to the system. If already exists will return 400.
type AccountCreationRequest struct {

	// The account name to use. This will identify the account and must be globally unique in the system.
	Name string `json:"name"`

	// An optional email to associate with the account for contact purposes
	Email string `json:"email,omitempty"`
}

type AccountList []Account

// A summary of account status
type AccountStatus struct {

	// The status of the account
	State string `json:"state,omitempty"`
}

type CredentialList []AccessCredential

// A payload for creating a new user, includes the username and password in a single request
type UserCreationRequest struct {

	// The username to create
	Username string `json:"username"`

	// The initial password for the user, must be at least 6 characters, up to 128
	Password string `json:"password"`
}

type UserList []User
