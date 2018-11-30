package client

import (
	"time"
)

type FeedGroupMetadata struct {

	Name string `json:"name,omitempty"`

	CreatedAt time.Time `json:"created_at,omitempty"`

	LastSync time.Time `json:"last_sync,omitempty"`

	RecordCount int32 `json:"record_count,omitempty"`
}

// Metadata on a single feed based on what the engine finds from querying the endpoints
type FeedMetadata struct {

	// name of the feed
	Name string `json:"name,omitempty"`

	// Date the metadata record was created in engine (first seen on source)
	CreatedAt time.Time `json:"created_at,omitempty"`

	// Date the metadata was last updated
	UpdatedAt time.Time `json:"updated_at,omitempty"`

	Groups []FeedGroupMetadata `json:"groups,omitempty"`

	LastFullSync time.Time `json:"last_full_sync,omitempty"`
}
