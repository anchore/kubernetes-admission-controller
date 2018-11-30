package client


// Generic HTTP API error response
type ApiErrorResponse struct {

	Code int32 `json:"code,omitempty"`

	ErrorType string `json:"error_type,omitempty"`

	Message string `json:"message,omitempty"`

	// Details structure for additional information about the error if available. Content and structure will be error specific.
	Detail *interface{} `json:"detail,omitempty"`
}

// Properties for common pagination handling to be included in any wrapping object that needs pagination elements
type PaginationProperties struct {

	// The page number returned (should match the requested page query string param)
	Page string `json:"page,omitempty"`

	// True if additional pages exist (page + 1) or False if this is the last page
	NextPage string `json:"next_page,omitempty"`

	// The number of items sent in this response
	ReturnedCount int32 `json:"returned_count,omitempty"`
}

// System status response
type StatusResponse struct {

	Available bool `json:"available,omitempty"`

	Busy bool `json:"busy,omitempty"`

	Up bool `json:"up,omitempty"`

	Message string `json:"message,omitempty"`

	Version string `json:"version,omitempty"`

	DbVersion string `json:"db_version,omitempty"`

	Detail *interface{} `json:"detail,omitempty"`
}

// System status response
type SystemStatusResponse struct {

	ServiceStates *ServiceList `json:"service_states,omitempty"`
}
