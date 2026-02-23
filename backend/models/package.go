package models

type Package struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
	LockFile    string `json:"lock_file"`
	Category    string `json:"category"`
	// Additional fields for the response
	Hits        int    `json:"hits"`
	Status      string `json:"status"`
	ServiceType string `json:"service_type"`
	ServiceName string `json:"service_name"`
}
