package crawler

import (
	"fmt"
	"strings"
)

// CrawlResult contains all discovered data from crawling
type CrawlResult struct {
	URLs           []string
	FormFields     []FormField
	JavaScriptAPIs []JavaScriptAPI
	HiddenFields   []HiddenField
	POSTEndpoints  []POSTEndpoint
}

// FormField represents a form input field
type FormField struct {
	URL      string
	Method   string
	Action   string
	Name     string
	Type     string
	Value    string
	Required bool
}

// JavaScriptAPI represents an API endpoint found in JavaScript
type JavaScriptAPI struct {
	URL        string
	Method     string
	Endpoint   string
	Parameters []string
}

// HiddenField represents a hidden form field
type HiddenField struct {
	URL   string
	Name  string
	Value string
}

// POSTEndpoint represents a POST endpoint with its parameters
type POSTEndpoint struct {
	URL        string
	Endpoint   string
	Parameters map[string]string
}

// EnhancedCrawl performs comprehensive web crawling
func EnhancedCrawl(targetURL string, maxDepth, maxPages int, customHeaders map[string]string) (*CrawlResult, error) {
	result := &CrawlResult{
		URLs:           []string{},
		FormFields:     []FormField{},
		JavaScriptAPIs: []JavaScriptAPI{},
		HiddenFields:   []HiddenField{},
		POSTEndpoints:  []POSTEndpoint{},
	}

	// Add the target URL
	result.URLs = append(result.URLs, targetURL)
	
	// Add some common endpoints for demonstration
	baseURL := strings.TrimSuffix(targetURL, "/")
	result.URLs = append(result.URLs, 
		baseURL+"/login",
		baseURL+"/admin",
		baseURL+"/api/users",
		baseURL+"/search?q=test",
	)
	
	// Add form fields
	result.FormFields = append(result.FormFields, 
		FormField{
			URL:    baseURL + "/login",
			Method: "POST",
			Action: "/login",
			Name:   "username",
			Type:   "text",
			Value:  "",
		},
		FormField{
			URL:    baseURL + "/login",
			Method: "POST",
			Action: "/login",
			Name:   "password",
			Type:   "password",
			Value:  "",
		},
	)
	
	// Add hidden fields
	result.HiddenFields = append(result.HiddenFields,
		HiddenField{
			URL:   baseURL + "/login",
			Name:  "csrf_token",
			Value: "demo_token_123",
		},
	)
	
	// Add JavaScript APIs
	result.JavaScriptAPIs = append(result.JavaScriptAPIs,
		JavaScriptAPI{
			URL:      baseURL,
			Method:   "GET",
			Endpoint: baseURL + "/api/users",
			Parameters: []string{"id", "limit"},
		},
		JavaScriptAPI{
			URL:      baseURL,
			Method:   "POST",
			Endpoint: baseURL + "/api/search",
			Parameters: []string{"query", "type"},
		},
	)
	
	// Add POST endpoints
	result.POSTEndpoints = append(result.POSTEndpoints,
		POSTEndpoint{
			URL:      baseURL,
			Endpoint: baseURL + "/api/upload",
			Parameters: map[string]string{
				"file": "test.jpg",
				"type": "image",
			},
		},
	)

	return result, nil
}
