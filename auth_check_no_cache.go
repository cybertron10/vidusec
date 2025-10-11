package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	// Target URL
	url := "http://16.170.226.104:3000/"
	
	// Create HTTP client with shorter timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	
	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal("Error creating request:", err)
	}
	
	// Add headers from Burp BUT REMOVE conditional headers
	req.Header.Set("Host", "16.170.226.104:3000")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Referer", "http://16.170.226.104:3000/login")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cookie", "auth_token=eyJ1c2VybmFtZSI6ImFkbWluIiwidGltZXN0YW1wIjoxNzYwMTM0NTMyNzg0fQ%3D%3D.0a744181eb9abb78354c47480e60201561f005f0e6623d566540474da93e4daa")
	// REMOVED: If-None-Match and If-Modified-Since headers
	req.Header.Set("Connection", "keep-alive")
	
	// Make the request
	fmt.Printf("Making request to: %s (without conditional headers)\n", url)
	
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Error making request:", err)
	}
	defer resp.Body.Close()
	
	// Print response details
	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Code: %d\n", resp.StatusCode)
	
	// Check if we got a successful response
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Printf("✅ SUCCESS: Got successful response\n")
	} else if resp.StatusCode == 401 {
		fmt.Printf("❌ AUTHENTICATION FAILED: 401 Unauthorized\n")
	} else if resp.StatusCode == 403 {
		fmt.Printf("❌ ACCESS FORBIDDEN: 403 Forbidden\n")
	} else if resp.StatusCode == 304 {
		fmt.Printf("⚠️  NOT MODIFIED: 304 (cached response)\n")
	} else {
		fmt.Printf("❌ FAILED: Got error response (status %d)\n", resp.StatusCode)
	}
	
	// Print some key headers
	fmt.Printf("\nKey Response Headers:\n")
	fmt.Printf("  Content-Type: %s\n", resp.Header.Get("Content-Type"))
	fmt.Printf("  Content-Length: %s\n", resp.Header.Get("Content-Length"))
	fmt.Printf("  Set-Cookie: %s\n", resp.Header.Get("Set-Cookie"))
}
