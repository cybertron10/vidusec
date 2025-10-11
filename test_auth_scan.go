package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func main() {
	// Target URL
	url := "http://16.170.226.104:3000/"
	
	// Create HTTP client
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	
	// Create request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal("Error creating request:", err)
	}
	
	// Add the exact headers from Burp
	req.Header.Set("Host", "16.170.226.104:3000")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Referer", "http://16.170.226.104:3000/login")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cookie", "auth_token=eyJ1c2VybmFtZSI6ImFkbWluIiwidGltZXN0YW1wIjoxNzYwMTM0NTMyNzg0fQ%3D%3D.0a744181eb9abb78354c47480e60201561f005f0e6623d566540474da93e4daa")
	req.Header.Set("If-None-Match", `W/"785-199d007e1c9"`)
	req.Header.Set("If-Modified-Since", "Fri, 10 Oct 2025 21:30:01 GMT")
	req.Header.Set("Connection", "keep-alive")
	
	// Make the request
	fmt.Printf("Making request to: %s\n", url)
	fmt.Printf("Headers:\n")
	for name, values := range req.Header {
		for _, value := range values {
			fmt.Printf("  %s: %s\n", name, value)
		}
	}
	fmt.Printf("\n")
	
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("Error making request:", err)
	}
	defer resp.Body.Close()
	
	// Print response details
	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Response Headers:\n")
	for name, values := range resp.Header {
		for _, value := range values {
			fmt.Printf("  %s: %s\n", name, value)
		}
	}
	
	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error reading response body:", err)
	}
	
	fmt.Printf("\nResponse Body Length: %d bytes\n", len(body))
	fmt.Printf("Response Body Preview (first 500 chars):\n")
	if len(body) > 500 {
		fmt.Printf("%s...\n", string(body[:500]))
	} else {
		fmt.Printf("%s\n", string(body))
	}
	
	// Check if we got a successful response
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		fmt.Printf("\n✅ SUCCESS: Got successful response (status %d)\n", resp.StatusCode)
	} else {
		fmt.Printf("\n❌ FAILED: Got error response (status %d)\n", resp.StatusCode)
	}
}
