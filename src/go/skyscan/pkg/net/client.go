package net

import (
	"time"

	"github.com/valyala/fasthttp"
)

// Client is a wrapper around fasthttp.Client
type Client struct {
	client *fasthttp.Client
}

// NewClient creates a new high-performance HTTP client
func NewClient(timeout int) *Client {
	return &Client{
		client: &fasthttp.Client{
			MaxConnsPerHost:               2000,
			ReadTimeout:                   time.Duration(timeout) * time.Second,
			WriteTimeout:                  time.Duration(timeout) * time.Second,
			NoDefaultUserAgentHeader:      true, // We will rotate UAs manually if needed
			DisableHeaderNamesNormalizing: true,
		},
	}
}

// Check performs a HEAD/GET request to check for existence
func (c *Client) Check(url string) (int, int64, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.SetMethod(fasthttp.MethodHead) // Start with HEAD for speed

	err := c.client.Do(req, resp)
	if err != nil {
		return 0, 0, err
	}

	return resp.StatusCode(), int64(resp.Header.ContentLength()), nil
}

// GetBody performs a GET request and returns the body
func (c *Client) GetBody(url string) ([]byte, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.SetMethod(fasthttp.MethodGet)

	err := c.client.Do(req, resp)
	if err != nil {
		return nil, err
	}

	// Copy body because ReleaseResponse recycles it
	body := make([]byte, len(resp.Body()))
	copy(body, resp.Body())

	return body, nil
}
