package httpclassifier

import (
	"bytes"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type RequestClass int

const (
	ClassUnknown    RequestClass = iota
	ClassLegitimate
	ClassMalicious
)

var httpMethods = map[string]bool{
	"GET":     true,
	"HEAD":    true,
	"POST":    true,
	"PUT":     true,
	"DELETE":  true,
	"OPTIONS": true,
	"PATCH":   true,
	"TRACE":   true,
	"CONNECT": true,
}

var httpVersions = map[string]bool{
	"HTTP/1.0": true,
	"HTTP/1.1": true,
	"HTTP/2":   true,
	"HTTP/2.0": true,
	"HTTP/3":   true,
	"HTTP/3.0": true,
}

type Config struct {
	LegitimateRequests []string `yaml:"legitimate_requests"`
}

type Classifier struct {
	exact    map[string]bool
	prefixes []string
}

func LoadFromFile(path string) (*Classifier, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return build(cfg), nil
}

func build(cfg Config) *Classifier {
	c := &Classifier{
		exact: make(map[string]bool),
	}
	for _, entry := range cfg.LegitimateRequests {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if strings.HasSuffix(entry, "*") {
			c.prefixes = append(c.prefixes, strings.TrimSuffix(entry, "*"))
		} else {
			c.exact[entry] = true
		}
	}
	return c
}

func IsValidHTTPRequest(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	end := bytes.IndexByte(data, '\n')
	if end == -1 {
		end = len(data)
	}
	firstLine := data[:end]
	for _, b := range firstLine {
		if b < 0x20 && b != '\r' && b != '\t' {
			return false
		}
		if b > 0x7E {
			return false
		}
	}

	line := strings.TrimSpace(string(firstLine))
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return false
	}

	method, path, version := parts[0], parts[1], parts[2]

	if !httpMethods[strings.ToUpper(method)] {
		return false
	}

	if !httpVersions[strings.ToUpper(version)] {
		return false
	}

	if path != "*" && !strings.HasPrefix(path, "/") {
		return false
	}

	if len(path) == 0 {
		return false
	}

	return true
}

func (c *Classifier) Classify(firstChunk []byte) (class RequestClass, method, path string) {
	if !IsValidHTTPRequest(firstChunk) {
		return ClassUnknown, "", ""
	}

	method, path = extractMethodAndPath(firstChunk)
	if method == "" || path == "" {
		return ClassUnknown, "", ""
	}

	key := strings.ToLower(method + " " + path)

	if c.exact[key] {
		return ClassLegitimate, method, path
	}

	for _, prefix := range c.prefixes {
		if strings.HasPrefix(key, prefix) {
			return ClassLegitimate, method, path
		}
	}

	return ClassMalicious, method, path
}

func extractMethodAndPath(data []byte) (method, path string) {
	end := bytes.IndexByte(data, '\n')
	if end == -1 {
		end = len(data)
	}
	line := strings.TrimSpace(string(data[:end]))
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return "", ""
	}
	if !strings.HasPrefix(parts[2], "HTTP/") {
		return "", ""
	}
	return parts[0], parts[1]
}