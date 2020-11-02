package vault

// LICENSE https://github.com/hashicorp/vault/blob/master/LICENSE
// SOURCE https://github.com/hashicorp/vault/blob/31ddb809c8e46b2796654f5083cc2ac8b1b3b188/command/base_helpers.go
// making this easier to use

import (
	"strings"

	"github.com/hashicorp/vault/api"
)

// EnsureNoLeadingSlash ensures the given string has a trailing slash.
func EnsureNoLeadingSlash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	for len(s) > 0 && s[0] == '/' {
		s = s[1:]
	}
	return s
}

// EnsureNoTrailingSlash ensures the given string has a trailing slash.
func EnsureNoTrailingSlash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// EnsureTrailingSlash ensures the given string has a trailing slash.
func EnsureTrailingSlash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	for len(s) > 0 && s[len(s)-1] != '/' {
		s = s + "/"
	}
	return s
}

// ExtractListData reads the secret and returns a typed list of data and a
// boolean indicating whether the extraction was successful.
func ExtractListData(secret *api.Secret) ([]interface{}, bool) {
	if secret == nil || secret.Data == nil {
		return nil, false
	}

	k, ok := secret.Data["keys"]
	if !ok || k == nil {
		return nil, false
	}

	i, ok := k.([]interface{})
	return i, ok
}

// SanitizePath removes any leading or trailing things from a "path".
func SanitizePath(s string) string {
	return EnsureNoTrailingSlash(EnsureNoLeadingSlash(strings.TrimSpace(s)))
}
