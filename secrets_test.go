package main

import "testing"

func TestShellIdentifier(t *testing.T) {
	exportable := []string{"DATABASE_URL", "_private", "A1"}
	for _, key := range exportable {
		if !shellIdentifier.MatchString(key) {
			t.Errorf("%q should be exportable", key)
		}
	}

	skipped := []string{"github-token", "1A", "", "a b"}
	for _, key := range skipped {
		if shellIdentifier.MatchString(key) {
			t.Errorf("%q should be skipped", key)
		}
	}
}
