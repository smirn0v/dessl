package dessl

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"regexp"
)

type DesslReplaceEntry struct {
	MatchingPathRegexp *regexp.Regexp
	Headers            []string
	Body               []byte
}

type desslReplaceYamlEntry struct {
	PathRegexp string   `yaml:"path_regexp"`
	BodyFile   string   `yaml:"body_file"`
	Headers    []string `yaml:"headers"`
}

func ReadDesslReplaceMap(path string) ([]DesslReplaceEntry, error) {
	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read YAML file: %w", err)
	}

	var entries []desslReplaceYamlEntry
	if err := yaml.Unmarshal(fileData, &entries); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	baseDir := filepath.Dir(path)
	result := make([]DesslReplaceEntry, 0, len(entries))

	for idx, entry := range entries {
		re, err := regexp.Compile(entry.PathRegexp)
		if err != nil {
			return nil, fmt.Errorf("invalid regexp at index %d: %w", idx, err)
		}

		bodyPath := filepath.Join(baseDir, entry.BodyFile)
		bodyData, err := os.ReadFile(bodyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read body file at index %d ('%s'): %w", idx, entry.BodyFile, err)
		}

		result = append(result, DesslReplaceEntry{
			MatchingPathRegexp: re,
			Headers:            entry.Headers,
			Body:               bodyData,
		})
	}

	return result, nil
}

/*
- path_regexp: "^/api/v1/users$"
  body_file: "responses/users.json"
  headers:
    - "Content-Type: application/json"
    - "Cache-Control: no-cache"

- path_regexp: "^/api/v1/items/[0-9]+$"
  body_file: "responses/item.json"
  headers:
    - "Content-Type: application/json"
*/
