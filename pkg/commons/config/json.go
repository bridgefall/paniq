package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadJSONFile reads a JSON file into the provided struct pointer.
func LoadJSONFile(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	return DecodeJSON(data, out)
}

// DecodeJSON unmarshals JSON data into the provided struct pointer.
func DecodeJSON(data []byte, out any) error {
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	return nil
}
