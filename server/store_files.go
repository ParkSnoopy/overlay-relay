package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"unicode/utf8"
)

func readStoreFile(dir, name string, limit int64) ([]byte, error) {
	file, err := os.Open(filepath.Join(dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("overlay i/o failed: %w", err)
	}
	defer func() { _ = file.Close() }()
	var input io.Reader = file
	if limit != 0 {
		input = io.LimitReader(file, limit+1)
	}
	raw, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("overlay i/o failed: %w", err)
	}
	return raw, nil
}

func writeStoreJSON(w io.Writer, document any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(document)
}

func saveStoreJSON(path, temporaryPrefix string, document any, syncDirectory bool) error {
	var raw bytes.Buffer
	if err := writeStoreJSON(&raw, document); err != nil {
		return fmt.Errorf("overlay json is invalid: %w", err)
	}
	// The CLI uses a trailing newline; the Rust persisted files do not.
	err := replaceStoreFile(path, temporaryPrefix, bytes.TrimSuffix(raw.Bytes(), []byte("\n")), syncDirectory)
	if err != nil {
		return fmt.Errorf("overlay i/o failed: %w", err)
	}
	return nil
}

func replaceStoreFile(path, temporaryPrefix string, raw []byte, syncDirectory bool) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, temporaryPrefix)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(err, closeErr); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil || !syncDirectory {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func unmarshalStoreJSON(raw []byte, out any) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8")
	}
	return json.Unmarshal(raw, out)
}

type storeField struct {
	name     string
	out      any
	required bool
	nullable bool
}

func requiredField(name string, out any) storeField {
	return storeField{name: name, out: out, required: true}
}

func optionalField(name string, out any) storeField {
	return storeField{name: name, out: out}
}

func nullableField(name string, out any) storeField {
	return storeField{name: name, out: out, nullable: true}
}

// Match Serde's struct fields: exact case, no repeated known fields, and no
// explicit null for non-Option values (even if omission supplies a default).
func decodeStoreObject(raw []byte, allowUnknown bool, fields ...storeField) error {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return errors.New("malformed JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("expected a JSON object")
	}
	seen := make([]bool, len(fields))
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
		found := false
		for i, field := range fields {
			if key != field.name {
				continue
			}
			found = true
			if seen[i] || (!field.nullable && bytes.Equal(value, []byte("null"))) || json.Unmarshal(value, field.out) != nil {
				return fmt.Errorf("invalid or repeated field %q", field.name)
			}
			seen[i] = true
			break
		}
		if !allowUnknown && !found {
			return errors.New("unknown field")
		}
	}
	for i, field := range fields {
		if field.required && !seen[i] {
			return fmt.Errorf("missing field %q", field.name)
		}
	}
	return nil
}
