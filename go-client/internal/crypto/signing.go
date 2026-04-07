package crypto

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sort"
)

// CanonicalJSON serializes a map to canonical JSON bytes.
// Rules: sorted keys, no whitespace, UTF-8.
// Must produce byte-identical output to Python's
// json.dumps(obj, sort_keys=True, separators=(',',':')).
func CanonicalJSON(obj map[string]interface{}) ([]byte, error) {
	// json.Marshal sorts map keys by default in Go.
	// We explicitly ensure top-level key order, and rely on json.Marshal
	// for nested structures (which also sorts map keys).
	return marshalSorted(obj)
}

// marshalSorted produces compact JSON with keys sorted at every level.
func marshalSorted(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		buf := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			keyBytes, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			buf = append(buf, keyBytes...)
			buf = append(buf, ':')
			valBytes, err := marshalSorted(val[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, valBytes...)
		}
		buf = append(buf, '}')
		return buf, nil

	case []interface{}:
		buf := []byte{'['}
		for i, item := range val {
			if i > 0 {
				buf = append(buf, ',')
			}
			itemBytes, err := marshalSorted(item)
			if err != nil {
				return nil, err
			}
			buf = append(buf, itemBytes...)
		}
		buf = append(buf, ']')
		return buf, nil

	default:
		return json.Marshal(v)
	}
}

// Sign signs a message with Ed25519. Returns a 64-byte signature.
func Sign(sk ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(sk, message)
}

// Verify verifies an Ed25519 signature. Returns an error on failure.
func Verify(pk ed25519.PublicKey, message, signature []byte) error {
	if !ed25519.Verify(pk, message, signature) {
		return errors.New("Ed25519 signature verification failed")
	}
	return nil
}

// SignDict signs the canonical JSON encoding of a map.
func SignDict(sk ed25519.PrivateKey, obj map[string]interface{}) ([]byte, error) {
	data, err := CanonicalJSON(obj)
	if err != nil {
		return nil, err
	}
	return Sign(sk, data), nil
}

// VerifyDict verifies a signature over the canonical JSON encoding of a map.
func VerifyDict(pk ed25519.PublicKey, obj map[string]interface{}, signature []byte) error {
	data, err := CanonicalJSON(obj)
	if err != nil {
		return err
	}
	return Verify(pk, data, signature)
}
