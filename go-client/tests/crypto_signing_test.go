package tests

import (
	"testing"

	"github.com/cisc468/p2p-project/internal/crypto"
)

func TestCanonicalJSONSortedKeys(t *testing.T) {
	obj := map[string]interface{}{"z": 1.0, "a": 2.0, "m": 3.0}
	result, err := crypto.CanonicalJSON(obj)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"a":2,"m":3,"z":1}`
	if string(result) != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestCanonicalJSONNoWhitespace(t *testing.T) {
	obj := map[string]interface{}{"key": "value"}
	result, _ := crypto.CanonicalJSON(obj)
	for _, b := range result {
		if b == ' ' || b == '\n' || b == '\t' {
			t.Error("canonical JSON must have no whitespace")
		}
	}
}

func TestCanonicalJSONNested(t *testing.T) {
	obj := map[string]interface{}{
		"outer": map[string]interface{}{"z": 1.0, "a": 2.0},
		"b":     "val",
	}
	result, err := crypto.CanonicalJSON(obj)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"b":"val","outer":{"a":2,"z":1}}`
	if string(result) != expected {
		t.Errorf("got %s, want %s", result, expected)
	}
}

func TestSignVerify(t *testing.T) {
	sk, pk, _ := crypto.GenerateIdentityKeypair()
	msg := []byte("hello world")
	sig := crypto.Sign(sk, msg)
	if len(sig) != 64 {
		t.Errorf("signature length = %d, want 64", len(sig))
	}
	if err := crypto.Verify(pk, msg, sig); err != nil {
		t.Errorf("verify failed: %v", err)
	}
}

func TestVerifyWrongMessage(t *testing.T) {
	sk, pk, _ := crypto.GenerateIdentityKeypair()
	sig := crypto.Sign(sk, []byte("hello"))
	if err := crypto.Verify(pk, []byte("different"), sig); err == nil {
		t.Error("expected error for wrong message")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	sk1, _, _ := crypto.GenerateIdentityKeypair()
	_, pk2, _ := crypto.GenerateIdentityKeypair()
	sig := crypto.Sign(sk1, []byte("test"))
	if err := crypto.Verify(pk2, []byte("test"), sig); err == nil {
		t.Error("expected error for wrong key")
	}
}

func TestSignDictVerifyDict(t *testing.T) {
	sk, pk, _ := crypto.GenerateIdentityKeypair()
	obj := map[string]interface{}{"action": "test", "value": 42.0}
	sig, err := crypto.SignDict(sk, obj)
	if err != nil {
		t.Fatal(err)
	}
	if err := crypto.VerifyDict(pk, obj, sig); err != nil {
		t.Errorf("VerifyDict failed: %v", err)
	}
}

func TestVerifyDictTampered(t *testing.T) {
	sk, pk, _ := crypto.GenerateIdentityKeypair()
	obj := map[string]interface{}{"action": "test", "value": 42.0}
	sig, _ := crypto.SignDict(sk, obj)
	obj["value"] = 43.0
	if err := crypto.VerifyDict(pk, obj, sig); err == nil {
		t.Error("expected error for tampered dict")
	}
}
