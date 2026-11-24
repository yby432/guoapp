package core

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func hongguoRegisterFixtureIdentity() hongguoRegisterIdentity {
	return hongguoRegisterIdentity{
		CDID:       "11111111-1111-4111-8111-111111111111",
		OpenUDID:   "abcdef0123456789",
		ClientUDID: "22222222-2222-4222-8222-222222222222",
		OAID:       "33333333-3333-4333-8333-333333333333",
		ReqID:      "44444444-4444-4444-8444-444444444444",
	}
}

func hongguoDecryptTTData(t *testing.T, body []byte) []byte {
	t.Helper()
	if len(body) < 38 || body[0] != 0x74 || body[1] != 0x63 || body[2] != 0x05 || body[3] != 0x10 {
		t.Fatalf("envelope prefix = %x", body[:6])
	}
	if !bytes.Equal(body[6:38], hongguoTTEncryptPrefix) {
		t.Fatal("envelope prefix bytes mismatch")
	}
	prefixHash := sha512.Sum512(hongguoTTEncryptPrefix)
	keyIV := sha512.Sum512(append(prefixHash[:], hongguoTTEncryptConstant...))
	block, err := aes.NewCipher(keyIV[:16])
	if err != nil {
		t.Fatal(err)
	}
	encrypted := body[38:]
	if len(encrypted)%aes.BlockSize != 0 {
		t.Fatal("ciphertext not block aligned")
	}
	plain := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(block, keyIV[16:32]).CryptBlocks(plain, encrypted)
	padding := int(plain[len(plain)-1])
	if padding < 1 || padding > aes.BlockSize {
		t.Fatalf("padding = %d", padding)
	}
	plain = plain[:len(plain)-padding]
	if len(plain) < sha512.Size {
		t.Fatal("decrypted payload too short")
	}
	if digest := sha512.Sum512(plain[sha512.Size:]); !bytes.Equal(digest[:], plain[:sha512.Size]) {
		t.Fatal("sha512 digest mismatch")
	}
	return plain[sha512.Size:]
}

func TestHongguoRegisterBodyDeterministic(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_123).UTC()
	body, err := hongguoRegisterBody(hongguoRegisterFixtureIdentity(), now)
	if err != nil {
		t.Fatal(err)
	}
	again, err := hongguoRegisterBody(hongguoRegisterFixtureIdentity(), now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, again) {
		t.Fatal("register body is not deterministic for a fixed identity")
	}
}

func TestHongguoTTEncryptRoundTrip(t *testing.T) {
	input := []byte("register payload for round trip")
	encrypted := hongguoTTEncrypt(input)
	if encrypted == nil {
		t.Fatal("TTEncrypt returned nil")
	}
	if got := hongguoDecryptTTData(t, encrypted); !bytes.Equal(got, input) {
		t.Fatalf("round trip = %q", got)
	}
}

func TestHongguoRegisterBodyPlaintext(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_123).UTC()
	body, err := hongguoRegisterBody(hongguoRegisterFixtureIdentity(), now)
	if err != nil {
		t.Fatal(err)
	}
	gzipped := hongguoDecryptTTData(t, body)
	reader, err := gzip.NewReader(bytes.NewReader(gzipped))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), `"magic_tag":"ss_app_log"`) ||
		!strings.Contains(string(plain), `"package":"com.phoenix.read"`) ||
		!strings.Contains(string(plain), `"device_id":"0"`) ||
		!strings.Contains(string(plain), `"version_code":73932`) ||
		!strings.Contains(string(plain), `"cdid":"11111111-1111-4111-8111-111111111111"`) {
		t.Fatalf("plaintext = %s", plain)
	}
	if strings.Contains(string(plain), "device_token") || strings.Contains(string(plain), "Cookie") {
		t.Fatal("plaintext contains a credential")
	}
	var decoded struct {
		GenTime int64 `json:"_gen_time"`
		Header  struct {
			OAID struct {
				Time int64 `json:"time"`
			} `json:"oaid"`
		} `json:"header"`
	}
	if err := json.Unmarshal(plain, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GenTime != 1_700_000_000_123 || decoded.Header.OAID.Time != 1_700_000_000_123-200 {
		t.Fatalf("gen_time = %d oaid time = %d", decoded.GenTime, decoded.Header.OAID.Time)
	}
	if index := strings.Index(string(plain), `"display_name"`); index < 0 || index > strings.Index(string(plain), `"update_version_code"`) {
		t.Fatalf("header order wrong: %s", plain)
	}
}

func TestHongguoParseRegister(t *testing.T) {
	deviceID, installID, err := hongguoParseRegisterResponse([]byte(`{"new_user":1,"device_id_str":"7100000000000001","install_id_str":"7100000000000002"}`))
	if err != nil {
		t.Fatal(err)
	}
	if deviceID != "7100000000000001" || installID != "7100000000000002" {
		t.Fatalf("ids = %s %s", deviceID, installID)
	}
	for _, bad := range []string{
		``,
		`{"device_id_str":"7100000000000001"}`,
		`{"device_id_str":"0","install_id_str":"7100000000000002"}`,
		`{"device_id_str":"abc","install_id_str":"7100000000000002"}`,
		`not json`,
	} {
		if _, _, err := hongguoParseRegisterResponse([]byte(bad)); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestHongguoNewOpenUDID(t *testing.T) {
	first := hongguoNewOpenUDID()
	if len(first) != 16 {
		t.Fatalf("openudid = %q", first)
	}
	if _, err := hex.DecodeString(first); err != nil {
		t.Fatalf("openudid not hex: %q", first)
	}
	if first != strings.ToLower(first) {
		t.Fatalf("openudid not lowercase: %q", first)
	}
	if second := hongguoNewOpenUDID(); second == first {
		t.Fatal("openudid not unique")
	}
}

func TestHongguoGuestCookie(t *testing.T) {
	state := hongguoCatalogState{RegisteredInstallID: "7100000000000002", TTReq: "ticket123", StoreRegionSrc: "cn"}
	if got := hongguoGuestCookie(state); got != "passport_csrf_token=<redacted>; store-region-src=cn; install_id=7100000000000002; ttreq=ticket123" {
		t.Fatalf("cookie = %q", got)
	}
	if got := hongguoGuestCookie(hongguoCatalogState{}); got != "" {
		t.Fatalf("cookie without ticket = %q", got)
	}
}
