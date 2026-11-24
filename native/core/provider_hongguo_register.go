package core

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const hongguoRegisterBaseURL = "https://log5-applog-lq.fqnovel.com"

const hongguoRegisterVersionCode = 73932

const hongguoRegisterVersionName = "7.3.9.32"

const hongguoRegisterUserAgent = "com.phoenix.read/73932 (Linux; U; Android 16; zh_CN; 25053RT47C; Build/BP2A.250605.031.A3; Cronet/TTNetVersion:8d40f833 2026-03-03 QuicVersion:21ac1950 2025-11-18)"

var hongguoTTEncryptConstant, _ = hex.DecodeString("4dd4c2e6b83162090e52b3c7a6733ba41cb2462b829ab58a196b39db57177524f49baf7f08e8d68d26a72e37c1a95a2f1f05a51892aef2949732b62a38aadd58")

var hongguoTTEncryptPrefix, _ = hex.DecodeString("3176c9b6d71579d7e82179c9e7cbde787b54d541bad3b15f2e8fed92293fa25a")

type hongguoRegisterIdentity struct {
	CDID       string
	OpenUDID   string
	ClientUDID string
	OAID       string
	ReqID      string
}

func hongguoNewOpenUDID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(raw[:])
}

func hongguoTTEncrypt(input []byte) []byte {
	prefixHash := sha512.Sum512(hongguoTTEncryptPrefix)
	keyIV := sha512.Sum512(append(prefixHash[:], hongguoTTEncryptConstant...))
	digest := sha512.Sum512(input)
	plain := make([]byte, 0, len(digest)+len(input)+aes.BlockSize)
	plain = append(plain, digest[:]...)
	plain = append(plain, input...)
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	for i := 0; i < padding; i++ {
		plain = append(plain, byte(padding))
	}
	block, err := aes.NewCipher(keyIV[:16])
	if err != nil {
		return nil
	}
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, keyIV[16:32]).CryptBlocks(encrypted, plain)
	out := make([]byte, 0, 6+len(hongguoTTEncryptPrefix)+len(encrypted))
	out = append(out, 0x74, 0x63, 0x05, 0x10, 0x00, 0x00)
	out = append(out, hongguoTTEncryptPrefix...)
	out = append(out, encrypted...)
	return out
}

type hongguoOrderedField struct {
	key   string
	value any
}

func hongguoOrderedJSON(fields []hongguoOrderedField) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for index, field := range fields {
		if index > 0 {
			buffer.WriteByte(',')
		}
		key, err := json.Marshal(field.key)
		if err != nil {
			return nil, err
		}
		value, err := json.Marshal(field.value)
		if err != nil {
			return nil, err
		}
		buffer.Write(key)
		buffer.WriteByte(':')
		buffer.Write(value)
	}
	buffer.WriteByte('}')
	return buffer.Bytes(), nil
}

func hongguoRegisterHeader(identity hongguoRegisterIdentity, now time.Time) []hongguoOrderedField {
	oaid := map[string]any{
		"req_id":             identity.ReqID,
		"hw_id_version_code": "0",
		"take_ms":            "6",
		"is_track_limited":   "false",
		"query_times":        "1",
		"id":                 identity.OAID,
		"time":               now.Add(-200 * time.Millisecond).UnixMilli(),
	}
	return []hongguoOrderedField{
		{"display_name", "红果免费短剧"},
		{"update_version_code", hongguoRegisterVersionCode},
		{"manifest_version_code", hongguoRegisterVersionCode},
		{"app_version_minor", hongguoRegisterVersionName},
		{"aid", 8662},
		{"channel", "update_64"},
		{"package", "com.phoenix.read"},
		{"app_version", hongguoRegisterVersionName},
		{"version_code", hongguoRegisterVersionCode},
		{"os", "Android"},
		{"os_api", 36},
		{"os_version", "16"},
		{"device_platform", "android"},
		{"guest_mode", 0},
		{"is_system_app", 0},
		{"sdk_flavor", "china"},
		{"access", "wifi"},
		{"cdid", identity.CDID},
		{"clientudid", identity.ClientUDID},
		{"cpu_abi", "arm64-v8a"},
		{"device_brand", "Redmi"},
		{"device_id", "0"},
		{"device_manufacturer", "Redmi"},
		{"device_model", "25053RT47C"},
		{"install_id", "0"},
		{"ipv6_list", []string{}},
		{"language", "zh"},
		{"oaid", oaid},
		{"oaid_may_support", true},
		{"openudid", identity.OpenUDID},
		{"region", "CN"},
		{"req_id", identity.ReqID},
		{"sim_serial_number", []string{}},
		{"timezone", 8},
		{"tz_name", "Asia/Shanghai"},
		{"tz_offset", 28800},
	}
}

func hongguoRegisterBody(identity hongguoRegisterIdentity, now time.Time) ([]byte, error) {
	header, err := hongguoOrderedJSON(hongguoRegisterHeader(identity, now))
	if err != nil {
		return nil, err
	}
	var plain bytes.Buffer
	plain.WriteString(`{"magic_tag":"ss_app_log","header":`)
	plain.Write(header)
	plain.WriteString(`,"_gen_time":`)
	plain.WriteString(fmt.Sprintf("%d", now.UnixMilli()))
	plain.WriteByte('}')
	var gzipped bytes.Buffer
	writer, err := gzip.NewWriterLevel(&gzipped, gzip.DefaultCompression)
	if err != nil {
		return nil, err
	}
	writer.Header.ModTime = now.UTC()
	writer.Header.OS = 255
	if _, err := writer.Write(plain.Bytes()); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return hongguoTTEncrypt(gzipped.Bytes()), nil
}

func hongguoParseRegisterResponse(body []byte) (string, string, error) {
	var response struct {
		DeviceIDStr  string `json:"device_id_str"`
		InstallIDStr string `json:"install_id_str"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&response); err != nil {
		return "", "", errors.New("红果设备注册返回格式异常")
	}
	if !hongguoNumericID.MatchString(response.DeviceIDStr) || response.DeviceIDStr == "0" ||
		!hongguoNumericID.MatchString(response.InstallIDStr) || response.InstallIDStr == "0" {
		return "", "", errors.New("红果设备注册未下发有效设备号")
	}
	return response.DeviceIDStr, response.InstallIDStr, nil
}

func hongguoRegistered(state hongguoCatalogState) bool {
	return hongguoNumericID.MatchString(state.RegisteredDeviceID) && state.RegisteredDeviceID != "0" &&
		hongguoNumericID.MatchString(state.RegisteredInstallID) && state.RegisteredInstallID != "0"
}

func hongguoGuestCookie(state hongguoCatalogState) string {
	if state.TTReq == "" {
		return ""
	}
	return "passport_csrf_token=<redacted>; store-region-src=" + state.StoreRegionSrc + "; install_id=" + state.RegisteredInstallID + "; ttreq=" + state.TTReq
}

func (downloader *Downloader) hongguoRegister(ctx context.Context, identity hongguoRegisterIdentity) (string, string, map[string]string, error) {
	now := time.Now()
	body, err := hongguoRegisterBody(identity, now)
	if err != nil {
		return "", "", nil, err
	}
	if len(body) < 6 || body[0] != 0x74 || body[1] != 0x63 {
		return "", "", nil, errors.New("红果设备注册数据异常")
	}
	query := url.Values{}
	query.Set("req_id", identity.ReqID)
	query.Set("tt_data", "a")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, hongguoRegisterBaseURL+"/service/2/device_register/?"+query.Encode(), bytes.NewReader(body))
	if err != nil {
		return "", "", nil, err
	}
	request.Header.Set("User-Agent", hongguoRegisterUserAgent)
	request.Header.Set("Content-Type", "application/octet-stream;tt-data=a")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("log-encode-type", "gzip")
	request.Header.Set("sdk-version", "2")
	request.Header.Set("passport-sdk-version", "5051452")
	request.Header.Set("x-vc-bdturing-sdk-version", "4.0.3.cn")
	request.Header.Set("x-ss-dp", "8662")
	request.Header.Set("X-SS-STUB", fmt.Sprintf("%X", md5.Sum(body)))
	response, err := downloader.doPreparedCatalogRequest(request, 30*time.Second, nil)
	if err != nil {
		return "", "", nil, err
	}
	content, readErr := io.ReadAll(io.LimitReader(response.Body, providerMaxBodyBytes+1))
	cookies := map[string]string{}
	for _, cookie := range response.Cookies() {
		if cookie.Name != "" {
			cookies[cookie.Name] = cookie.Value
		}
	}
	response.Body.Close()
	if readErr != nil {
		return "", "", nil, readErr
	}
	if response.StatusCode != http.StatusOK {
		return "", "", nil, fmt.Errorf("红果设备注册失败（HTTP %d）", response.StatusCode)
	}
	if len(content) == 0 || len(content) > providerMaxBodyBytes {
		return "", "", nil, errors.New("红果设备注册未返回有效数据")
	}
	deviceID, installID, err := hongguoParseRegisterResponse(content)
	if err != nil {
		return "", "", nil, err
	}
	return deviceID, installID, cookies, nil
}

func (downloader *Downloader) hongguoEnsureRegistered(ctx context.Context) error {
	client := downloader.hongguoClient()
	client.registerMu.Lock()
	defer client.registerMu.Unlock()
	client.mu.Lock()
	if hongguoRegistered(client.state) {
		client.mu.Unlock()
		return nil
	}
	identity := hongguoRegisterIdentity{
		CDID: client.state.CDID, OpenUDID: client.state.OpenUDID,
		ClientUDID: client.state.ClientUDID, OAID: client.state.OAID, ReqID: client.state.ReqID,
	}
	if identity.CDID == "" {
		identity.CDID = hongguoV5NewCDID()
		client.state.CDID = identity.CDID
	}
	if identity.OpenUDID == "" {
		identity.OpenUDID = hongguoNewOpenUDID()
		client.state.OpenUDID = identity.OpenUDID
	}
	if identity.ClientUDID == "" {
		identity.ClientUDID = hongguoV5NewCDID()
		client.state.ClientUDID = identity.ClientUDID
	}
	if identity.OAID == "" {
		identity.OAID = hongguoV5NewCDID()
		client.state.OAID = identity.OAID
	}
	if identity.ReqID == "" {
		identity.ReqID = hongguoV5NewCDID()
		client.state.ReqID = identity.ReqID
	}
	client.mu.Unlock()
	deviceID, installID, cookies, err := downloader.hongguoRegister(ctx, identity)
	if err != nil {
		return fmt.Errorf("红果设备注册失败: %w", err)
	}
	if len(cookies) > 0 && cookies["ttreq"] == "" {
		return errors.New("红果设备注册未下发游客票据")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	client.state.RegisteredDeviceID = deviceID
	client.state.RegisteredInstallID = installID
	if value := cookies["ttreq"]; value != "" {
		client.state.TTReq = value
	}
	if value := cookies["store-region"]; value != "" {
		client.state.StoreRegion = value
	}
	if value := cookies["store-region-src"]; value != "" {
		client.state.StoreRegionSrc = value
	}
	return nil
}
