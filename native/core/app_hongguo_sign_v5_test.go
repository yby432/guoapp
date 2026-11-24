package core

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestHongguoV5F13Vectors(t *testing.T) {
	type vector struct {
		raw     string
		variant int
		want    string
	}
	vectors := []vector{
		{`7726ede5e1d4a6f0496bd9ee9c9bc78fb73a954ac3cd17d7869ea2ee647b7b631a37f77bcab869ebbb9a215327aaaf4e94fb3e70`, 5, `a98bb813909f9e77891bc9b729d71f5749cf3c53`},
		{`1dc64f38bc40021e2a2b4e3c61219cec99ce8eb555186598dbc7dc83407411f652fc0cb8a25bba5a3ffc6065675dd244b8709a70`, 5, `1533220459c0e87ba6f45d54b64d34590af433d5`},
		{`e36062702b8dda4c655ee91abb56a4fc86fdd6d151e5d865822cb01d9067b9f4eaf3572bc0321d97c42369fd4c3ff0b9577eb765`, 5, `b94390621173b2eb4c34247a1811ca2710d9373d`},
		{`d4af8542de4cd1eff60d1599140b49fc6d5ce429cb56c33211175a2c09a2bd66bf4e27df8039fa026c81de830a37aecb55cd4768`, 5, `103002516115635bb4397b1de43b936a4b42e5f6`},
		{`2f93e6a829558cb92d9bf1114ee7e87d0d6942e1ec3bb789a7a2b5bc1eb87b28bf139057eaa4b162aed4016e99d44b1c006f4a67`, 12, `ea52b57a285f77fe0d88832dd05431040149a450`},
		{`113ead29810a18a113bd29d54667825fb0c4a318e18087cc03e1d33ffc580b27350f565551e00b0046260b46ab7433f3f0e8ed6d`, 12, `1b06ab72a39593f2927cbef97701cae7c060bdba`},
		{`797ad5fcedd17ddc3ca34dd3fdd3726420ac074ac98f0cd0f1c653e5925e2d25490976c17e2e215b00a78edcab641f0e3191fa70`, 12, `f44b67b54bb362be5663455a7db1732142657a81`},
		{`e72096b67b81788eb8f4ccab2dd98b532d9f15ac72adf74dd59ff2da96a820e5bf13750c19fc754ace2f6008179b42115bf026e5`, 12, `28614ac903b0a2a4df77b31d2abb98ecd2959a11`},
	}
	for _, v := range vectors {
		raw, err := hex.DecodeString(v.raw)
		if err != nil || len(raw) != 52 {
			t.Fatalf("bad vector %q", v.raw)
		}
		var sm3 [32]byte
		var body, head [16]byte
		copy(sm3[:], raw[:32])
		copy(body[:], raw[32:48])
		want, err := hex.DecodeString(v.want)
		if err != nil || len(want) != 20 {
			t.Fatalf("bad vector %q", v.want)
		}
		copy(head[:], want[:16])
		ts := binary.LittleEndian.Uint32(raw[48:])
		if got := hongguoV5F13Tail(head); hex.EncodeToString(got) != v.want[32:] {
			t.Errorf("variant %d tail(%x) = %x, want %s", v.variant, head, got, v.want[32:])
		}
		var got [16]byte
		switch v.variant {
		case 5:
			got = hongguoV5F13HeadMD5(sm3, body, ts)
		case 12:
			got = hongguoV5F13HeadSHA(sm3, body, ts)
		}
		if got != head {
			t.Errorf("variant %d head(%s) = %x, want %x", v.variant, v.raw, got, head)
		}
	}
	tails := []string{
		`f0bb5cac4471b8995a4181d9f514361a11f3af6f`,
		`5834ef592138e598e566f6ab22081e514a98f6c6`,
		`1ff529778c9026953af1b1338482e18391657f4b`,
		`e2bc53535ac14a0e4773fe97266f368d5b519109`,
		`9de1623a454e46af081af0b64f6be5fb13ef7173`,
		`ac06b3dcd93621f2267d6dc7ef905a450a4aff97`,
		`226ec8cef403117a4728b11ca9a9fe094ab0777e`,
		`d8aeb630eb9dc01bb29bbccbc160ea3e131587ab`,
	}
	_ = tails
}

func TestHongguoV5HeliosVectors(t *testing.T) {
	type vector struct {
		query  string
		body   string
		ts     uint32
		helios string
	}
	vectors := []vector{
		{`query=abc&aid=8662&device_id=1234567890123456&iid=1234567890123457&version_code=74332&version_name=7.4.3.32&ts=1763460000&_rticket=1763460000138`, `-`, 1763460000, `1XzNUi2r8kKRJQp9+56mJPL82zIHMvzd1XnT6Xd8B/srJo8r`},
		{`aid=8662&device_id=1234567890123456&iid=1234567890123457&version_name=7.4.3.32&device_platform=android&_rticket=1763460000123`, `7b2264725f7363656e65223a22706c61796572222c226d697865645f766964656f5f69645f6d6170223a7b2231303034223a5b2237343231303532363138383439363637225d7d7d`, 1763460000, `AhIPa+9QUH5Hm3IP8fv16LbOaFXjl1vSLBMJYZNhyrlBeEGg`},
		{`query=abc&aid=8662&device_id=1234567890123456&iid=1234567890123457&version_code=74332&version_name=7.4.3.32&ts=1763460001&_rticket=1763460001144`, `-`, 1763460001, `1XzNUrgMYejk2RozoF2qEYt3mlQHMvzd1XnT6Xd8B/srJo8r`},
	}
	for _, v := range vectors {
		var body []byte
		if v.body != "-" {
			var err error
			body, err = hex.DecodeString(v.body)
			if err != nil {
				t.Fatal(err)
			}
		}
		_ = body
		h, err := base64.StdEncoding.DecodeString(v.helios)
		if err != nil {
			t.Fatal(err)
		}
		if got := hongguoV5Helios(v.ts, binary.LittleEndian.Uint32(h[:4])); got != v.helios {
			t.Errorf("x-helios = %s, want %s", got, v.helios)
		}
	}
}

func TestHongguoV5MedusaVectors(t *testing.T) {
	type vector struct {
		query    string
		body     string
		ts       uint32
		deviceID string
		envJSON  string
		rndJSON  string
		want     string
	}
	vectors := []vector{
		{`query=abc&aid=8662&device_id=1234567890123456&iid=1234567890123457&version_code=74332&version_name=7.4.3.32&ts=1763460000&_rticket=1763460000138`, `-`, 1763460000, `1234567890123456`, `{"PID":4321,"PPID":1234,"LaunchMillis":1763460000000,"Clock18":766353820,"Clock19":16,"Clock20":-1072050540,"Channel":"xiaomi_8662_64","UnH":2398682137,"Fkd":655280453,"Pd":-1533169987,"Sts":27,"Lp":"2|520830913092|521433182354|2078052786776|1081701896","Fl":"0|0|2523408538|2586339478|997724116|0|0|0|0|606600138"}`, `{"Message":1327614909,"Key":1605379809,"Packed":1001584842}`, `pUMcaY0IU6PpNhEqn/ayRYIu0D/hJgABRIrq+LI7gWQLGIrRvAIIPwSXY9xA3M0E2DfldWKZ0dNtJpq3/O6lCC/rYMalYwB5VPLIpQWzunlq8h4lnmaPVTR1Z4bDYEHmDyCuPQMxfkZZTk1LQo4HAtS2KNlaqkq306h/To6qmH0vF0xyU5xSU3yy9LDS1OxcdFbP+rlIaYwlvSOUhRhHuWAbtwZ4qLo8FvEVQuWCX4uYf4Rj7/PKXrApRWNcF1+Z0IeLLAG+cHSX+sbqYif945ozQAgxYUXTPTERSltPJNcey7Ps3SMlj/dCFl48alFLxzUew6nBaS8w1SOC1EAonbrPltODKv+DUFOj1tx4aHEWADWj4E/ipj9E+bd8nMhjnMPBgqjnqlO5s6pUJR3/JcvUwwqmS8ImnnULgtllXlDWfxUvM/89fJNrJzLfLkzYatioYaVYH0lOyJREvSCdRFo1grn2+suaRJtZcekR7OkV2EFbpLgUkZO/T7LS9hsoCSsbq+lT5v+z53K0hBBa9MET+tX2f86CL8RXNbUPXDO1rUzxEOfEehm0rKMI0UWnOqYU0aaY6GUcE//7ffq4L55UFtGkEAkyGFlQsP0KMQhZu7zW5fDkvB60mOKxxPBDOZbIJ8zvTgzn0jPUJgX8NlnxlSx8stNMH0/hDrl5WrqsAdqBTSyJUcOx4dX094SBvR9mZOQRelU77oHBKf37IzFcTacrwBdjx3ddfXYdCzOMqihPLQSSfy9C8LIRRVVxS8j0uFnGwNmJTv8+Ynx8qQ6JpGe24PLk1nHFc8kVjRe6hnDaB/7hZu06VJJHq0aq49tDNiIK6UPB8Wjif/eS41nrUIIA5IHpPhmkK4JdiUePTkfvEvt/2EWLL/HRLPCTNOnqtyWadxrPUlM9IV+M0mVh1PgDiJBMcFyMl0ekhWpJywqjA+Z+9L1WYe+n+7LvR0lvbCf3WKQXOr+HHYGJQxnkLl306VKNonfTG9E0QQIYPLxqnpgQvNIZ/3QAeUudj8iYZIqyJJaHH1IciJLmZK1+mSnrnAZsR4VRjml9CepK80iHPtWPYcU8rVJ/zZOExHNFhA5lL+JE9kLY9xbixCfEeuQq145bfxX/+n8V//KwXw==`},
		{`aid=8662&device_id=1234567890123456&iid=1234567890123457&version_name=7.4.3.32&device_platform=android&_rticket=1763460000123`, `7b2264725f7363656e65223a22706c61796572222c226d697865645f766964656f5f69645f6d6170223a7b2231303034223a5b2237343231303532363138383439363637225d7d7d`, 1763460000, `1234567890123456`, `{"PID":4321,"PPID":1234,"LaunchMillis":1763460000000,"Clock18":766353820,"Clock19":16,"Clock20":-1072050540,"Channel":"xiaomi_8662_64","UnH":2398682137,"Fkd":655280453,"Pd":-1533169987,"Sts":27,"Lp":"2|520830913092|520830913496|2078052786776|1081701888","Fl":"0|0|2523408538|2586339478|997724116|0|0|0|0|128"}`, `{"Message":593892428,"Key":1766845771,"Packed":594242347}`, `pUMcaY0IU6PpNhEqn/ayRYIu0D9L7QABhMorY3sngegLGIgR4YFibk1VRSVB64KWQv5NeyMM9+ci3qxvrac5V3Fx+oJuDjVnrhiEXB07KZU62wcAI2XJQCpXyC6o38auWTPBal0BKj9HHJ7ux9CfpQy+YBuvUv8CuZcDaya9O93D12ZgcuBJvUgKD0UXzBQyHfq1efCGULF39Opqa60gmc0k3WPhnCe3bpinPT32c4rItYIKuRcoL+wxoo/VBjzv8E99XNjHm7vG+E5DyNw0cuJoEJ9WwhpA7vXkkvmtGCwM64FhCo3OmnEV2ZkmlOn1UvZH9JTgxGjWambVDGb442Ui9Pgzg5vQK5cf9bxaVodPaM+ZRnJkZ7u1N28hs+chcaVh/qKAVHBOFLzNRIDrol8cPMG8SxWIfPN+LRS+9HEVURcbMZoVA4iZrPmhlUzxv9uYXBP9swk0nmxdIvwN4X9c7azgAh/ZhktNK+Yq7EzsJS82KZyjiiRyIQcQMipI7+s3gDkFWGwRQkEfdoPh5LDffyar4NkLhBXh0qgfGIEPDou6RCsC+LhyeNZ0QhHKnW2oeFybn9tN/IjwSV2eEwlptB8b6n56v9jSjg2lV3uYc/suFIT/Khkj4VaCXjqmdPKYijqQLOO6YtvbkzCzAS3waVHq3aNKc75HdaEp03aH7XJyHVITsUraNM92bJVF8kRgOCMYenYmpl1vuaK4LN6jIk34saK7QAj/vc+5sKfx3FSmNii98I+7xCniWPLK7W3YtyZ1F6wmcqNbuH7dl8Z2S0iNXB/s5wTvfbJhzG1QqBdAoQXBc43o4lm8vnztv2f6SZWy0NCSIyFTqMdxyJnhoBXnD54ZhL0f5Oazdbrs680AAg2x8FqMfPxRJ9tzkumcHxW+Ad/n30+jLJ/Oo9S445OkzHD1EfugY3MwhDc6SE8NOKMy4AG7WhdwbI9B4ZBXioZLK0YBieRxZHnWtZvb1UJ0tXPlSl2KBo0xTCxpEI4jbdES3wMR3/cptl8m2p6dEt3OC/EzeWV9VwNiDfrYkMgKIKM/PrnpycLkc3Kg9yPaXNs1td9/1uNRr03rPbUvCdpEc/n6+g94/cVO9o4d//2H2//9h9NPaQ==`},
		{`query=abc&aid=8662&device_id=1234567890123456&iid=1234567890123457&version_code=74332&version_name=7.4.3.32&ts=1763460001&_rticket=1763460001144`, `-`, 1763460001, `1234567890123456`, `{"PID":4321,"PPID":1234,"LaunchMillis":1763460001000,"Clock18":766353820,"Clock19":16,"Clock20":-1072050540,"Channel":"xiaomi_8662_64","UnH":2398682137,"Fkd":4083905108,"Pd":399276915,"Sts":27,"Lp":"2|520830913092|521433182338|2078052788144|1081701896","Fl":"0|0|2523409778|1915578518|124225872|0|0|0|0|606600154"}`, `{"Message":1327614909,"Key":1605379809,"Packed":1001584842}`, `pEMcaYwIU6PoNhEqnvayRYMu0D/hJgAB6Irq8KI7AVIBGPmCpIjVXKgkMqd7XwXe11i+uuRt9e+4JU3J7fPtJjfYwAZiJkj7CWloOWA70qf07Vo861/Ko1elw/gNgylDuyVRBObSpXxxADkgPMFqI3G3xPxekJ5McHUQXAxLKERmgeGPMoNIej6I4hHsRVT+0hSYXAg4492q67AMIzlhnGRc0fDOuhla+LQ8Sr/f4jZmZlxwPoGJMQsWeqFOQm9kzrMtPmIcVygLXWyXPqU0JPzCLN86d02G7gUCzSe0pgt6a3DQzjz9RdkKVEYPeJ8QSh/BIFCiWtRMiO+EoRa+Xk8uDWy4w7R9eG+osf0XfaMuPO16Vwx2QL0pEcie6UC5M2cMU2qpm69uhkl/nu7uuT8YGGtHJBmIkYSWHLeDRrmw+h4PJKDXfTCInM2qE2nNJLCsavigbEm4YG7ot8O5hyliyFF6AZGWY4Gpz22cBTj1AW6YiJ9A3xTiJVcmyVcwhEDer41zgj9QR5EIB68pEd7BcNAhwwdbmTez5kbks5Ywa+b9zwIr0zRZ39TBdabfWYqVyqQiMg4Q2aRkK+rrhu0ZqsKhMh6v4Py0cU7RPcxiKSLTtmA+2WovEVS6ZeVPbT9Ieb8tpJq4jRvFh/zTd7uoOGskrIpzWFUPVBwZJeKU54RSKFNYy9lkUK7fdpzBpojC95UMQrqddSK4ArpBonqOLdVZhtKM/LxPJ5dP5wE4Pllr/Ka14zdp0JcaP4iyoVPzK8WU/9ELreM6L+3CzG5mOvvl2esGybT1PvKMG8/ve0MlClCSRCIZA85XWOgjAFA5kRQfUrbGOdRMf05eAZvQ9osvgfh8BCKyp/V1RAJfihASta53yMzIrSHVZj5dkg2ryJ6DQtBZTDRRYTzbiWjLvRLFDVoh3vBGmoBPu8sOKyc3WLO5Buuw5MX0mOS9JhiAtFKT1MNM3dAWjRYqS3nwgYVM4NTCU5SjDsmDTkquWT9CYDfK2EGQHf1MI2Ji6iG8qcCydSJWfHwN3U5mFj9RFgmVB/LLbRkaLrbK5qMG/dsEq/plBLId0aFFOdZ6FheDD23aDGRR6CYxYXOo32Fi5WW3ut36fxX/+n8V97Bf`},
	}
	for i, v := range vectors {
		var body []byte
		if v.body != "-" {
			var err error
			body, err = hex.DecodeString(v.body)
			if err != nil {
				t.Fatal(err)
			}
		}
		var env hongguoV5MedusaEnv
		var rnd hongguoV5MedusaRandom
		if err := json.Unmarshal([]byte(v.envJSON), &env); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(v.rndJSON), &rnd); err != nil {
			t.Fatal(err)
		}
		env.Status = hongguoV5EmulatorStatus
		in, ok := hongguoV5NewMedusaInput(v.query, body, v.ts)
		if !ok {
			t.Fatalf("vector %d selects an unsupported field-13 variant", i)
		}
		if got := hongguoV5AssembleMedusa(in, v.deviceID, env, rnd); got != v.want {
			t.Errorf("vector %d (ts %d): x-medusa differs\n got %s\nwant %s", i, v.ts, got, v.want)
		}
	}
}

func TestHongguoV5SignPlaybackTicket(t *testing.T) {
	body := []byte("gzip bytes")
	entropy := &hongguoV5Entropy{MessageRandom: 1234567, Random: 7654321, PackedRandom: 999999, HeliosRandom: 424242}
	query, headers, err := hongguoV5SignPlayback([][2]string{{"a", "1"}, {"_rticket", ""}, {"device_id", "7100000000000001"}}, 1_794_000_000_123, body, entropy)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(query, "a=1&_rticket=") || !strings.HasSuffix(query, "&device_id=7100000000000001") || strings.Count(query, "_rticket=") != 1 {
		t.Fatalf("query = %s", query)
	}
	if headers["x-medusa"] == "" || headers["x-helios"] == "" || headers["x-ss-stub"] == "" || headers["x-khronos"] == "" {
		t.Fatalf("headers = %v", headers)
	}
	query, _, err = hongguoV5SignPlayback([][2]string{{"a", "1"}, {"device_id", "7100000000000001"}}, 1_794_000_000_123, body, entropy)
	if err != nil || !strings.HasPrefix(query, "a=1&device_id=7100000000000001&_rticket=") {
		t.Fatalf("appended ticket query = %s err %v", query, err)
	}
}

func TestHongguoV5DefaultEnvStatus(t *testing.T) {
	if got := hongguoV5DefaultMedusaEnv(0).Status; got != hongguoV5DeviceStatus || got == hongguoV5EmulatorStatus {
		t.Fatalf("status = %d, want %d", got, hongguoV5DeviceStatus)
	}
	in, _ := hongguoV5NewMedusaInput("device_id=1234567890123456", nil, 1763460000)
	device := hongguoV5MedusaMessage(in, "1234567890123456", hongguoV5DefaultMedusaEnv(0), hongguoV5MedusaRandom{})
	emulator := hongguoV5DefaultMedusaEnv(0)
	emulator.Status = hongguoV5EmulatorStatus
	if string(device) == string(hongguoV5MedusaMessage(in, "1234567890123456", emulator, hongguoV5MedusaRandom{})) {
		t.Fatal("status is not part of the message")
	}
	if want := string(hongguoV5ProtoSInt(21, hongguoV5DeviceStatus)); !strings.Contains(string(device), want) {
		t.Fatalf("message lacks field 21 = %d", hongguoV5DeviceStatus)
	}
}
