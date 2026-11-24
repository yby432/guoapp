package core

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const hongguoV5License = "646637794"

const hongguoV5AppID = "8662"

const hongguoV5MedusaVersion = 5

const hongguoV5MedusaSDKVersion = "v04.10.03-ml-android"

const hongguoV5MedusaSDKCode = 0x040a0300

const hongguoV5MedusaEnvVersion = "v04.10.03.04-bugfix"

const hongguoV5MedusaPackedHead = 0xca

const hongguoV5DeviceStatus = 369

const hongguoV5EmulatorStatus = 377

var hongguoV5Magic = hongguoV5MustHex("2d4b4fca49750d433fb5ae2c226dcc56")

var hongguoV5SignKey = hongguoV5MustHex("b23c2a470a20d105dc3f8c4438f8272ed46d6c89ffdcdedd5108698d26e9489d")

var hongguoV5Sbox = hongguoV5MustHex("53290fe9e51f316f90f74a7e034d367784ab49237cd0135cdc632c322fd3be0e2624a417ecd9151a7ff64f60730a87f9445ec6ada2f865d22b696c4188f24c0df37b75510b939f6bc2fe6883e68bc8c722181ba0bdb08c9871b50c9a16b46eea8eed20ba4b8a14e0fcf1468dbbef05a93e5a9d7dcf06898635c1fd99f5de287a80c594daaab19b6279fbd75070cb52eb2555c456e39e7839853874e2f0013ac0b64742d8ca10e4b79c955de8b843ce4ed464a6a72ed508091c92e7b3eedd1e1dd12afac321618fa3d65f9167c982f43d66a53c6a1997585b346dbf9672ff37cdbc073b2dae11453304df00815476b2a13fccdb30b957a8acafe127400248591238922563e36406d37a24100b7902a028044e218453c2a399199c9d13dc40c55ba67e502273850ebdc1a2e2188b8f2d9e3cb909b8c46a2a9f4a6dd93007eafa65b7b3a881aa908cc74f0ad76bbbb58617c37012ca05a469fd44e62eecf1e4272ce860c0ae5eadf99b20d8f0234174006f3f110d7657d01645d4eff8f71471cbfe1cb2f52648727bf3c9de55153e031b4d61757db63dbf7782eeafe9018a8891362fb14759ac32bab03b349aeb5a377c5156be4c8dfbe13a684bda39cf836697c894545fe0f2491acea9fc6252f4ff1e0fe72bd2df6e67a7f635e5bcc6d1a5dd951d89960887a18eb40c785cdb1f80ed42299333ab98cdd67f316cd54346585dccd759fb722789b08807cc0fda293f7e5e1819bb0353517020b31d3d00374952bea2c421e862040a9ec892a05b266b7a0d0cc316f483b81af39715657ffe32ad8de0c13077646035236ee5363e5f900e9a7cf850a81cd9960b6df73317226f99eaa6fff15cec34acb98246639b918ab2851466a7cdfc4ad1b52c2ae95a58d3734e47ddd5b7560193f644ef9c408b7dee39b4d6aabf4de761e3252d4c7ba3843187745d55e6a5db05d42b45caed43c0c5d0b64bfa9d94a4a9d8f2f0e1a108dcfd288fd2bc1fc7bd675412138169cb09249875ba3b68cfb11180afae104fc9789571c6dfce02413886796ae21e3c488cc21b9f423a066c2eabf98e2fdeeb5776e4f5d09a515ba58cbbab3e37b09fd4f6d9244df80512e84cd7956be301cf64f1429d58577cc241f3a2c655144f81aaf95a4e108da894b38970561ae9002619fbbac91fa922ed202bfc62cb08e0de2a7f3631435f8b47c8a3c563b4db4071ce74c46da6fa696a9e282d1e825d663b93bfd56c48dce1884bb10fccea063929f746443fd830a4232e53da21a1f2d1bdfebc3a02c10a1b8ad31d04fd616590d272ac737e98eb33af60528716bee78ec0ee8699031177277d9cff32542c67caf5f44591681335ae0e178f3409a7803db83892dde5b9b7f0c750e24aef077badd678a09b850b84ec1597e4963cb5e675df1c0d6fb618496ecd76c35c798325590c2fb27a5e")

func hongguoV5MustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func hongguoV5Le32(value uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], value)
	return b[:]
}

func hongguoV5Be32(value uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], value)
	return b[:]
}

func hongguoV5Md5(value []byte) [16]byte {
	return md5.Sum(value)
}

func hongguoV5Rol32(value, count uint32) uint32 {
	n := count & 31
	if n == 0 {
		return value
	}
	return (value << n) | (value >> (32 - n))
}

func hongguoV5Ror32(value, count uint32) uint32 {
	n := count & 31
	if n == 0 {
		return value
	}
	return (value >> n) | (value << (32 - n))
}

func hongguoV5Ror64(value, count uint64) uint64 {
	n := count & 63
	if n == 0 {
		return value
	}
	return (value >> n) | (value << (64 - n))
}

func hongguoV5Ror8(value byte, count uint32) byte {
	count &= 7
	return value>>count | value<<(8-count)
}

func hongguoV5Zigzag(value int64) uint64 {
	return uint64((value << 1) ^ (value >> 63))
}

func hongguoV5Varint(value uint64) []byte {
	var out []byte
	for value > 127 {
		out = append(out, byte(value&127)|128)
		value >>= 7
	}
	return append(out, byte(value))
}

func hongguoV5ProtoKey(tag uint32, wire byte) []byte {
	return hongguoV5Varint((uint64(tag) << 3) | uint64(wire))
}

func hongguoV5ProtoBytes(tag uint32, body []byte) []byte {
	if len(body) == 0 {
		return nil
	}
	out := hongguoV5ProtoKey(tag, 2)
	out = append(out, hongguoV5Varint(uint64(len(body)))...)
	return append(out, body...)
}

func hongguoV5ProtoString(tag uint32, s string) []byte {
	return hongguoV5ProtoBytes(tag, []byte(s))
}

func hongguoV5ProtoSInt(tag uint32, value int64) []byte {
	out := hongguoV5ProtoKey(tag, 0)
	return append(out, hongguoV5Varint(hongguoV5Zigzag(value))...)
}

func hongguoV5ProtoFloat(tag uint32, value float32) []byte {
	out := hongguoV5ProtoKey(tag, 5)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], math.Float32bits(value))
	return append(out, b[:]...)
}

func hongguoV5ProtoEmpty(tag uint32) []byte {
	return append(hongguoV5ProtoKey(tag, 2), 0)
}

func hongguoV5Concat(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func hongguoV5EncodeComponent(s string) string {
	const unreserved = "-_.!~*'()"
	var b strings.Builder
	for _, c := range []byte(s) {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || strings.ContainsRune(unreserved, rune(c)) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func hongguoV5EncodeQuery(pairs [][2]string) string {
	parts := make([]string, len(pairs))
	for i, pair := range pairs {
		parts[i] = hongguoV5EncodeComponent(pair[0]) + "=" + hongguoV5EncodeComponent(pair[1])
	}
	return strings.Join(parts, "&")
}

func hongguoV5QueryValue(query, name string) string {
	for _, part := range strings.Split(query, "&") {
		key, value, _ := strings.Cut(part, "=")
		if key == name {
			return value
		}
	}
	return ""
}

func hongguoV5GetIV(iv uint32, data []byte) uint32 {
	value := iv
	for i, b := range data {
		if i&1 == 0 {
			value = (value >> 4) ^ value ^ (value << 6) ^ uint32(b)
			continue
		}
		inner := (value >> 7) ^ value ^ (uint32(b) | (value << 12))
		value = ^inner
	}
	return value
}

func hongguoV5Sm3(msg []byte) [32]byte {
	h := [8]uint32{
		0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
		0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
	}
	padded := hongguoV5Sm3Pad(msg)
	var w [68]uint32
	var wp [64]uint32
	for off := 0; off < len(padded); off += 64 {
		block := padded[off : off+64]
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(block[i*4 : i*4+4])
		}
		for j := 16; j < 68; j++ {
			x := w[j-16] ^ w[j-9] ^ hongguoV5Rol32(w[j-3], 15)
			w[j] = hongguoV5Sm3P1(x) ^ hongguoV5Rol32(w[j-13], 7) ^ w[j-6]
		}
		for j := 0; j < 64; j++ {
			wp[j] = w[j] ^ w[j+4]
		}
		a, b, c, d := h[0], h[1], h[2], h[3]
		e, f, g, hh := h[4], h[5], h[6], h[7]
		for j := 0; j < 64; j++ {
			tj := uint32(0x7a879d8a)
			if j < 16 {
				tj = 0x79cc4519
			}
			ss1 := hongguoV5Rol32(hongguoV5Rol32(a, 12)+e+hongguoV5Rol32(tj, uint32(j)), 7)
			ss2 := ss1 ^ hongguoV5Rol32(a, 12)
			tt1 := hongguoV5Sm3FF(j, a, b, c) + d + ss2 + wp[j]
			tt2 := hongguoV5Sm3GG(j, e, f, g) + hh + ss1 + w[j]
			d = c
			c = hongguoV5Rol32(b, 9)
			b = a
			a = tt1
			hh = g
			g = hongguoV5Rol32(f, 19)
			f = e
			e = hongguoV5Sm3P0(tt2)
		}
		h[0] ^= a
		h[1] ^= b
		h[2] ^= c
		h[3] ^= d
		h[4] ^= e
		h[5] ^= f
		h[6] ^= g
		h[7] ^= hh
	}
	var out [32]byte
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(out[i*4:], h[i])
	}
	return out
}

func hongguoV5Sm3Pad(msg []byte) []byte {
	bitLen := uint64(len(msg)) * 8
	out := make([]byte, 0, len(msg)+72)
	out = append(out, msg...)
	out = append(out, 0x80)
	for (len(out)+8)%64 != 0 {
		out = append(out, 0)
	}
	var lenb [8]byte
	binary.BigEndian.PutUint64(lenb[:], bitLen)
	return append(out, lenb[:]...)
}

func hongguoV5Sm3FF(j int, x, y, z uint32) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (x & z) | (y & z)
}

func hongguoV5Sm3GG(j int, x, y, z uint32) uint32 {
	if j < 16 {
		return x ^ y ^ z
	}
	return (x & y) | (^x & z)
}

func hongguoV5Sm3P0(x uint32) uint32 { return x ^ hongguoV5Rol32(x, 9) ^ hongguoV5Rol32(x, 17) }

func hongguoV5Sm3P1(x uint32) uint32 { return x ^ hongguoV5Rol32(x, 15) ^ hongguoV5Rol32(x, 23) }

func hongguoV5F13Variant(querySM3 [32]byte, bodyMD5 [16]byte, ts uint32) uint32 {
	return hongguoV5GetIV(hongguoV5GetIV(hongguoV5GetIV(0x20230928, querySM3[:]), bodyMD5[:]), hongguoV5Le32(ts)) & 15
}

func hongguoV5F13Supported(variant uint32) bool { return variant == 5 || variant == 12 }

func hongguoV5F13(querySM3 [32]byte, bodyMD5 [16]byte, ts uint32) ([20]byte, bool) {
	var out [20]byte
	var head [16]byte
	switch hongguoV5F13Variant(querySM3, bodyMD5, ts) {
	case 5:
		head = hongguoV5F13HeadMD5(querySM3, bodyMD5, ts)
	case 12:
		head = hongguoV5F13HeadSHA(querySM3, bodyMD5, ts)
	default:
		return out, false
	}
	copy(out[:16], head[:])
	copy(out[16:], hongguoV5F13Tail(head))
	return out, true
}

func hongguoV5F13Tail(head [16]byte) []byte {
	h := uint32(0x20220420)
	for i, cb := range head[:8] {
		if i&1 == 0 {
			h = h<<7 ^ uint32(cb) ^ h>>3 ^ h
		} else {
			h = ^((h<<11 | uint32(cb)) ^ h>>5 ^ h)
		}
	}
	out := hongguoV5Le32(h)
	out[0] &= 0xdb
	out[3] ^= 1
	return out
}

func hongguoV5F13HeadMD5(querySM3 [32]byte, bodyMD5 [16]byte, ts uint32) [16]byte {
	var in [52]byte
	copy(in[:32], querySM3[:])
	copy(in[32:48], bodyMD5[:])
	binary.LittleEndian.PutUint32(in[48:], ts)
	w := func(at int) uint32 { return binary.LittleEndian.Uint32(in[at:]) }

	var pad [8]byte
	for i, b := range hongguoV5F13Pad {
		pad[i] = hongguoV5Ror8(b, (ts-1)&7)
	}
	m := [16]uint32{
		w(36), w(32), binary.LittleEndian.Uint32(pad[:4]), w(24),
		w(40), w(28), binary.LittleEndian.Uint32(pad[4:]), w(44),
		w(0), w(4), w(8), 0x1a0,
		w(48), w(16), w(20), w(12),
	}

	var iv [4]uint32
	for i, v := range hongguoV5F13IV {
		iv[i] = hongguoV5Ror32(v, (ts+2)&31)
	}
	a, b, c, d := iv[0], iv[1], iv[2], iv[3]
	for i := 0; i < 64; i++ {
		var f uint32
		switch i / 16 {
		case 0:
			f = d ^ (b & (c ^ d))
		case 1:
			f = c ^ (d & (b ^ c))
		case 2:
			f = b ^ c ^ d
		default:
			f = c ^ (b | ^d)
		}
		k := hongguoV5Ror32(hongguoV5F13K[i], (ts+3+uint32(i/16))&31)
		x := a + f + m[hongguoV5F13Order[i]] + k
		a, b, c, d = d, b+hongguoV5Rol32(x, uint32(hongguoV5F13Shift[i])), b, c
	}
	state := [4]uint32{a, b, c, d}

	var out [16]byte
	for i := range state {
		binary.LittleEndian.PutUint32(out[i*4:], (iv[i]+state[i])^hongguoV5Ror32(hongguoV5F13Final[i], (ts+8)&31))
	}
	return out
}

func hongguoV5F13HeadSHA(querySM3 [32]byte, bodyMD5 [16]byte, ts uint32) [16]byte {
	const seed = uint32(0x9d4a97c2)
	count := seed + ts
	table := make([]uint32, len(hongguoV5Branch0TT))
	for i, v := range hongguoV5Branch0TT {
		table[i] = hongguoV5Ror32(v, count+1)
	}
	pad := []byte{0xfa, 0x45, 0x61, 0xd7}
	for i, v := range pad {
		pad[i] = byte((uint16(v) | uint16(v)<<8) >> ((count + 2) & 7))
	}
	words := hongguoV5ExpandWords(hongguoV5Concat(querySM3[:], bodyMD5[:], hongguoV5Le32(ts), pad, []byte{0, 0, 0, 0, 0, 0, 1, 0xa0}))
	initial := make([]uint32, len(hongguoV5Branch0Init))
	for i, v := range hongguoV5Branch0Init {
		initial[i] = hongguoV5Ror32(v, count)
	}
	state := hongguoV5MixRounds(append([]uint32(nil), initial...), [11]uint32{96, 1, 3, 4, 0, 6, 5, 2, 0, 7, 7}, words, table, seed)
	var result [32]byte
	for i, v := range state {
		binary.BigEndian.PutUint32(result[i*4:], v+initial[i])
	}
	var out [16]byte
	for i := range out {
		out[i] = result[i] ^ result[i+16]
	}
	return out
}

func hongguoV5ExpandWords(data []byte) []uint32 {
	di := make([]uint32, 0, 16+112)
	for off := 0; off+4 <= len(data); off += 4 {
		di = append(di, binary.BigEndian.Uint32(data[off:off+4]))
	}
	di0 := di[0]
	for i := 0; i < 112; i++ {
		di1 := di[i+1]
		di14 := di[i+14]
		r1 := hongguoV5Rol32(di1, 14) ^ hongguoV5Rol32(di1, 25) ^ (di1 >> 3)
		r2 := hongguoV5Rol32(di14, 13) ^ hongguoV5Rol32(di14, 15) ^ (di14 >> 10)
		di = append(di, di0+di[i+9]+r1+r2)
		di0 = di1
	}
	return di
}

func hongguoV5MixRounds(state []uint32, rounds [11]uint32, di, tt []uint32, ivV1 uint32) []uint32 {
	for i := uint32(0); i < rounds[0]; i++ {
		base := ivV1 + i
		w := di[base&127]
		idx := func(k int) int { return int(rounds[k]) }
		n1 := ((state[idx(3)] ^ state[idx(4)]) & state[idx(1)]) ^ state[idx(3)]
		n2 := hongguoV5Rol32(state[idx(1)], 26) ^ hongguoV5Rol32(state[idx(1)], 21) ^ hongguoV5Rol32(state[idx(1)], 7)
		n4 := w + n1 + n2 + tt[base&63] + state[idx(5)]
		n5 := hongguoV5Rol32(state[idx(2)], 30) ^ hongguoV5Rol32(state[idx(2)], 19) ^ hongguoV5Rol32(state[idx(2)], 10)
		n6 := (state[idx(2)] & state[idx(6)]) | ((state[idx(2)] | state[idx(6)]) & state[idx(7)])
		n7 := n5 + n6
		old := state[idx(9)]
		last := state[len(state)-1]
		state = append([]uint32{last}, state[:len(state)-1]...)
		state[idx(10)] = n7 + n4
		state[idx(8)] = old + n4
	}
	return state
}

var (
	hongguoV5F13IV    = [4]uint32{0x79e0f2fb, 0xc8b52570, 0xebc2f8cd, 0x7c104d93}
	hongguoV5F13Final = [4]uint32{0x19be4866, 0xe85986b4, 0xe19b326e, 0x71d1d7d4}
	hongguoV5F13Pad   = [8]byte{0x84, 0x96, 0x77, 0x9d, 0xd4, 0x15, 0x0b, 0xf8}
	hongguoV5F13K     = [64]uint32{
		0xa7aefe20, 0x7149f1d6, 0x47e4ca07, 0xe9b58f67, 0x93b924de, 0xc614d0f5, 0x38afe0ef, 0xb2bbad73,
		0xe24444c3, 0x9d3aec9b, 0xdf7b37e4, 0xd8b16d40, 0xf8ac31b8, 0x76b9a90b, 0x31d833ee, 0x953fce64,
		0x6a6b2b48, 0x8c138276, 0x6d24a010, 0x18da124b, 0xbbeb82ee, 0x39f7ea56, 0x149f4fe1, 0x229946bc,
		0x0327f309, 0xf4f50e66, 0x62d569aa, 0x78419f92, 0x4db088a7, 0x7430a018, 0xf31d88f4, 0x2f4ed651,
		0x9b13fe59, 0x45c5910d, 0x374bf0ec, 0xd5a5b69e, 0xefaceb16, 0x714f4811, 0x4c98233b, 0xc9e6e7b1,
		0xd0623b3f, 0xdf5e4f6f, 0xccb31244, 0xaddab856, 0x6faf9c9e, 0x62804e10, 0x6fa7e29d, 0x7e429d51,
		0xcdb31e01, 0xb339e419, 0xe497a8a3, 0xebeca6bc, 0x1746cd57, 0xfbf4f54a, 0xd5ea2a8b, 0xb4f02ed2,
		0x0512b192, 0xefad4d29, 0xd59bec05, 0x2a1436e2, 0xfaea73c1, 0x1ebdbae8, 0x8ff257bd, 0x2d59351d,
	}
	hongguoV5F13Order = [64]uint8{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		0, 10, 5, 14, 3, 4, 15, 13, 6, 1, 12, 8, 9, 7, 11, 2,
		8, 10, 3, 1, 14, 3, 7, 2, 5, 0, 13, 9, 11, 4, 15, 12,
		8, 9, 15, 10, 2, 6, 5, 13, 13, 1, 7, 3, 11, 14, 4, 12,
	}
	hongguoV5F13Shift = [64]uint8{
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
	}
	hongguoV5Branch0TT = [64]uint32{
		0xebb64faf, 0x07aadcc2, 0xcf3187bf, 0xe01138ff, 0x6d0bfcff, 0x5a30a3be, 0xb41ad638, 0x34180eb8,
		0xf233eb6f, 0xb1a584cc, 0xccc30dc7, 0x47d1db51, 0xd55653de, 0x70a84fa1, 0x57473c12, 0xf76f0288,
		0x2c077f0a, 0xda0dcad0, 0xfbb86f6c, 0xfdc4cf00, 0x688a020d, 0xe676c6a6, 0x8cd6338b, 0x1a3c8d0e,
		0xcce8b06b, 0x6ad0ed0b, 0xa0522717, 0xdc71ac83, 0x2285db71, 0xd5b4dda6, 0x736f8650, 0x6560306c,
		0x617ce2a6, 0xe423417e, 0x0a40e143, 0x544e4032, 0x88dffb2a, 0x716c1ae0, 0x4c467a88, 0x05b23bb3,
		0xe1d0b866, 0xbaa3dcb8, 0xae3374d3, 0xc3381a50, 0x1702f75b, 0xfe6da368, 0xf0b4cf48, 0x4e0ffbb8,
		0x72aad10d, 0x26c53a3d, 0xf2bce0f6, 0xb4557581, 0x4a257fdd, 0x8c3182a2, 0xab0b3b86, 0x3d5dfb14,
		0x4f103634, 0xd37b52d7, 0x444eff16, 0xeb0a33d1, 0x6ca86f6e, 0x00284ba7, 0x08387cfa, 0x5fb37586,
	}
	hongguoV5Branch0Init = [8]uint32{
		0x7aba4fc8, 0x67166507, 0x6403fa00, 0x340f512f,
		984304912, 3005047866, 2874125293, 2152413264,
	}
)

var hongguoV5AesCon2 = [4][4]int{{1, 0, 2, 3}, {2, 0, 3, 1}, {0, 1, 3, 2}, {1, 0, 2, 3}}

var hongguoV5AesOrder = [4][16]int{
	{0, 9, 14, 11, 4, 13, 2, 7, 8, 1, 6, 15, 12, 5, 10, 3},
	{0, 9, 14, 15, 4, 13, 2, 7, 8, 1, 6, 3, 12, 5, 10, 11},
	{0, 9, 14, 7, 4, 13, 2, 11, 8, 1, 6, 3, 12, 5, 10, 15},
	{0, 9, 14, 11, 4, 13, 2, 7, 8, 1, 6, 15, 12, 5, 10, 3},
}

var hongguoV5AesInitWord = [4]uint32{0xca025ddc, 0x823dc546, 0xc9420583, 0xc298225f}

type hongguoV5Aes struct {
	box   []byte
	con2  [4]int
	order [16]int
	keys  [12][4]byte
}

func hongguoV5ExpandAESWith(key []byte, init uint32, box []byte) [12][4]byte {
	initial := make([]byte, 0, 16)
	var le [4]byte
	binary.LittleEndian.PutUint32(le[:], init)
	for i := 0; i < 4; i++ {
		initial = append(initial, le[:]...)
	}
	expanded := hongguoV5XorBytes(initial, key)
	expanded = append(expanded, make([]byte, 32)...)
	rounds := uint32(8)
	for i := 4; i < 12; i++ {
		at := 4 * (i - 1)
		a, b, c, d := expanded[at], expanded[at+1], expanded[at+2], expanded[at+3]
		if i&3 == 0 {
			t := ((init >> (rounds & 24)) ^ uint32(box[b])) & 255
			b = box[c]
			c = box[d]
			d = box[a]
			a = byte(t)
		}
		rounds += 2
		expanded[at+4] = a ^ expanded[at-12]
		expanded[at+5] = b ^ expanded[at-11]
		expanded[at+6] = c ^ expanded[at-10]
		expanded[at+7] = d ^ expanded[at-9]
	}
	var keys [12][4]byte
	for i := range keys {
		copy(keys[i][:], expanded[i*4:i*4+4])
	}
	return keys
}

func hongguoV5XorBytes(a, b []byte) []byte {
	out := append([]byte{}, a...)
	for i := range out {
		out[i] ^= b[i%len(b)]
	}
	return out
}

func hongguoV5AesAddCon(state *[4][4]byte, keys [][4]byte, con2 [4]int) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] ^= keys[i][con2[j]]
		}
	}
}

func (a hongguoV5Aes) sub(state *[4][4]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] = a.box[state[i][j]]
		}
	}
	old := *state
	for i := 0; i < 4; i++ {
		state[i] = old[a.con2[i]]
	}
}

func (a hongguoV5Aes) shift(state *[4][4]byte) {
	var flat [16]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			flat[i*4+j] = state[i][j]
		}
	}
	for i := 0; i < 16; i++ {
		state[i/4][i%4] = flat[a.order[i]]
	}
}

func hongguoV5AesShiftCon(state *[4][4]byte, con2 [4]int) {
	old := *state
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] = old[i][con2[j]]
		}
	}
}

func hongguoV5AesMixColumns(state *[4][4]byte) {
	xt := func(x byte) byte {
		v := x << 1
		if x&128 != 0 {
			v ^= 0x1b
		}
		return v
	}
	for i := 0; i < 4; i++ {
		t := state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i]
		u := state[0][i]
		state[0][i] ^= t ^ xt(state[0][i]^state[1][i])
		state[1][i] ^= t ^ xt(state[1][i]^state[2][i])
		state[2][i] ^= t ^ xt(state[2][i]^state[3][i])
		state[3][i] ^= t ^ xt(state[3][i]^u)
	}
}

func (a hongguoV5Aes) block(value []byte) []byte {
	var state [4][4]byte
	for i := 0; i < 4; i++ {
		copy(state[i][:], value[i*4:i*4+4])
	}
	keys := a.keys[:]
	hongguoV5AesAddCon(&state, keys[0:4], a.con2)
	for i := 1; i < 3; i++ {
		a.sub(&state)
		a.shift(&state)
		if i == 1 {
			hongguoV5AesShiftCon(&state, a.con2)
			hongguoV5AesMixColumns(&state)
		}
		hongguoV5AesAddCon(&state, keys[i*4:i*4+4], a.con2)
	}
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] ^= keys[4+i][j]
		}
	}
	out := make([]byte, 0, 16)
	for i := 0; i < 4; i++ {
		out = append(out, state[i][:]...)
	}
	return out
}

func hongguoV5EncryptPlayback(data, key, iv []byte, timestamp uint32) []byte {
	word := timestamp & 3
	box := hongguoV5Sbox[word*256 : (word+1)*256]
	initial := [4]uint32{0xbbb5de72, 0xd4638d5b, 0x92a5f73b, 0x89f8a1c9}[word]
	cipher := hongguoV5Aes{
		box:  box,
		con2: [4][4]int{{2, 0, 3, 1}, {1, 3, 2, 0}, {3, 2, 1, 0}, {2, 3, 1, 0}}[word],
		order: [4][16]int{
			{0, 9, 14, 15, 4, 13, 2, 7, 8, 1, 6, 3, 12, 5, 10, 11},
			{0, 9, 14, 11, 4, 13, 2, 3, 8, 1, 6, 15, 12, 5, 10, 7},
			{0, 9, 14, 3, 4, 13, 2, 15, 8, 1, 6, 11, 12, 5, 10, 7},
			{0, 9, 14, 15, 4, 13, 2, 3, 8, 1, 6, 11, 12, 5, 10, 7},
		}[word],
		keys: hongguoV5ExpandAESWith(key, initial, box),
	}
	wire := [8]uint{6, 5, 3, 4, 2, 7, 1, 0}
	compact := [8]uint{1, 7, 3, 6, 2, 0, 4, 5}
	var plain [32]byte
	for i := 0; i < 31; i++ {
		for j := range wire {
			at := i*8 + j
			if at < len(data) {
				plain[i] |= ((data[at] >> wire[j]) & 1) << compact[j]
			}
		}
	}
	plain[31] = 1
	first := cipher.block(hongguoV5XorBytes(plain[:16], iv))
	bits := append(first, cipher.block(hongguoV5XorBytes(plain[16:], first))...)
	out := append([]byte(nil), data...)
	for i := 0; i < 31; i++ {
		for j := range wire {
			at := i*8 + j
			if at < len(out) {
				out[at] = (out[at] &^ (1 << wire[j])) | (((bits[i] >> compact[j]) & 1) << wire[j])
			}
		}
	}
	return append([]byte{bits[31]}, out...)
}

func hongguoV5Helios(ts, random uint32) string {
	seed := hongguoV5Md5(append(hongguoV5Le32(random), []byte(hongguoV5AppID)...))
	ascii := []byte(hex.EncodeToString(seed[:]))
	words := make([]uint64, 4)
	for i := range words {
		words[i] = binary.LittleEndian.Uint64(ascii[i*8:])
	}
	table := hongguoV5Diffuse(words)
	text := []byte(fmt.Sprintf("%d-%s-%s", ts, hongguoV5License, hongguoV5AppID))
	padding := byte(16 - len(text)%16)
	for range int(padding) {
		text = append(text, padding)
	}
	out := hongguoV5Le32(random)
	for at := 0; at < len(text); at += 16 {
		a := binary.LittleEndian.Uint64(text[at:])
		b := binary.LittleEndian.Uint64(text[at+8:])
		for _, key := range table[:34] {
			b = key ^ (a + hongguoV5Ror64(b, 8))
			a = b ^ hongguoV5Ror64(a, 61)
		}
		var block [16]byte
		binary.LittleEndian.PutUint64(block[:8], a)
		binary.LittleEndian.PutUint64(block[8:], b)
		out = append(out, block[:]...)
	}
	return base64.StdEncoding.EncodeToString(out)
}

func hongguoV5Diffuse(words []uint64) []uint64 {
	table := []uint64{words[0]}
	b0 := words[0]
	b8 := words[1]
	queue := append([]uint64{}, words[2:]...)
	for i := uint64(0); i < 34; i++ {
		x8 := hongguoV5Ror64(b8, 8) + b0
		x8 ^= i
		queue = append(queue, x8)
		x8 ^= hongguoV5Ror64(b0, 61)
		table = append(table, x8)
		b0 = x8
		b8 = queue[0]
		queue = queue[1:]
	}
	return table
}

type hongguoV5Entropy struct {
	MessageRandom uint32
	Random        uint32
	PackedRandom  uint32
	HeliosRandom  uint32
}

type hongguoV5MedusaRandom struct {
	Message uint32
	Key     uint32
	Packed  uint32
}

type hongguoV5MedusaDevice struct {
	AppVersion    string
	Model         string
	Brand         string
	OSVersion     string
	InstallMillis int64
	StorageGB     float32
	StorageFreeGB float32
	MemoryGB      float32
	MemoryFreeGB  float32
}

type hongguoV5MedusaEnv struct {
	PID          int64
	PPID         int64
	LaunchMillis int64
	Clock18      int64
	Clock19      int64
	Clock20      int64
	Channel      string
	UnH          int64
	Fkd          int64
	Pd           int64
	Sts          int64
	Lp           string
	Fl           string
	Status       int64
	Device       *hongguoV5MedusaDevice
}

const hongguoV5NotSet = "!notset!"

const hongguoV5UnsetInt = -999999

const hongguoV5NoPerm = "!noperm!"

const hongguoV5NoPermInt = -888888

const hongguoV5MedusaInstallAnchor = 1795440816000

var hongguoV5EmulatorFlags = []byte{0x08, 0, 0, 0, 0, 0, 0, 0}

var hongguoV5DeviceFlags = []byte{0x04, 0x05, 0, 0, 0, 0, 0, 0}

func hongguoV5DefaultMedusaEnv(launchMillis int64) hongguoV5MedusaEnv {
	return hongguoV5MedusaEnv{
		PID: 4321, PPID: 1234,
		LaunchMillis: launchMillis,
		Clock18:      766353820, Clock19: 16, Clock20: -1072050540,
		Channel: "update_64",
		UnH:     2398682137, Sts: 27, Fkd: 1963693275, Pd: 1442983616,
		Lp:     "2|520830913092|521433182354|2078052786776|1081701896",
		Fl:     "0|0|2523408538|2586339478|997724116|0|0|0|0|606600138",
		Status: hongguoV5DeviceStatus,
	}
}

var (
	hongguoV5MedusaEnvOnce sync.Once
	hongguoV5MedusaEnvVal  hongguoV5MedusaEnv
)

func hongguoV5ProcessMedusaEnv() hongguoV5MedusaEnv {
	hongguoV5MedusaEnvOnce.Do(func() {
		now := time.Now()
		hongguoV5MedusaEnvVal = hongguoV5DefaultMedusaEnv(now.UnixMilli())
		hongguoV5MedusaEnvVal.PID = 3000 + now.UnixNano()%25000
		hongguoV5MedusaEnvVal.PPID = 500 + (now.UnixNano()/25000)%700
	})
	return hongguoV5MedusaEnvVal
}

func (env hongguoV5MedusaEnv) flags() []byte {
	if env.Device != nil {
		return hongguoV5DeviceFlags
	}
	return hongguoV5EmulatorFlags
}

func hongguoV5RequestMedusaEnv(query, deviceID string) hongguoV5MedusaEnv {
	env := hongguoV5ProcessMedusaEnv()
	env.Device = hongguoV5MedusaDeviceOf(query, deviceID)
	return env
}

func hongguoV5MedusaDeviceOf(query, deviceID string) *hongguoV5MedusaDevice {
	model := hongguoV5QueryValue(query, "device_type")
	if model == "" {
		return nil
	}
	h := sha256.Sum256([]byte("medusa-device\x00" + deviceID))
	pick := func(i int, n uint32) uint32 { return binary.LittleEndian.Uint32(h[i*4:]) % n }
	storage := []float32{106.83, 108.57, 229.36, 233.91, 487.62}[pick(0, 5)] + float32(pick(1, 400))/1000
	memory := []float32{5.37, 7.42, 11.18, 15.07}[pick(2, 4)] + float32(pick(3, 90))/1000
	const day = 24 * 60 * 60 * 1000
	return &hongguoV5MedusaDevice{
		AppVersion:    hongguoV5QueryValue(query, "version_name"),
		Model:         model,
		Brand:         hongguoV5QueryValue(query, "device_brand"),
		OSVersion:     hongguoV5QueryValue(query, "os_version"),
		InstallMillis: hongguoV5MedusaInstallAnchor - day - int64(pick(4, 20*day)),
		StorageGB:     storage,
		StorageFreeGB: storage * (0.25 + float32(pick(5, 500))/1000),
		MemoryGB:      memory,
		MemoryFreeGB:  0.35 + float32(pick(6, 900))/1000,
	}
}

var (
	hongguoV5MedusaCounterOnce sync.Once
	hongguoV5MedusaCounter     atomic.Int64
)

func hongguoV5NextMedusaCount() int64 {
	hongguoV5MedusaCounterOnce.Do(func() { hongguoV5MedusaCounter.Store(20 + time.Now().UnixNano()%100) })
	return hongguoV5MedusaCounter.Add(1)
}

func hongguoV5MedusaV5DeviceBlock(deviceID string, env hongguoV5MedusaEnv, nowMillis int64) []byte {
	d := env.Device
	str := func(tag uint32, s string) []byte {
		if s == "" {
			s = hongguoV5NotSet
		}
		return hongguoV5ProtoString(tag, s)
	}
	return hongguoV5Concat(
		hongguoV5ProtoSInt(1, 1),
		hongguoV5ProtoString(3, hongguoV5AppID),
		hongguoV5ProtoString(4, deviceID),
		hongguoV5ProtoString(5, hongguoV5NotSet),
		hongguoV5ProtoString(6, hongguoV5NoPerm),
		hongguoV5ProtoSInt(7, hongguoV5NoPermInt),
		hongguoV5ProtoSInt(8, hongguoV5NoPermInt),
		hongguoV5ProtoSInt(9, 2),
		hongguoV5ProtoSInt(10, hongguoV5NoPermInt),
		hongguoV5ProtoString(11, hongguoV5NotSet),
		hongguoV5ProtoString(12, "Asia/Shanghai,8"),
		hongguoV5ProtoString(13, "zh_CN"),
		hongguoV5ProtoSInt(14, 8),
		hongguoV5ProtoFloat(16, d.StorageGB),
		hongguoV5ProtoFloat(17, d.StorageFreeGB),
		hongguoV5ProtoFloat(18, d.MemoryGB),
		hongguoV5ProtoFloat(19, d.MemoryFreeGB),
		hongguoV5ProtoFloat(20, d.StorageGB*2),
		hongguoV5ProtoFloat(21, d.StorageFreeGB*2),
		str(22, d.OSVersion),
		hongguoV5ProtoSInt(23, 60),
		hongguoV5ProtoSInt(24, 10),
		hongguoV5ProtoSInt(25, d.InstallMillis),
		hongguoV5ProtoSInt(26, env.LaunchMillis+540),
		hongguoV5ProtoSInt(27, d.InstallMillis),
		hongguoV5ProtoSInt(28, nowMillis),
		hongguoV5ProtoSInt(29, 1),
		str(30, d.Model),
		str(31, d.Brand),
		hongguoV5ProtoString(32, hongguoV5NotSet),
		hongguoV5ProtoString(33, hongguoV5NotSet),
		hongguoV5ProtoString(34, hongguoV5NotSet),
		str(35, d.Brand),
		hongguoV5ProtoString(36, hongguoV5NotSet),
		hongguoV5ProtoSInt(38, 3),
		hongguoV5ProtoSInt(40, env.LaunchMillis),
	)
}

func hongguoV5MedusaV5Device(deviceID string, env hongguoV5MedusaEnv) []byte {
	out := hongguoV5Concat(hongguoV5ProtoSInt(1, 1), hongguoV5ProtoString(3, hongguoV5AppID), hongguoV5ProtoString(4, deviceID))
	for tag := uint32(5); tag <= 40; tag++ {
		switch {
		case tag == 5 || tag == 6 || (tag >= 11 && tag <= 13) || tag == 15 || tag == 22 || (tag >= 30 && tag <= 37):
			out = append(out, hongguoV5ProtoString(tag, hongguoV5NotSet)...)
		case (tag >= 7 && tag <= 10) || tag == 14 || (tag >= 23 && tag <= 25) || tag == 27 || tag == 29 || tag == 38:
			out = append(out, hongguoV5ProtoSInt(tag, hongguoV5UnsetInt)...)
		case tag >= 16 && tag <= 21:
			out = append(out, hongguoV5ProtoFloat(tag, hongguoV5UnsetInt)...)
		case tag == 26 || tag == 28 || tag == 40:
			out = append(out, hongguoV5ProtoSInt(tag, env.LaunchMillis)...)
		}
	}
	return out
}

type hongguoV5MedusaInput struct {
	querySM3 [32]byte
	bodyMD5  [16]byte
	digest   [20]byte
	ts       uint32
}

func hongguoV5NewMedusaInput(query string, body []byte, ts uint32) (hongguoV5MedusaInput, bool) {
	in := hongguoV5MedusaInput{querySM3: hongguoV5Sm3([]byte(query)), ts: ts}
	if body != nil {
		in.bodyMD5 = hongguoV5Md5(body)
	}
	digest, ok := hongguoV5F13(in.querySM3, in.bodyMD5, ts)
	in.digest = digest
	return in, ok
}

func hongguoV5AssembleMedusa(in hongguoV5MedusaInput, deviceID string, env hongguoV5MedusaEnv, rnd hongguoV5MedusaRandom) string {
	return hongguoV5SealMedusa(hongguoV5MedusaMessage(in, deviceID, env, rnd), in, rnd, env.flags())
}

func hongguoV5MedusaMessage(in hongguoV5MedusaInput, deviceID string, env hongguoV5MedusaEnv, rnd hongguoV5MedusaRandom) []byte {
	ts := in.ts
	const unset = 694367
	counters := hongguoV5Concat(hongguoV5ProtoSInt(1, unset), hongguoV5ProtoSInt(2, unset), hongguoV5ProtoSInt(3, unset), hongguoV5ProtoSInt(5, unset))
	var appVersion []byte
	if env.Device != nil {
		counters = hongguoV5Concat(hongguoV5ProtoSInt(1, hongguoV5NextMedusaCount()), hongguoV5ProtoSInt(2, 5), hongguoV5ProtoSInt(3, unset), hongguoV5ProtoSInt(5, unset))
		appVersion = hongguoV5ProtoString(7, env.Device.AppVersion)
	}
	return hongguoV5Concat(
		hongguoV5ProtoBytes(1, hongguoV5Magic),
		hongguoV5ProtoSInt(2, hongguoV5MedusaVersion),
		hongguoV5ProtoSInt(3, int64(rnd.Message)),
		hongguoV5ProtoString(4, hongguoV5AppID),
		hongguoV5ProtoString(5, deviceID),
		hongguoV5ProtoString(6, hongguoV5License),
		appVersion,
		hongguoV5ProtoString(8, hongguoV5MedusaSDKVersion),
		hongguoV5ProtoSInt(9, hongguoV5MedusaSDKCode),
		hongguoV5ProtoBytes(10, env.flags()),
		hongguoV5ProtoSInt(12, int64(ts)),
		hongguoV5ProtoBytes(13, in.digest[:]),
		hongguoV5ProtoBytes(14, in.querySM3[:6]),
		hongguoV5ProtoBytes(15, counters),
		hongguoV5ProtoSInt(17, int64(ts)),
		hongguoV5ProtoString(20, "none"),
		hongguoV5ProtoSInt(21, env.Status),
		hongguoV5ProtoBytes(23, hongguoV5MedusaEnvBytes(ts, deviceID, env, rnd)),
		hongguoV5ProtoString(24, hongguoV5MedusaJSON(env)),
	)
}

func hongguoV5MedusaEnvBytes(ts uint32, deviceID string, env hongguoV5MedusaEnv, rnd hongguoV5MedusaRandom) []byte {
	if d := env.Device; d != nil {
		uptime := int64(ts) - env.LaunchMillis/1000
		if uptime < 1 {
			uptime = 1
		}
		version := d.AppVersion
		if version == "" {
			version = hongguoV5NotSet
		}
		return hongguoV5Concat(
			hongguoV5ProtoSInt(1, uptime),
			hongguoV5ProtoString(6, hongguoV5MedusaEnvVersion),
			hongguoV5ProtoSInt(7, env.PID),
			hongguoV5ProtoString(8, env.Channel),
			hongguoV5ProtoBytes(12, hongguoV5MedusaV5DeviceBlock(deviceID, env, int64(ts)*1000+int64(rnd.Message%1000))),
			hongguoV5ProtoEmpty(13),
			hongguoV5ProtoString(14, version),
			hongguoV5ProtoSInt(15, env.PPID),
			hongguoV5ProtoSInt(18, int64(ts)+env.Clock18),
			hongguoV5ProtoSInt(19, int64(ts)+env.Clock19),
			hongguoV5ProtoSInt(20, int64(ts)+env.Clock20),
		)
	}
	return hongguoV5Concat(
		hongguoV5ProtoString(6, hongguoV5MedusaEnvVersion),
		hongguoV5ProtoSInt(7, env.PID),
		hongguoV5ProtoString(8, env.Channel),
		hongguoV5ProtoBytes(12, hongguoV5MedusaV5Device(deviceID, env)),
		hongguoV5ProtoEmpty(13),
		hongguoV5ProtoString(14, hongguoV5NotSet),
		hongguoV5ProtoSInt(15, env.PPID),
		hongguoV5ProtoSInt(18, int64(ts)+env.Clock18),
		hongguoV5ProtoSInt(19, int64(ts)+env.Clock19),
		hongguoV5ProtoSInt(20, int64(ts)+env.Clock20),
	)
}

func hongguoV5MedusaJSON(env hongguoV5MedusaEnv) string {
	return fmt.Sprintf(`{"cmr":16777216,"cmr2":16777216,"un_h":%d,"vpn":0,"sts":%d,"kd":0,"fkd":%d,"pd":%d,"lp":%s,"fl":%s,"dyn":"","do":0,"tk":true}`,
		env.UnH, env.Sts, env.Fkd, env.Pd, strconv.Quote(env.Lp), strconv.Quote(env.Fl))
}

func hongguoV5Xmxor(data, key []byte) []byte {
	n := len(data)
	encoded := make([]byte, n)
	for i := 0; i < n; i++ {
		at := (i * 4) & 28
		d0 := key[at]
		d1 := key[at+1]
		d2 := byte((uint32((data[i]<<4)|(data[i]>>4)) + uint32(d0)))
		d2 = ^d2 ^ d1
		d2 = (d2 << 3) | (d2 >> 5)
		d2 += d1
		d2 ^= d0
		encoded[n-i-1] = ^d2
	}
	last := encoded[n-1] ^ encoded[n-2]
	first := encoded[0]
	encoded[0] = (^last) + first
	encoded[1] = (encoded[0] ^ encoded[n-1] ^ 254) + encoded[1]
	shifted := (encoded[1] << 3) | (encoded[1] >> 5)
	fix2 := (last - first) ^ (shifted ^ 2)
	encoded[2] += fix2
	for i := 0; i < n-4; i++ {
		sh := (encoded[i+2] << 3) | (encoded[i+2] >> 5)
		temp := sh ^ encoded[i+1] ^ byte(i+3)
		encoded[i+3] = (^temp) + encoded[i+3]
	}
	encoded[n-1] ^= encoded[n-2]
	var sum uint32
	for _, item := range encoded[1:] {
		sum += uint32(item)
	}
	encoded[0] = (encoded[0] ^ encoded[1]) + byte(sum)
	return encoded
}

func hongguoV5KeyHash(signKey []byte, random uint32) ([32]byte, [4]byte) {
	buf := append([]byte{}, signKey...)
	buf = append(buf, hongguoV5Le32(random)...)
	buf = append(buf, signKey...)
	hash := hongguoV5Sm3(buf)
	d1 := byte((random >> 16) & 255)
	d2 := (uint32(d1) << 11) | (random >> 24)
	d2 ^= uint32(d1) >> 5
	d2 ^= uint32(d1)
	d2 = ^d2
	var seed [4]byte
	copy(seed[:], hongguoV5Le32(d2))
	return hash, seed
}

func hongguoV5SealMedusa(message []byte, in hongguoV5MedusaInput, rnd hongguoV5MedusaRandom, flags []byte) string {
	ts := in.ts
	hash, seed := hongguoV5KeyHash(hongguoV5SignKey, rnd.Key)
	transformed := append(append([]byte(nil), flags...), hongguoV5Xmxor(message, hash[:])...)
	for i, j := 0, len(transformed)-1; i < j; i, j = i+1, j-1 {
		transformed[i], transformed[j] = transformed[j], transformed[i]
	}
	for i := range transformed {
		transformed[i] ^= seed[(^i)&3]
	}
	check := uint32(0x18000001) | uint32(in.querySM3[0]&63)<<14 | uint32(in.digest[0]&63)<<8
	packed := hongguoV5Concat([]byte{hongguoV5MedusaPackedHead}, hongguoV5Le32(rnd.Packed), hongguoV5Le32(check), transformed, []byte{byte(rnd.Key >> 16), byte(rnd.Key >> 24)})
	key := hongguoV5Md5(hongguoV5SignKey[:16])
	iv := hongguoV5Md5(hongguoV5SignKey[16:])
	encrypted := hongguoV5EncryptPlayback(packed, key[:], iv[:], ts)
	prefix := hongguoV5Concat(hongguoV5Le32(hongguoV5MedusaVersion), hongguoV5Magic)
	for i := range prefix {
		prefix[i] ^= byte(ts >> (uint(i&3) * 8))
	}
	return base64.StdEncoding.EncodeToString(hongguoV5Concat(prefix, []byte{byte(rnd.Key), byte(rnd.Key >> 8), 0, 1}, encrypted))
}

func hongguoV5DrawEntropy(nowMillis int64) hongguoV5Entropy {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return hongguoV5Entropy{
		MessageRandom: binary.LittleEndian.Uint32(buf[0:4]),
		Random:        binary.LittleEndian.Uint32(buf[4:8]),
		PackedRandom:  binary.LittleEndian.Uint32(buf[8:12]),
		HeliosRandom:  binary.LittleEndian.Uint32(buf[12:16]),
	}
}

func (e hongguoV5Entropy) medusaRandom() hongguoV5MedusaRandom {
	return hongguoV5MedusaRandom{Message: e.MessageRandom & 0x7fffffff, Key: e.Random & 0x7fffffff, Packed: e.PackedRandom & 0x7fffffff}
}

func hongguoV5SignPlayback(pairs [][2]string, nowMillis int64, body []byte, entropy *hongguoV5Entropy) (string, map[string]string, error) {
	ts := uint32(nowMillis / 1000)
	bodyMD5 := [16]byte{}
	if body != nil {
		bodyMD5 = hongguoV5Md5(body)
	}
	withTicket := append([][2]string(nil), pairs...)
	slot := -1
	for i, kv := range withTicket {
		if kv[0] == "_rticket" {
			slot = i
			break
		}
	}
	if slot < 0 {
		withTicket = append(withTicket, [2]string{"_rticket", ""})
		slot = len(withTicket) - 1
	}
	for offset := int64(0); offset < 1024; offset++ {
		withTicket[slot][1] = strconv.FormatInt(nowMillis+offset, 10)
		query := hongguoV5EncodeQuery(withTicket)
		medusaIn, ok := hongguoV5NewMedusaInput(query, body, ts)
		if !ok {
			continue
		}
		ent := hongguoV5Entropy{}
		if entropy == nil {
			ent = hongguoV5DrawEntropy(nowMillis)
		} else {
			ent = *entropy
		}
		headers := map[string]string{
			"x-khronos": strconv.FormatUint(uint64(ts), 10),
			"x-helios":  hongguoV5Helios(ts, ent.HeliosRandom),
			"x-medusa":  hongguoV5AssembleMedusa(medusaIn, hongguoV5QueryValue(query, "device_id"), hongguoV5RequestMedusaEnv(query, hongguoV5QueryValue(query, "device_id")), ent.medusaRandom()),
		}
		if body != nil {
			headers["Content-Type"] = "application/json; charset=utf-8"
			headers["x-ss-stub"] = strings.ToUpper(hex.EncodeToString(bodyMD5[:]))
		}
		return query, headers, nil
	}
	return "", nil, fmt.Errorf("playback V5 signing branch unavailable")
}

func hongguoV5PlaybackPairs(deviceID, installID, cdid string) [][2]string {
	version := hongguoPlaybackVersionCode
	return [][2]string{
		{"device_platform", "android"},
		{"os", "android"},
		{"ssmix", "a"},
		{"_rticket", ""},
		{"cdid", cdid},
		{"channel", "update_64"},
		{"aid", "8662"},
		{"app_name", "novelread"},
		{"version_code", version},
		{"version_name", hongguoPlaybackVersionName},
		{"manifest_version_code", version},
		{"update_version_code", version},
		{"resolution", "1280*2772"},
		{"dpi", "520"},
		{"device_type", "25053RT47C"},
		{"device_brand", "Redmi"},
		{"language", "zh"},
		{"os_api", "36"},
		{"os_version", "16"},
		{"ac", "wifi"},
		{"host_abi", "arm64-v8a"},
		{"dragon_device_type", "phone"},
		{"pv_player", version},
		{"compliance_status", "0"},
		{"need_personal_recommend", "1"},
		{"player_so_load", "1"},
		{"is_android_pad_screen", "0"},
		{"iid", installID},
		{"device_id", deviceID},
	}
}

func hongguoV5NewCDID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	var s [36]byte
	hex.Encode(s[0:8], raw[0:4])
	s[8] = '-'
	hex.Encode(s[9:13], raw[4:6])
	s[13] = '-'
	hex.Encode(s[14:18], raw[6:8])
	s[18] = '-'
	hex.Encode(s[19:23], raw[8:10])
	s[23] = '-'
	hex.Encode(s[24:36], raw[10:16])
	return string(s[:])
}

func hongguoV5ReadingRequestID(millis int64) string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return strconv.FormatInt(millis, 10) + "-0"
	}
	n := int64(binary.BigEndian.Uint64(raw[:]) & 0x7fffffffffffffff)
	return strconv.FormatInt(millis, 10) + "-" + strconv.FormatInt(n, 10)
}
