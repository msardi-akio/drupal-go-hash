package drupalGoHash

import (
	"bytes"
	"crypto/md5"
	"crypto/sha512"

	"encoding/hex"
	"hash"
	"math"
	"strings"
)

const DRUPAL_HASH_LENGTH = 55
const DRUPAL_MIN_HASH_COUNT = 7
const DRUPAL_MAX_HASH_COUNT = 30

func CheckPassword(dbHash string, pass string) bool {
	var storedHash string
	if dbHash[:2] == "U$" {
		// This may be an updated password from user_update_7000(). Such hashes
		// have 'U' added as the first character and need an extra md5().
		storedHash = dbHash[1:]
		b := md5.Sum([]byte(pass))
		pass = hex.EncodeToString(b[:])
	} else {
		storedHash = dbHash
	}

	hashType := storedHash[:3]
	var hash string
	switch hashType {
	case "$S$":
		// println("Hash is sha512")
		hash = password_crypt("sha512", pass, storedHash)

	case "$H$":
	case "$P$":
		// println("Hash is md5")
		hash = password_crypt("md5", pass, storedHash)

	default:
		simpleMd5 := md5.Sum([]byte(pass))
		hash = hex.EncodeToString(simpleMd5[:])
	}
	return (len(hash) > 0 && storedHash == hash)
}

func password_crypt(algo string, password string, setting string) string {
	if len(password) > 512 {
		panic(false)
	}
	setting = setting[:12]
	// println("Short setting: ", setting)
	if setting[0] != '$' || setting[2] != '$' {
		panic(false)
	}
	countLog2 := password_get_count_log2(setting)
	if countLog2 < DRUPAL_MIN_HASH_COUNT || countLog2 > DRUPAL_MAX_HASH_COUNT {
		println(countLog2)
		panic(false)
	}
	// println("CountLog2: ", countLog2)
	salt := setting[4:12]
	// println("Salt: " + salt)
	if len(salt) != 8 {
		panic(false)
	}
	count := int(math.Pow(2, float64(countLog2)))
	// MD5
	var hashAlg hash.Hash
	switch algo {
	case "md5":
		hashAlg = md5.New()
	default:
		hashAlg = sha512.New()
	}

	hashAlg.Write([]byte(salt))
	hashAlg.Write([]byte(password))
	hash := hashAlg.Sum(nil)

	for i := 0; i < count; i++ {
		hashAlg.Reset()
		hashAlg.Write(hash)
		hashAlg.Write([]byte(password))
		hash = hashAlg.Sum(nil)
	}
	length := len(hash)
	println("Hash: ", hex.EncodeToString(hash))

	output := setting + passwordBase64Encode(hash)
	println("Output: ", output)
	expected := 12 + int(math.Ceil((float64(8*length) / float64(6))))

	if len(output) == expected {
		return output[:DRUPAL_HASH_LENGTH]
	} else {
		panic(false)
	}

}

const passwordItoA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func passwordBase64Encode(input []byte) string {
	output := bytes.Buffer{}
	i := 0
	count := len(input)
	for i < count {
		value := uint(input[i])
		i++
		output.WriteByte(passwordItoA64[value&0x3f])
		if i < count {
			value |= uint(input[i]) << 8
		}
		output.WriteByte(passwordItoA64[(value>>6)&0x3f])
		i++
		if i >= count {
			break
		}
		if i < count {
			value |= uint(input[i]) << 16
		}
		output.WriteByte(passwordItoA64[(value>>12)&0x3f])
		i++
		if i >= count {
			break
		}
		output.WriteByte(passwordItoA64[(value>>18)&0x3f])
	}

	return output.String()
}

func password_get_count_log2(setting string) int {
	itoa64 := password_itoa64()
	return strings.Index(itoa64, string(setting[3]))
}

func password_itoa64() string {
	return "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
}
