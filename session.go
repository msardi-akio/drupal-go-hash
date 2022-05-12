package drupalGoHash

import (
	"crypto/sha256"
	"encoding/base64"
)

func GetCookieName(cookieDomain string, ssl bool) string {
	var prefix string
	if ssl {
		prefix = "SSESS"
	} else {
		prefix = "SESS"
	}
	hasher := sha256.New()
	hasher.Write([]byte(cookieDomain))
	rawHash := hasher.Sum(nil)[0:32]
	hash := base64.URLEncoding.EncodeToString(rawHash)
	return prefix + hash
}
