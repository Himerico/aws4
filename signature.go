package aws4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type AuthInfo struct {
	AK        string
	SK        string
	Token     string
	SpaceName string
	Service   string
	Region    string
	AmzDate   string
	Algorithm string
	Params    map[string]string
}

func GetSignature(authInfo *AuthInfo) (string, error) {
	if !dataCheck(authInfo) {
		return "", fmt.Errorf("Incomplete argument")
	}
	dateStamp := strings.Split(authInfo.AmzDate, "T")[0]
	skp := signatureKeyParam{
		secretKey: authInfo.SK,
		datestamp: dateStamp,
		region:    authInfo.Region,
		service:   authInfo.Service,
	}
	hashCanonicalRequestStr := getHashCanonicalRequestStr(authInfo)
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, authInfo.Region, authInfo.Service)
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s", authInfo.Algorithm, authInfo.AmzDate, credentialScope, hashCanonicalRequestStr)
	signingKey := skp.getSignatureKey()
	hash := hmac.New(sha256.New, signingKey)
	hash.Write([]byte(stringToSign))
	signature := hex.EncodeToString(hash.Sum(nil))
	return signature, nil
}
