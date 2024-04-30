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

func GetAuthorization(authInfo *AuthInfo) (string, error) {
	signature, err := GetSignature(authInfo)
	dateStamp := strings.Split(authInfo.AmzDate, "T")[0]
	if err != nil {
		return "", err
	}
	authorization := fmt.Sprintf("%s%s/%s/%s/%s/%s%s", "AWS4-HMAC-SHA256 Credential=", authInfo.AK, dateStamp, authInfo.Region, authInfo.Service, "aws4_request, SignedHeaders=x-amz-date;x-amz-security-token, Signature=", signature)
	return authorization, nil

}
