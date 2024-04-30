package aws4

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
)

func getHashCanonicalRequestStr(authInfo *AuthInfo) string {
	commitParams := authInfo.Params
	amzdate := authInfo.AmzDate
	token := authInfo.Token

	canonicalQuerystring := getParameters(commitParams)
	canonicalHeaders := getCanonicalHeaders(amzdate, token)
	signedHeaders := getHeadersParam()
	payloadHash := getPayloadHash()
	canonicalRequestStr := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", "GET", "/", canonicalQuerystring, canonicalHeaders, signedHeaders, payloadHash)
	hash := sha256.New()
	hash.Write([]byte(canonicalRequestStr))
	hashCanonicalRequestStr := hex.EncodeToString(hash.Sum(nil))
	return hashCanonicalRequestStr
}

// 序列化查询字符串
func getParameters(params map[string]string) string {
	// 将参数的键按照字母顺序排序
	var sortedKeys []string
	for key := range params {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	// 构建排序后的参数字典
	sortedParams := make(map[string]string)
	for _, key := range sortedKeys {
		sortedParams[key] = params[key]
	}

	// 将参数字典转换为 URL 编码的字符串
	signParameters := url.Values{}
	for key, value := range sortedParams {
		signParameters.Set(key, value)
	}

	return signParameters.Encode()
}

func getCanonicalHeaders(amzdate string, token string) string {
	headers := map[string]string{
		"x-amz-date":           amzdate,
		"x-amz-security-token": token,
	}
	var canonicalHeaders string
	for key, value := range headers {
		canonicalHeaders += key + ":" + value + "\n"
	}

	return canonicalHeaders
}

// 获取请求头参数列表
func getHeadersParam() string {
	return "x-amz-date;x-amz-security-token"
}

// 获取负载哈希值
func getPayloadHash() string {
	payload := ""
	// 使用 SHA-256 算法对 payload 进行哈希
	hash := sha256.New()
	hash.Write([]byte(payload))
	hashedPayload := hex.EncodeToString(hash.Sum(nil))
	return hashedPayload
}

func dataCheck(authInfo *AuthInfo) bool {
	if authInfo.AK == "" || authInfo.SK == "" || authInfo.Token == "" || authInfo.SpaceName == "" || authInfo.Region == "" || authInfo.Service == "" || authInfo.Algorithm == "" || authInfo.AmzDate == "" || authInfo.Params == nil {
		return false
	} else {
		return true
	}
}
