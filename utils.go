package aws4

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func getHashCanonicalRequestStr(authInfo *AuthInfo, payload []byte) string {
	commitParams := authInfo.Params
	amzdate := authInfo.AmzDate
	token := authInfo.Token
	method := authInfo.Method

	canonicalQuerystring := getParameters(commitParams)
	canonicalHeaders := getCanonicalHeaders(amzdate, token, method, payload)
	signedHeaders := getHeadersParam(method)
	payloadHash := getPayloadHash(payload)
	canonicalRequestStr := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", method, "/", canonicalQuerystring, canonicalHeaders, signedHeaders, payloadHash)
	hash := sha256.New()
	//fmt.Println("crs", canonicalRequestStr)
	hash.Write([]byte(canonicalRequestStr))
	hashCanonicalRequestStr := hex.EncodeToString(hash.Sum(nil))
	//fmt.Println("hcrs:", hashCanonicalRequestStr)
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

func getCanonicalHeaders(amzdate string, token string, method string, payload []byte) string {
	headers := map[string]string{
		"x-amz-date":           amzdate,
		"x-amz-security-token": token,
	}
	if method == "POST" {
		headers["x-amz-content-sha256"] = getPayloadHash(payload)
	}
	var canonicalHeaders string
	var list []string
	if method == "POST" {
		list = strings.Split("x-amz-content-sha256;x-amz-date;x-amz-security-token", ";")
	} else {
		list = strings.Split("x-amz-date;x-amz-security-token", ";")
	}
	for _, value := range list {
		canonicalHeaders += value + ":" + headers[value] + "\n"
	}

	return canonicalHeaders
}

// 获取请求头参数列表
func getHeadersParam(method string) string {
	if method == "POST" {
		return "x-amz-content-sha256;x-amz-date;x-amz-security-token"
	} else {
		return "x-amz-date;x-amz-security-token"
	}
}

// 获取负载哈希值
func getPayloadHash(payload []byte) string {
	// 计算请求主体的 SHA-256 散列值
	hash := sha256.Sum256([]byte(payload))

	// 将散列值编码为十六进制字符串
	sha256Hex := hex.EncodeToString(hash[:])
	return sha256Hex
}

func dataCheck(authInfo *AuthInfo) bool {
	if authInfo.AK == "" || authInfo.SK == "" || authInfo.Token == "" || authInfo.SpaceName == "" || authInfo.Region == "" || authInfo.Service == "" || authInfo.Algorithm == "" || authInfo.AmzDate == "" || authInfo.Method == "" || authInfo.Params == nil {
		return false
	} else {
		return true
	}
}
