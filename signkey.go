package aws4

import (
	"crypto/hmac"
	"crypto/sha256"
)

type signatureKeyParam struct {
	secretKey string
	datestamp string
	region    string
	service   string
}

func (signatureKeyParam) sign(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

func (p signatureKeyParam) getSignatureKey() (signatureKey []byte) {

	kDate := p.sign([]byte("AWS4"+p.secretKey), p.datestamp)
	kRegion := p.sign(kDate, p.region)
	kService := p.sign(kRegion, p.service)

	signatureKey = p.sign(kService, "aws4_request")

	return
}
