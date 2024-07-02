package kms

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/internal/crypto"
	"github.com/alibabacloud-go/tea/tea"
	dedicatedkmsopenapi "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/openapi"
	dedicatedkmssdk "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/sdk"
	"strings"
)

const ()

func GetDkmsClientByClientKeyFile() *dedicatedkmssdk.Client {
	// 创建DKMS Client配置
	config := &dedicatedkmsopenapi.Config{
		Protocol: tea.String("https"),
		// 请替换为您在KMS应用管理获取的ClientKey文件的路径
		ClientKeyFile: tea.String("yourClientKeyFile"),
		// 请替换为您在KMS应用管理创建ClientKey时输入的加密口令
		Password: tea.String("yourClientKeyPassword"),
		// 请替换为您实际的专属KMS实例服务地址(不包括协议头https://)
		Endpoint: tea.String("yourEndpoint"),
	}
	// 创建DKMS Client对象
	client, err := dedicatedkmssdk.NewClient(config)
	if err != nil {
		// 异常处理
		panic(err)
	}
	return client
}

func (smw *SecretManagerWrapper) GetCertificateChain(ctx context.Context) ([]*x509.Certificate, error) {
	// read a certChain
	secret, err := smw.vaultClient.KVv2("secret").Get(ctx, vw.keyID)
	if err != nil {
		return nil, err
	}
	certString, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, errors.New("failed to parse certificate from KV secrets engine")
	}
	certBytes := []byte(certString)
	return crypto.ParseCertificates(certBytes)
}

func (smw *SecretManagerWrapper) Sign(ctx context.Context, encodedData string, signAlgorithm string) ([]byte, error) {
	// sign with transit SE

	signature, ok := resp.Data["signature"].(string)
	if !ok {
		return nil, errors.New("failed to parse signature from TransitSign response")
	}
	items := strings.Split(signature, ":")
	sigBytes, err := base64.StdEncoding.DecodeString(items[2])
	if err != nil {
		return nil, err
	}
	return sigBytes, nil
}
