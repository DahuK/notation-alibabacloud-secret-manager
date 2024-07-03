package sm

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/alibabacloud-go/tea/tea"
	dedicatedkmsopenapi "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/openapi"
	dedicatedkmssdk "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/sdk"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
)

const (
	KMS_RSA_2048 = "RSA_2048"
	KMS_RSA_3072 = "RSA_3072"
	KMS_RSA_4096 = "RSA_4096"
	KMS_EC_P256  = "EC_P256"
	KMS_EC_P256K = "EC_P256K"
	KMS_EC_SM2   = "EC_SM2"
)

func GetDkmsClientByClientKeyFile(clientKeyPath, password, endpoint string) (*dedicatedkmssdk.Client, error) {
	// 创建DKMS Client配置
	config := &dedicatedkmsopenapi.Config{
		Protocol: tea.String("https"),
		// 请替换为您在KMS应用管理获取的ClientKey文件的路径
		ClientKeyFile: tea.String(clientKeyPath),
		// 请替换为您在KMS应用管理创建ClientKey时输入的加密口令
		Password: tea.String(password),
		// 请替换为您实际的专属KMS实例服务地址(不包括协议头https://)
		Endpoint: tea.String(endpoint),
	}
	// 创建DKMS Client对象
	client, err := dedicatedkmssdk.NewClient(config)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func ParseCertificates(keyStr string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	block, rest := pem.Decode([]byte(keyStr))
	for block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		block, rest = pem.Decode(rest)
	}
	return certs, nil
}

func SwitchKeySpec(kmsKeySpec string) plugin.KeySpec {
	switch kmsKeySpec {
	case KMS_RSA_2048:
		return plugin.KeySpecRSA2048
	case KMS_RSA_3072:
		return plugin.KeySpecRSA3072
	case KMS_RSA_4096:
		return plugin.KeySpecRSA4096
	case KMS_EC_P256:
		return plugin.KeySpecEC256
	}
	return ""
}
