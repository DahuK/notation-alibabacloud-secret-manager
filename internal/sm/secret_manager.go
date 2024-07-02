package sm

import (
	"github.com/alibabacloud-go/tea/tea"
	dedicatedkmsopenapi "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/openapi"
	dedicatedkmssdk "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/sdk"
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

func