// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"github.com/AliyunContainerService/ack-ram-tool/pkg/ctl/common"
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/internal/sm"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	kms "github.com/alibabacloud-go/kms-20160120/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	dedicatedkmsopenapiutil "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/openapi-util"
	dkms "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/sdk"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
	"io/ioutil"
)

type AlibabaCloudSecretManagerPlugin struct {
	DedicatedClient dkms.Client
	KmsClient       kms.Client
	KeyID           string
}

func NewAlibabaCloudSecretManagerPlugin() (*AlibabaCloudSecretManagerPlugin, error) {

	client := common.GetClientOrDie()
	config := openapi.Config{
		Credential: client.Credential(),
	}
	kmsClient, err := kms.NewClient(&config)
	if err != nil {
		return nil, err
	}

	// 专属KMS实例签名密钥的ID或别名（Alias）
	keyId := "yourKeyId"
	// 创建DKMS Client对象
	dkmsClient, err := sm.GetDkmsClientByClientKeyFile()

	return &AlibabaCloudSecretManagerPlugin{
		dkmsClient,
		kmsClient,
		keyId,
	}, nil
}

func (p *AlibabaCloudSecretManagerPlugin) DescribeKey(_ context.Context, req *plugin.DescribeKeyRequest) (*plugin.DescribeKeyResponse, error) {
	request := &kms.DescribeKeyRequest{
		KeyId: tea.String(req.KeyID),
	}
	keyResult := &kms.DescribeKeyResponse{}
	response, err := p.KmsClient.DescribeKey(request)
	if err != nil {
		return nil, err
	}
	keyResult = response
	keySpec := keyResult.Body.KeyMetadata.KeySpec
	return &plugin.DescribeKeyResponse{
		KeyID:   req.KeyID,
		KeySpec: plugin.KeySpecRSA2048,
	}, nil
}

func (p *AlibabaCloudSecretManagerPlugin) GenerateSignature(_ context.Context, req *plugin.GenerateSignatureRequest) (*plugin.GenerateSignatureResponse, error) {

	messageType := "RAW"
	signRequest := &dkms.SignRequest{
		KeyId:       tea.String(req.KeyID),
		Message:     req.Payload,
		MessageType: tea.String(messageType),
	}

	//set instance ca from file
	ca, err := ioutil.ReadFile("path/to/caCert.pem")
	if err != nil {
		return nil, err
	}
	runtimeOptions := &dedicatedkmsopenapiutil.RuntimeOptions{
		Verify: tea.String(string(ca)),
	}

	signResponse, err := p.DedicatedClient.SignWithOptions(signRequest, runtimeOptions)
	if err != nil {
		return nil, err
	}

	return &plugin.GenerateSignatureResponse{
		KeyID:            req.KeyID,
		Signature:        signResponse.Signature,
		SigningAlgorithm: plugin.SignatureAlgorithmRSASSA_PSS_SHA384,
		CertificateChain: [][]byte{[]byte("mockCert1"), []byte("mockCert2")},
	}, nil
}

func (p *AlibabaCloudSecretManagerPlugin) GenerateEnvelope(_ context.Context, _ *plugin.GenerateEnvelopeRequest) (*plugin.GenerateEnvelopeResponse, error) {

	return nil, plugin.NewUnsupportedError("GenerateSignature operation is not implemented by this plugin")
}

func (p *AlibabaCloudSecretManagerPlugin) VerifySignature(_ context.Context, req *plugin.VerifySignatureRequest) (*plugin.VerifySignatureResponse, error) {
	upAttrs := req.Signature.UnprocessedAttributes
	pAttrs := make([]interface{}, len(upAttrs))
	for i := range upAttrs {
		pAttrs[i] = upAttrs[i]
	}

	return &plugin.VerifySignatureResponse{
		ProcessedAttributes: pAttrs,
		VerificationResults: map[plugin.Capability]*plugin.VerificationResult{
			plugin.CapabilityTrustedIdentityVerifier: {
				Success: true,
				Reason:  "Valid trusted Identity",
			},
			plugin.CapabilityRevocationCheckVerifier: {
				Success: true,
				Reason:  "Not revoked",
			},
		},
	}, nil
}

func (p *AlibabaCloudSecretManagerPlugin) GetMetadata(_ context.Context, _ *plugin.GetMetadataRequest) (*plugin.GetMetadataResponse, error) {
	return &plugin.GetMetadataResponse{
		SupportedContractVersions: []string{plugin.ContractVersion},
		Name:                      "com.example.plugin",
		Description:               "This is an description of example plugin",
		URL:                       "https://example.com/notation/plugin",
		Version:                   "1.0.0",
		Capabilities: []plugin.Capability{
			plugin.CapabilitySignatureGenerator,
			plugin.CapabilityTrustedIdentityVerifier,
			plugin.CapabilityRevocationCheckVerifier},
	}, nil
}
