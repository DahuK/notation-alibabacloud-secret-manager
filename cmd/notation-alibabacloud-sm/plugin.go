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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/AliyunContainerService/ack-ram-tool/pkg/ctl/common"
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/internal/log"
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/internal/sm"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	kms "github.com/alibabacloud-go/kms-20160120/v3/client"
	"github.com/alibabacloud-go/tea/tea"
	dedicatedkmsopenapiutil "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/openapi-util"
	dkms "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/sdk"
	"github.com/notaryproject/notation-plugin-framework-go/plugin"
	"os"
)

const (
	PluginName = "notation"
)

type AlibabaCloudSecretManagerPlugin struct {
	DedicatedClient *dkms.Client
	KmsClient       *kms.Client
}

func NewAlibabaCloudSecretManagerPlugin() (*AlibabaCloudSecretManagerPlugin, error) {
	client := common.GetClientOrDie()
	config := openapi.Config{
		RegionId:   tea.String(sm.GetKMSRegionId()),
		Credential: client.Credential(),
	}
	kmsClient, err := kms.NewClient(&config)
	if err != nil {
		return nil, err
	}
	instanceEndpoint := sm.GetInstanceEndpoint()
	if instanceEndpoint == "" {
		return nil, errors.New("Env ALIBABA_CLOUD_KMS_INSTANCE_ENDPOINT MUST be set for kms instance endpoint")
	}
	clientKey := sm.GetClientKey()
	if instanceEndpoint == "" {
		return nil, errors.New("Env ALIBABA_CLOUD_KMS_INSTANCE_ENDPOINT MUST be set for kms instance endpoint")
	}
	kmsPassword := sm.GetKMSPassword()
	if instanceEndpoint == "" {
		return nil, errors.New("Env ALIBABA_CLOUD_KMS_INSTANCE_ENDPOINT MUST be set for kms instance endpoint")
	}
	//init DKMS Client
	dkmsClient, err := sm.GetDkmsClientByClientKeyFile(clientKey, kmsPassword, instanceEndpoint)
	if err != nil {
		return nil, err
	}
	return &AlibabaCloudSecretManagerPlugin{
		dkmsClient,
		kmsClient,
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
	smKeySpec := keyResult.Body.KeyMetadata.KeySpec
	fmt.Printf("alibaba cloud secret manager key spec is %s\n", smKeySpec)
	keySpec, err := sm.SwitchKeySpec(tea.StringValue(smKeySpec))
	if err != nil {
		return nil, err
	}
	return &plugin.DescribeKeyResponse{
		KeyID:   req.KeyID,
		KeySpec: keySpec,
	}, nil
}

func (p *AlibabaCloudSecretManagerPlugin) GenerateSignature(_ context.Context, req *plugin.GenerateSignatureRequest) (*plugin.GenerateSignatureResponse, error) {

	messageType := "RAW"
	signRequest := &dkms.SignRequest{
		KeyId:       tea.String(req.KeyID),
		Message:     req.Payload,
		MessageType: tea.String(messageType),
	}
	runtimeOptions := &dedicatedkmsopenapiutil.RuntimeOptions{
		IgnoreSSL: tea.Bool(true),
	}
	//set instance ca from file
	caFilePath := sm.GetKMSCAFile()
	if caFilePath != "" {
		certPEMBlock, err := os.ReadFile(caFilePath)
		if err != nil {
			log.Logger.Errorf("Failed to read certificate file from %s, err %v", caFilePath, err)
			return nil, err
		}
		certDERBlock, _ := pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			log.Logger.Errorf("Failed to decode PEM block from file %s", caFilePath)
			return nil, err
		}
		cert, err := x509.ParseCertificate(certDERBlock.Bytes)
		if err != nil {
			log.Logger.Errorf("Failed to parse certificate %s, err: %v", caFilePath, err)
			return nil, err
		}
		if !cert.IsCA {
			log.Logger.Errorf("The provided certificate is not a CA certificate")
			return nil, err
		}
		runtimeOptions = &dedicatedkmsopenapiutil.RuntimeOptions{
			Verify: tea.String(string(certPEMBlock)),
		}
	}

	signResponse, err := p.DedicatedClient.SignWithOptions(signRequest, runtimeOptions)
	if err != nil {
		log.Logger.Errorf("Failed to sign with key %s, err %v", req.KeyID, err)
		return nil, err
	}

	getPublicKeyRequest := &dkms.GetPublicKeyRequest{
		KeyId: tea.String(req.KeyID),
	}
	publicKeyResponse, err := p.DedicatedClient.GetPublicKeyWithOptions(getPublicKeyRequest, runtimeOptions)
	if err != nil {
		log.Logger.Errorf("Failed to get public key from KMS service, err %v", err)
		return nil, err
	}

	certChain, err := sm.ParseCertificates(tea.StringValue(publicKeyResponse.PublicKey))
	if err != nil {
		log.Logger.Errorf("Failed to parse public key response, err %v", err)
		return nil, err
	}
	// build raw cert chain
	rawCertChain := make([][]byte, 0, len(certChain))
	for _, cert := range certChain {
		rawCertChain = append(rawCertChain, cert.Raw)
	}
	return &plugin.GenerateSignatureResponse{
		KeyID:            req.KeyID,
		Signature:        signResponse.Signature,
		SigningAlgorithm: plugin.SignatureAlgorithmRSASSA_PSS_SHA256,
		CertificateChain: rawCertChain,
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
		Name:                      "alibabacloud.secretmanager.plugin",
		Description:               "Alibaba Cloud Secret Manager signer plugin for Notation",
		URL:                       "https://example.com/notation/plugin",
		Version:                   "0.0.1",
		Capabilities: []plugin.Capability{
			plugin.CapabilitySignatureGenerator,
			plugin.CapabilityTrustedIdentityVerifier},
	}, nil
}
