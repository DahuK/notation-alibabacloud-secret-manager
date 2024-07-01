package kms

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/internal/crypto"
	kms "github.com/alibabacloud-go/kms-20160120/v3/client"
	dkms "github.com/aliyun/alibabacloud-dkms-gcs-go-sdk/sdk"
	"strings"
)

type SecretManagerWrapper struct {
	dedicatedClient *dkms.Client
	kmsClient       *kms.Client

	keyID string
}

func NewSecretManagerClientFromKeyID(id string) (*SecretManagerWrapper, error) {
	// read addr and token from environment variables

	return &SecretManagerWrapper{
		dedicatedClient: client,
		kmsClient:       client,
		keyID:           id,
	}, nil
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

func (vw *SecretManagerWrapper) Sign(ctx context.Context, encodedData string, signAlgorithm string) ([]byte, error) {
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
