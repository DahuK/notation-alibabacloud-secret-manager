package main

import (
	"github.com/AliyunContainerService/notation-alibabacloud-secret-manager/internal/version"
	"github.com/notaryproject/notation-go/plugin/proto"
)

func runGetMetadata() *proto.GetMetadataResponse {
	return &proto.GetMetadataResponse{
		Name:                      "hc-vault",
		Description:               "Sign artifacts with keys in HashiCorp Vault",
		Version:                   version.GetVersion(),
		URL:                       "https://github.com/AliyunContainerService/notation-alibabacloud-secret-manager",
		SupportedContractVersions: []string{proto.ContractVersion},
		Capabilities:              []proto.Capability{proto.CapabilitySignatureGenerator},
	}
}
