// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bundle

import (
	"fmt"

	pbbundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	pbcommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	pbrekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/tle"
)

func Build(entity SignedEntity) (*pbbundle.Bundle, error) {
	bundle := &pbbundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
	}
	var err error

	bundle.VerificationMaterial, err = buildVerificationMaterial(entity)
	if err != nil {
		return nil, err
	}

	sig, err := entity.SignatureContent()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signature content: %w", err)
	}
	if ms := sig.MessageSignatureContent(); ms != nil {
		bundle.Content = &pbbundle.Bundle_MessageSignature{
			MessageSignature: &pbcommon.MessageSignature{
				MessageDigest: &pbcommon.HashOutput{
					Algorithm: AsPbHashAlgorithm(ms.DigestAlgorithm()),
					Digest:    ms.Digest(),
				},
				Signature: ms.Signature(),
			},
		}
	} else if envelop := sig.EnvelopeContent(); envelop != nil {
		rawEnvelope := envelop.RawEnvelope()
		dsseSignatures := make([]*dsse.Signature, len(rawEnvelope.Signatures))
		for i, s := range rawEnvelope.Signatures {
			dsseSignatures[i] = &dsse.Signature{Keyid: s.KeyID, Sig: []byte(s.Sig)}
		}
		bundle.Content = &pbbundle.Bundle_DsseEnvelope{
			DsseEnvelope: &dsse.Envelope{
				Payload:     []byte(rawEnvelope.Payload),
				PayloadType: rawEnvelope.PayloadType,
				Signatures:  dsseSignatures,
			},
		}
	}

	return bundle, nil
}

func buildVerificationMaterial(entity SignedEntity) (*pbbundle.VerificationMaterial, error) {
	vm := pbbundle.VerificationMaterial{}

	vc, err := entity.VerificationContent()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch verification content: %w", err)
	}
	if cert, ok := vc.HasCertificate(); ok {
		vm.Content = &pbbundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &pbcommon.X509CertificateChain{
				Certificates: []*pbcommon.X509Certificate{
					{RawBytes: cert.Raw},
				},
			},
		}
	} else if pub, ok := vc.HasPublicKey(); ok {
		vm.Content = &pbbundle.VerificationMaterial_PublicKey{
			PublicKey: &pbcommon.PublicKeyIdentifier{
				Hint: pub.Hint(),
			},
		}
	}

	logEntry, err := entity.TlogEntry()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch transparency log entry: %w", err)
	}
	if logEntry != nil {
		tlEntry, err := tle.GenerateTransparencyLogEntry(*logEntry)
		if err != nil {
			return nil, fmt.Errorf("failed to generate TransparencyLogEntry: %w", err)
		}
		vm.TlogEntries = []*pbrekor.TransparencyLogEntry{tlEntry}
	}

	timestamps, err := entity.Timestamps()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch timestamps: %w", err)
	}
	if len(timestamps) > 0 {
		rfc3161timestamps := make([]*pbcommon.RFC3161SignedTimestamp, len(timestamps))
		for i, timestamp := range timestamps {
			rfc3161timestamps[i] = &pbcommon.RFC3161SignedTimestamp{SignedTimestamp: timestamp}
		}
		vm.TimestampVerificationData = &pbbundle.TimestampVerificationData{
			Rfc3161Timestamps: rfc3161timestamps,
		}
	}

	return &vm, nil
}

func AsPbHashAlgorithm(in string) pbcommon.HashAlgorithm {
	switch in {
	case "SHA2_256":
		return pbcommon.HashAlgorithm_SHA2_256
	default:
		panic(fmt.Sprintf("unknown hash algorithm: %s", in))
	}
}
