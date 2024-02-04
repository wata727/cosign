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
	"encoding/base64"
	"fmt"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// Bundle is Cosign's unique bundle file output format.
// Note that it is different from Sigstore bundle.
// This exists primarily for backwards compatibility.
type Bundle struct {
	Base64Signature string       `json:"base64Signature"`
	Cert            string       `json:"cert,omitempty"`
	Bundle          *RekorBundle `json:"rekorBundle,omitempty"`
}

func Build(entity *SignedEntity) (*Bundle, error) {
	bundle := &Bundle{}

	sig, err := entity.SignatureContent()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signature content: %w", err)
	}
	bundle.Base64Signature = base64.StdEncoding.EncodeToString(sig.Signature())

	vm, err := entity.VerificationContent()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch verification content: %w", err)
	}
	if cert, ok := vm.HasCertificate(); ok {
		certBytes, err := cryptoutils.MarshalCertificateToPEM(&cert)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal certificate: %w", err)
		}
		bundle.Cert = base64.StdEncoding.EncodeToString(certBytes)
	}

	entry, err := entity.TlogEntry()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch transparency log entry: %w", err)
	}
	if entry != nil {
		bundle.Bundle = EntryToBundle(entry)
	}

	return bundle, nil
}
