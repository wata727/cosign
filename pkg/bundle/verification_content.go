// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This file is based on https://github.com/sigstore/sigstore-go/blob/v0.1.0/pkg/bundle/verification_content.go

package bundle

import "crypto/x509"

type CertificateChain struct {
	Certificates []*x509.Certificate
}

var _ VerificationContent = (*CertificateChain)(nil)

type PublicKey struct {
	hint string
}

var _ VerificationContent = (*PublicKey)(nil)

func (pk PublicKey) Hint() string {
	return pk.hint
}

func (cc *CertificateChain) HasCertificate() (x509.Certificate, bool) {
	return *cc.Certificates[0], true
}

func (pk *PublicKey) HasCertificate() (x509.Certificate, bool) {
	return x509.Certificate{}, false
}

func (cc *CertificateChain) HasPublicKey() (PublicKeyProvider, bool) {
	return PublicKey{}, false
}

func (pk *PublicKey) HasPublicKey() (PublicKeyProvider, bool) {
	return *pk, true
}
