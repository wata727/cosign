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

// This file is based on https://github.com/sigstore/sigstore-go/blob/v0.1.0/pkg/verify/interface.go

package bundle

import (
	"crypto/x509"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/rekor/pkg/generated/models"
)

type SignatureProvider interface {
	SignatureContent() (SignatureContent, error)
}

type SignedTimestampProvider interface {
	Timestamps() ([][]byte, error)
}

type TlogEntryProvider interface {
	// TODO: Should return []*sigstore-go/pkg/tlog.Entry
	// TlogEntries() ([]*tlog.Entry, error)
	TlogEntry() (*models.LogEntryAnon, error)
}

type VerificationProvider interface {
	VerificationContent() (VerificationContent, error)
}

type SignedEntity interface {
	SignatureProvider
	SignedTimestampProvider
	TlogEntryProvider
	VerificationProvider
}

type VerificationContent interface {
	HasCertificate() (x509.Certificate, bool)
	HasPublicKey() (PublicKeyProvider, bool)
}

type SignatureContent interface {
	Signature() []byte
	EnvelopeContent() EnvelopeContent
	MessageSignatureContent() MessageSignatureContent
}

type PublicKeyProvider interface {
	Hint() string
}

type MessageSignatureContent interface {
	Digest() []byte
	DigestAlgorithm() string
	Signature() []byte
}

type EnvelopeContent interface {
	RawEnvelope() *dsse.Envelope
	Statement() (*in_toto.Statement, error)
}
