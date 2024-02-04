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

// This file is based on https://github.com/sigstore/sigstore-go/blob/v0.1.0/pkg/bundle/signature_content.go

package bundle

type MessageSignature struct {
	digest          []byte
	digestAlgorithm string
	signature       []byte
}

var _ SignatureContent = (*MessageSignature)(nil)
var _ MessageSignatureContent = (*MessageSignature)(nil)

func (m *MessageSignature) Digest() []byte {
	return m.digest
}

func (m *MessageSignature) DigestAlgorithm() string {
	return m.digestAlgorithm
}

func NewMessageSignature(digest []byte, digestAlgorithm string, signature []byte) *MessageSignature {
	return &MessageSignature{
		digest:          digest,
		digestAlgorithm: digestAlgorithm,
		signature:       signature,
	}
}

func (m *MessageSignature) EnvelopeContent() EnvelopeContent {
	return nil
}

func (m *MessageSignature) MessageSignatureContent() MessageSignatureContent {
	return m
}

func (m *MessageSignature) Signature() []byte {
	return m.signature
}
