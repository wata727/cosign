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
	sigstorebundle "github.com/sigstore/cosign/v2/pkg/bundle"
	"github.com/sigstore/rekor/pkg/generated/models"
)

type SignedEntity struct {
	Signature            sigstorebundle.SignatureContent
	VerificationMaterial sigstorebundle.VerificationContent
	LogEntry             *models.LogEntryAnon
	RFC3161Timestamps    [][]byte
}

var _ sigstorebundle.SignedEntity = (*SignedEntity)(nil)

func (s *SignedEntity) SignatureContent() (sigstorebundle.SignatureContent, error) {
	return s.Signature, nil
}

func (s *SignedEntity) VerificationContent() (sigstorebundle.VerificationContent, error) {
	return s.VerificationMaterial, nil
}

func (s *SignedEntity) TlogEntry() (*models.LogEntryAnon, error) {
	return s.LogEntry, nil
}

func (s *SignedEntity) Timestamps() ([][]byte, error) {
	return s.RFC3161Timestamps, nil
}
