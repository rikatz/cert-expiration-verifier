/*
Copyright 2020 The Kubernetes Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TODO: Move to a better place
// TODO2: Owner is defined here, but we can
// CertificateError defines a Certificate to be reported as with
// error
type CertificateError struct {
	DNSNames        []string
	Namespace       string
	CertificateName string
	ExpirationDate  metav1.Time
	Reason          string
	Owner           string
}
