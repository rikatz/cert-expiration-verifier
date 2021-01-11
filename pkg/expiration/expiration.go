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

package expiration

import (
	"context"
	"fmt"
	"time"

	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv1alpha1 "github.com/rikatz/cert-expiration-verifier/apis/v1alpha1"
)

// VerifyExpiration
func VerifyExpiration(client cmclient.Interface, days int) ([]apiv1alpha1.CertificateError, error) {

	var certificateErrors []apiv1alpha1.CertificateError
	certificateList, err := client.CertmanagerV1().Certificates("").List(context.TODO(), metav1.ListOptions{})

	if apierrors.IsForbidden(err) {
		return nil, fmt.Errorf("Permission denied while getting the certificates")
	}

	if err != nil {
		return nil, fmt.Errorf("Failed to communicate with Kubernetes cluster")
	}

	if len(certificateList.Items) < 1 {
		return certificateErrors, nil
	}

	stillValid := time.Now().Add(time.Duration(days) * time.Hour * 24)

	for _, certificate := range certificateList.Items {
		var msg string
		if certificate.Status.NotAfter != nil {
			if stillValid.After(certificate.Status.NotAfter.Time) {
				msg = fmt.Sprintf("Certificate is about to expire in less than %d days", int(days))
			}

			if time.Now().After(certificate.Status.NotAfter.Time) {
				msg = fmt.Sprintf("Certificate is expired and should be renewed or revoked")
			}
		}
		if msg != "" {
			certerror := apiv1alpha1.CertificateError{
				DNSNames:        certificate.Spec.DNSNames,
				Namespace:       certificate.GetNamespace(),
				CertificateName: certificate.GetName(),
				ExpirationDate:  *certificate.Status.NotAfter,
				Reason:          msg,
			}
			certificateErrors = append(certificateErrors, certerror)
		}
	}

	return certificateErrors, nil
}
