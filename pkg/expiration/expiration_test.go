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
	"reflect"
	"testing"
	"time"

	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"github.com/jetstack/cert-manager/pkg/client/clientset/versioned/fake"
	apiv1alpha1 "github.com/rikatz/cert-expiration-verifier/apis/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	certmanagerv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
)

func TestVerifyExpiration(t *testing.T) {

	var certificateItems []certmanagerv1.Certificate

	pastDate, err := time.Parse(time.RFC3339, "2010-10-16T10:10:00.000Z")
	if err != nil {
		t.Errorf("Failed generating past time %s", err)
	}
	metaTime := metav1.NewTime(pastDate)

	expiredCert := certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "bla1",
			Name:      "expiredcert",
		},
		Spec: certmanagerv1.CertificateSpec{
			DNSNames: []string{
				"expired1.bla.com",
				"expired2.blo.com",
			},
		},
		Status: certmanagerv1.CertificateStatus{
			NotAfter: &metaTime,
		},
	}

	// Certificate will expire in one week
	toExpireDate := metav1.NewTime(time.Now().AddDate(0, 0, 7))
	toExpireCert := certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "bla2",
			Name:      "toexpirecert",
		},
		Spec: certmanagerv1.CertificateSpec{
			DNSNames: []string{
				"toexpire.bla.com",
				"toexpire.blo.com",
			},
		},
		Status: certmanagerv1.CertificateStatus{
			NotAfter: &toExpireDate,
		},
	}

	// Will expire in 1 year
	farExpiringDate := metav1.NewTime(time.Now().AddDate(1, 0, 0))
	farExpireCert := certmanagerv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "bla3",
			Name:      "farexpirecert",
		},
		Spec: certmanagerv1.CertificateSpec{
			DNSNames: []string{
				"farexpire.bla.com",
				"farexpire.blo.com",
			},
		},
		Status: certmanagerv1.CertificateStatus{
			NotAfter: &farExpiringDate,
		},
	}

	certificateItems = append(certificateItems, expiredCert, toExpireCert, farExpireCert)
	certificateList := certmanagerv1.CertificateList{
		Items: certificateItems,
	}

	data := []struct {
		testName       string
		clientset      cmclient.Interface
		days           int
		expectedErrors []apiv1alpha1.CertificateError
	}{
		{
			testName:  "Check Expired only",
			clientset: fake.NewSimpleClientset(&certificateList),
			days:      5,
			expectedErrors: []apiv1alpha1.CertificateError{
				{
					DNSNames: []string{
						"expired1.bla.com",
						"expired2.blo.com",
					},
					Namespace:       "bla1",
					CertificateName: "expiredcert",
					ExpirationDate:  metaTime,
					Reason:          "Certificate is expired and should be renewed or revoked",
				},
			},
		},
		{
			testName:  "Check Expired and in the next 10 days",
			clientset: fake.NewSimpleClientset(&certificateList),
			days:      10,
			expectedErrors: []apiv1alpha1.CertificateError{
				{
					DNSNames: []string{
						"expired1.bla.com",
						"expired2.blo.com",
					},
					Namespace:       "bla1",
					CertificateName: "expiredcert",
					ExpirationDate:  metaTime,
					Reason:          "Certificate is expired and should be renewed or revoked",
				},
				{
					DNSNames: []string{
						"toexpire.bla.com",
						"toexpire.blo.com",
					},
					Namespace:       "bla2",
					CertificateName: "toexpirecert",
					ExpirationDate:  toExpireDate,
					Reason:          "Certificate is about to expire in less than 10 days",
				},
			},
		},
		{
			testName:  "Check the far far away certificate",
			clientset: fake.NewSimpleClientset(&certificateList),
			days:      600,
			expectedErrors: []apiv1alpha1.CertificateError{
				{
					DNSNames: []string{
						"expired1.bla.com",
						"expired2.blo.com",
					},
					Namespace:       "bla1",
					CertificateName: "expiredcert",
					ExpirationDate:  metaTime,
					Reason:          "Certificate is expired and should be renewed or revoked",
				},
				{
					DNSNames: []string{
						"toexpire.bla.com",
						"toexpire.blo.com",
					},
					Namespace:       "bla2",
					CertificateName: "toexpirecert",
					ExpirationDate:  toExpireDate,
					Reason:          "Certificate is about to expire in less than 600 days",
				},
				{
					DNSNames: []string{
						"farexpire.bla.com",
						"farexpire.blo.com",
					},
					Namespace:       "bla3",
					CertificateName: "farexpirecert",
					ExpirationDate:  farExpiringDate,
					Reason:          "Certificate is about to expire in less than 600 days",
				},
			},
		},
	}

	for _, single := range data {
		certErrors, err := VerifyExpiration(single.clientset, single.days)
		if err != nil {
			t.Errorf("Error in test %v", err)
		}

		if !reflect.DeepEqual(certErrors, single.expectedErrors) {
			t.Errorf("Expected error differs from returned by function: \nExpected: %+v\nReturned: %+v", single.expectedErrors, certErrors)
		}

	}

}
