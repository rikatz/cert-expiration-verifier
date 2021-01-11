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

package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"

	cmclient "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/rikatz/cert-expiration-verifier/pkg/expiration"
)

var (
	kubeconfig string
	inCluster  bool
	expireIn   int
	client     cmclient.Interface
	err        error
)

func main() {

	flag.Parse()
	var config *rest.Config
	var err error
	if !inCluster {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		config, err = rest.InClusterConfig()
	}

	if err != nil {
		log.Fatalf("Unable to generate Kubernetes Configuration: %s", err)
	}
	client, err = cmclient.NewForConfig(config)
	if err != nil {
		log.Fatalf("Unable to connect to Kubernetes Cluster: %s", err)
	}

	certs, err := expiration.VerifyExpiration(client, expireIn)
	if err != nil {
		log.Fatalf("Unable to verify certificates expiration: %s", err)
	}

	// TODO: This is going to be used by the report instead of printing on screen
	for _, cert := range certs {
		fmt.Printf("%+v\n", cert)
	}

}

func init() {

	if home := homedir.HomeDir(); home != "" {
		flag.StringVar(&kubeconfig, "kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	}

	flag.IntVar(&expireIn, "expire-in", 10, "How many days until the certificate expiration that should be alerted")

}
