//Copyright (c) 2019, Cogility Software

/*
mock_idp is a mock SAML IdP used for dev and test.

Command Flags

	host - the hostname the mock_idp service is published on
	cert - the fully quaified IdP certificate PEM file name
	key - the fully quaified IdP certificate key PEM file name

The mock IDP is started on port 8000. It's reverse proxy should provide https access to it

Get IDP Metadata

	curl https://<idp-host>/metadata

Register SP using an SP metadata file

	curl -d @sp-metadata.xml -X PUT https://<idp-host>/services/sp

List Registered SPs

	curl https://<idp-host>/services/sp

*/
package main

import (
	"flag"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"

	"github.com/zenazn/goji"

	"github.com/edaniels/go-saml/samlidp"
)

var (
	/*
		Command flags
	*/
	host = flag.String("host", "", "the hostname the mock_idp service is published on")
	cert = flag.String("cert", "", "the fully quaified IdP certificate PEM file name")
	key  = flag.String("key", "", "the fully quaified IdP certificate key PEM file name")
)

func main() {
	flag.Parse()
	if *host == "" {
		log.Fatalln("The IdP's hostname is blank")
	}

	if *cert == "" {
		log.Fatalln("The IdP's cert PEM file name is blank")
	}

	if *key == "" {
		log.Fatalln("The IdP's cert key PEM file name is blank")
	}

	certPEMFile, err := os.Open(*cert)
	if err != nil {
		log.Fatalf("Error opening %s: %s\n", *cert, err)
	}

	keyPEMFile, err := os.Open(*cert)
	if err != nil {
		log.Fatalf("Error opening %s: %s\n", *key, err)
	}

	certPEM, err := ioutil.ReadAll(certPEMFile)
	if err != nil {
		log.Fatalf("Error reading %s: %s\n", *cert, err)
	}

	keyPEM, err := ioutil.ReadAll(keyPEMFile)
	if err != nil {
		log.Fatalf("Error reading %s: %s\n", *key, err)
	}

	idpServer, err := samlidp.New(samlidp.Options{
		URL:         "https://" + *host,
		Key:         string(keyPEM),
		Certificate: string(certPEM),
		Store:       &samlidp.MemoryStore{},
	})
	if err != nil {
		log.Fatalf("%s", err)
	}

	aliceHashedPassword, _ := bcrypt.GenerateFromPassword([]byte("alicepw"), bcrypt.DefaultCost)
	err = idpServer.Store.Put("/users/alice", samlidp.User{
		Name:           "alice",
		HashedPassword: aliceHashedPassword,
		Groups:         []string{"cogynt_user", "cogynt_analyst"},
		Email:          "alice@acm.come",
		CommonName:     "Alice Smith",
		Surname:        "Smith",
		GivenName:      "Alice",
	})
	if err != nil {
		log.Fatalf("%s", err)
	}

	bobHashedPassword, _ := bcrypt.GenerateFromPassword([]byte("bobpw"), bcrypt.DefaultCost)
	err = idpServer.Store.Put("/users/bob", samlidp.User{
		Name:           "bob",
		HashedPassword: bobHashedPassword,
		Groups:         []string{"cogynt_user", "cogynt_admin"},
		Email:          "bob@acme.com",
		CommonName:     "Bob Smith",
		Surname:        "Smith",
		GivenName:      "Bob",
	})
	if err != nil {
		log.Fatalf("%s", err)
	}
	goji.Handle("/*", idpServer)
	goji.Serve()
}
