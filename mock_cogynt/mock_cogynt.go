//Copyright (c) 2019, Cogility Software

/*
mock_cogynt is a mock of the Cogynt authenticated and authentication-failure endpoints.

Command Flags

	host - the cogynt_sso hostname to which authn-session validate requests are sent
	port - the port the mock_cogynt service is published on

	Use -h to see command flag help
*/
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"log"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

type (
	//userAndRolesT is the result returned from a successful authn-session validation
	userAndRolesT struct {
		UserName string   `json:"user_name"`
		Roles    []string `json:"roles"`
	}
)

var (
	/*
		Command flags
	*/
	host = flag.String("host", "", "the cogynt_sso hostname to which authn-session validate requests are sent")
	port = flag.String("port", "8083", "the port the mock_cogynt service is published on")
)

func authnHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var (
		client          http.Client
		cookies         []*http.Cookie
		authnCookie     *http.Cookie
		authnSessionBuf *bytes.Buffer
		rsp             *http.Response
		userAndRoles    userAndRolesT
		err             error
	)

	log.Println("user authenticated")

	//Verify authn-session cookie exists
	cookies = r.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "authn-session" {
			authnCookie = cookie
		}
	}
	if authnCookie == nil {
		log.Println("authn-session cookie is missing")
		return
	}

	//Request cogent_sso to validate the authn-session and return its AEAD secured private content
	authnSessionBuf = bytes.NewBuffer([]byte(authnCookie.Value))
	rsp, err = client.Post("https://"+*host+"/validate", "application/json", authnSessionBuf)
	if err != nil {
		log.Printf("POST to validate authn-session cookie failed: %s\n", err)
		return
	}
	if rsp.StatusCode != http.StatusOK {
		log.Printf("POST to validate authn-session cookie failed: %s\n", rsp.Status)
		return
	}

	//JSON Decode returned authn-session private session
	err = json.NewDecoder(rsp.Body).Decode(&userAndRoles)
	if err != nil {
		log.Printf("JSON decode of authn-session user and roles failed: %s\n", err)
		return
	}
	log.Printf("authn-session user and roles: %+v\n", userAndRoles)

} //authnHandler

func authnFailureHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	log.Println("user authentication failed")
}

func main() {
	var (
		router = httprouter.New()
	)

	flag.Parse()
	if *host == "" {
		log.Fatalln("The mock_cogynt hostname is blank")
	}

	//Register request handlers
	router.GET("/authenticated", authnHandler)
	router.GET("/authentication-failure", authnFailureHandler)

	//Start mock_cogynt
	log.Println("Starting mock_cogynt on port " + *port)
	log.Fatal(http.ListenAndServe(":"+*port, router))
}
