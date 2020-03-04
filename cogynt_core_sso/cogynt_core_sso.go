//Copyright (c) 2019, Cogility Software

/*
cogynt_sso is the single sign-on service for the Cogynt product.

Command Flags

	init - initialize the cogynt_sso_dev Postgres DB and exit
	port - the port the cogynt_sso service is published on

	Use -h to see command flag help

When executed with init, cogynt_sso initializes its DB and exits. Init must be done prior to executing cogynt_sso as a service. DB initialization replaces the AEAD key which will terminate all active SP sessions if the SP is restarted.

Overview

Most Cogynt customers will require that Cogynt use their Identity Provider (IdP) to authenticate Cogynt users. An IdP handles authentication of the user and manages a single sign-on session for each user. Once a user is authenticated, this session allows the user to sign-on to additional apps without having to re-authenticate.

cogynt_sso initially supports SAML 2.0 IdPs and may later support OIDC IdPs.

Certificate Private Keys

Some private keys begin with the line:

	-----BEGIN PRIVATE KEY-----

These keys are PKCS#8 encoded and cannot be parsed correctly by cogynt_sso - they fail with an asn.1 RSA key parsing error. These keys must be converted to PKCS#1 keys. This can be done using the following openssl command:

	openssl rsa -in <pkcs#8-private-key> -out <pkcs#1-private-key>

This will produce an equivalent PKCS#1 encoded private key that begins with the line:

	-----BEGIN RSA PRIVATE KEY-----

This key will parse correctly.

SAML 2.0

In SAML, the relying party (cogynt_sso) is called a SAML Service Provider(SP). Prior to an SP using an IdP for authn, the IdP and SP must establish a relationship via an exchange of metadata. This includes the exchange of their public keys as well as other info.

The Cogynt SP uses the SAML Web SSO profile. This uses HTTP to transfer the user to an IdP page where authentication occurs and then transfers the user back to Cogynt.

The SP uses the SAML Redirect Binding to transfer the user to the IdP. The redirect binding does this by using an HTTP 302 - Found redirect to the IdP authn URL specified in IdP metadata. To this URL is added a SAMLRequest query parameter containing a SAML authn request. This request is not signed and encrypted.

The IdP authenticates the user (if the user does not already have an IdP authenticated session) and generates a
SAML Assertion that contains information about the user, their attributes and other data. This assertion is wrapped in a SAML response and returned via the SAML POST binding - an HTTP POST form with the action set to the SP authn URL (specified in SP metadata). The form's SAMLResponse hidden input field contains the IDP's SAML response.

SAML Response Security

SAML supports a number of options for securing responses. This SP supports only one option - a signed response
containing an encrypted assertion. This option is broadly supported; minimizes complexity and insures response
integrity with assertion privacy.

The response is XML signed with the IdP private key and it contains one XML encrypted assertion encrypted with the SP
public key (from the SP cert in SP metadata). The SP validates the response signature with the IdP public key (from the IdP cert in IdP metadata) and decrypts the assertion with its private key.

SAML Authn Assertion NotOnOrAfter Condition

Cogynt requires that Authn Assertions contain a NotOnOrAfter Condition. Cogynt uses this condition to restrict the lifetime of its user sessions.

SAML Authn Assertion User Name Attribute

Cogynt requires that Authn Assertions contain a user name attribute. It expects its first value to contain the user name
that distinguishes each user.

SAML Authn Assertion Role Attribute

Cogynt requires that Authn Assertions contain a role attribute that lists the Cogynt roles a user has been granted. Cogynt roles must all start with "cogynt" all other roles will be ignored.

Cogynt Authn Endpoints

Depending on the success/failure of user authn, the user is redirected to one of the following endpoints:

	http://<cogynt-base-domain>/authentication-failure
	http://<cogynt-base-domain>/authenticated

Authn Session Cookie

On successful user authentication, a session cookie named authn-session is set. This is an AEAD secured, Secure, Http-only, Same-site StrictMode session cookie with Domain=.<BASE_DOMAIN> and Path=/

Authn Session Validation

Every Cogynt request must validate the authn-session cookie by POSTing its value to the validate endpoint.

If validate  succeeds, the following JSON is returned in the response body:

 {
	 "user_name": "<user-name>",
	 "roles": ["role1", "role2"]
 }

If validate fails, an HTTP 400 Bad Request Status is returned. The endpoint must redirect the user to re-logon.

Environment Variables

cogynt_sso init requires the following envs; otherwise only DB, DB_USER and DB_PW are required and the others are ignored:

	DB_HOST - the DB endpoint for this Cogynt Deployment's Postgres DB Server
	DB_USER - the DB login user
	DB_PW - the DB login password
	SAML_IDP_METADATA - the IdP Metadata supplied by the IdP used by Cogynt
	BASE_DOMAIN - the subdomain that the customer has assigned to this Cogynt deployment
	SSO_MODE - “saml” or “oidc” or "none" - the mode of SSO used by this deployment - initially only saml and none are supported
	DN_ATTR - the name of the user attribute that contains the user's distinguished name
	ROLE_ATTR - the name of the user attribute that contains the Cogynt roles a user has been granted
	SP_CERT - the fully qualified file name of the Service Provider's certificate PEM file
	SP_KEY - the fully qualified file name of the Service Provider's certificate key PEM file

Endpoints

This service provides the following endpoints.

Note - Only the SP metadata endpoint will function without having registered the SP with the customer's IdP.

	GET http://cogynt_sso.<BASE_DOMAIN>/sp/metadata - returns the SAML SP metadata
	GET http://cogynt_sso.<BASE_DOMAIN>/login - initiates user authentication with the customer's SAML IdP
	POST http://cogynt_sso.<BASE_DOMAIN>/authn - expects a SAML IdP POST Binding form with a hidden SAMLResponse input. If the user
		authenticates, their authn-session cookie is set. Response is a redirection to the either /authenticated or /authentication-failure
	POST http://cogynt_sso.<BASE_DOMAIN>/validate - expects the value of a user's authn-session cookie, it validates the auth-session cookie
		and returns user name and roles

Database

The SP uses the cogynt_sso_dev Postgres DB to store its private key and self-signed X509 certificate. This DB must
be created and populated by running the SP as a command with the init flag prior to using the SP service.

	CREATE TABLE credential (
		key VARCHAR(2000) NOT NULL,
		cert VARCHAR(10000) NOT NULL,
		aeadKey VARCHAR(2000) NOT NULL,
		idpMetadataXML VARCHAR(10000) NOT NULL,
		baseDomain VARCHAR(1000) NOT NULL,
		ssoMode VARCHAR(200) NOT NULL,
		dnAttr VARCHAR(200) NOT NULL,
		roleAttr VARCHAR(200) NOT NULL);

*/
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/julienschmidt/httprouter"
	_ "github.com/lib/pq"
	saml "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

type (

	//authnPublicSessionT is the public content of an authn-session cookie; AEADBytes is an AEAD secured JSON marshalled authnPrivateSessionT
	authnPublicSessionT struct {
		Nonce     []byte `json:"nonce"`
		AEADBytes []byte `json:"aead_bytes"`
	}

	//authnPrivateSessionT is the private content of an authn-session cookie
	authnPrivateSessionT struct {
		UserName     string   `json:"user_name"`
		Roles        []string `json:"roles"`
		NotOnOrAfter string   `json:"not_on_or_after"`
	}

	//userAndRolesT is the result returned from a successful authn-session validation
	userAndRolesT struct {
		UserName string   `json:"user_name"`
		Roles    []string `json:"roles"`
	}
)

//spKeyStoreT provides a keystore to use with the saml package
//It supports the dsig.X509KeyStore interface
type spKeyStoreT struct {
	privateKey *rsa.PrivateKey
	certDER    []byte
}

//setKeyPair sets the store's private key and cert
func (ks *spKeyStoreT) setKeyPair(privateKey *rsa.PrivateKey, cert []byte) {
	ks.privateKey = privateKey
	ks.certDER = cert
} //setKeyPair

//GetKeyPair returns the store's private key and cert
func (ks *spKeyStoreT) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ks.privateKey, ks.certDER, nil
} //GetKeyPair

var (
	/*
		This global state is initialized prior to starting the HTTP server and is read only from server requests
	*/

	/*
		Command flags
	*/
	initDB = flag.Bool("init", false, "initialize the cogynt_sso_dev Postgres DB and exit")
	port   = flag.String("port", "8080", "the port the cogynt_sso service is published on")

	/*
		Environment Variables
	*/

	//The Postgres DB where Cogynt creates its dev DBs
	dbHost = os.Getenv("DB_HOST")
	dbUser = os.Getenv("DB_USER")
	dbPW   = os.Getenv("DB_PW")

	//The SAML IdP metadata that specifies how the Cogynt SAML SP uses it to authenticate its users
	samlIdpMetadataXML = os.Getenv("SAML_IDP_METADATA")

	//The customer domain that has been assigned to the Cogynt product
	baseDomain = os.Getenv("BASE_DOMAIN")

	//The mode of ssoMode that is used for this customer - saml, oidc or none.
	ssoMode = os.Getenv("SSO_MODE")

	//the name of the user attribute that contains the users distinguished name
	dnAttr = os.Getenv("DN_ATTR")

	//The name of the user attribute that contains the Cogynt roles a user has been granted
	roleAttr = os.Getenv("ROLE_ATTR")

	//The name of the SP certificate's PEM file name
	spCertFileName = os.Getenv("SP_CERT")

	//The name of the SP certificate key's PEM file name
	spKeyFileName = os.Getenv("SP_KEY")

	/*
		Other global state
	*/

	//AEAD key used to create the AEAD cipher; this is stored in the DB
	aeadKey []byte

	//AEAD cipher used to secure authn-session cookies; since the previous cipher is lost when cogynt_sso terminates,
	//all authn-session cookies that were secured with it are invalidated
	aeadCipher cipher.AEAD

	//The content of the SP cert file
	spCertPEM []byte

	//The content of the SP cert key file
	spKeyPEM []byte

	//SAML Service Provider
	sp *saml.SAMLServiceProvider
)

//setConfig creates/replaces the cogynt_sso_dev DB and initializes its self-signed cert and AEAD key
func setConfig() {
	var (
		dbConnStr    = "user=" + dbUser + " password=" + dbPW + " host=" + dbHost
		dbConnDBStr  = "user=" + dbUser + " password=" + dbPW + " host=" + dbHost + " dbname=cogynt_sso_dev"
		db           *sql.DB
		aeadKeyBytes = make([]byte, 32)
		b64AEADKey   string
		missingEnv   bool
		badSsoMode   bool
		spCertFile   *os.File
		spKeyFile    *os.File
		spKeyBlock   *pem.Block
		spCertBlock  *pem.Block
		err          error
	)

	//Verify the required ENVs are provided and the SP cert/key files can be opened
	if dbHost == "" {
		log.Println("The DB_HOST env is blank - it must be the Cogynt SSO Postgres DB endpoint")
		missingEnv = true
	}
	if dbUser == "" {
		log.Println("The DB_USER env is blank - it must be the Cogynt SSO Postgres DB user")
		missingEnv = true
	}
	if dbPW == "" {
		log.Println("The DB_PW env is blank - it must be the Cogynt SSO Postgres DB user password")
		missingEnv = true
	}
	if samlIdpMetadataXML == "" {
		log.Println("The SAML_IDP_METADATA env is blank - it must be the metadata of the SAML Identity Provider that Cogynt will use to authenticate its users")
		missingEnv = true
	}
	if baseDomain == "" {
		log.Println("The BASE_DOMAIN env is blank - it must be the fully qualified subdomain assigned to the Cogynt application")
		missingEnv = true
	}
	if ssoMode == "" {
		log.Println("The SSO env is blank - it must be the mode of SSO_MODE used to authenticate Cogynt users (currently this must be 'saml')")
		missingEnv = true
	} else {
		if ssoMode != "saml" {
			log.Printf("SSO_MODE env value must be \"saml\" but is: %s\n", ssoMode)
			badSsoMode = true
		}
	}
	if dnAttr == "" {
		log.Println("The DN_ATTR env is blank - it must be the name of the SAML IDP attribute containing the identity of a Cogynt user")
		missingEnv = true
	}
	if roleAttr == "" {
		log.Println("The ROLE_ATTR env is blank - it must be the SAML IDP attribute containing the Cogynt roles granted to a user - only roles with the 'cogynt_' prefix are used, others are ignored")
		missingEnv = true
	}
	if spCertFileName == "" {
		log.Println("The SP_CERT env is blank - it must be the fully qualified file name of the SAML SP certificate's PEM file")
		missingEnv = true
	} else {
		spCertFile, err = os.Open(spCertFileName)
		if err != nil {
			log.Printf("Error opening the SP certificate PEM file: %s\n", err)
		}
	}
	if spKeyFileName == "" {
		log.Println("The SP_KEY env is blank - it must be the fully qualified file name of the SAML SP certificate key's PEM file")
		missingEnv = true
	} else {
		spKeyFile, err = os.Open(spKeyFileName)
		if err != nil {
			log.Printf("Error opening the SP certificate key PEM file: %s\n", err)
		}
	}
	log.Printf("\ncogynt_sso environment variables\nDB_HOST = %s\nDB_USER = %s\nDB_PW = %s\nSAML_IDP_METADATA = %s\nBASE_DOMAIN = %s\nSSO_MODE = %s\nDN_ATTR = %s\nROLE_ATTR = %s\nSP_CERT = %s\nSP_KEY = %s\n", dbHost, dbUser, dbPW, samlIdpMetadataXML, baseDomain, ssoMode, dnAttr, roleAttr, spCertFileName, spKeyFileName)

	if missingEnv || badSsoMode || spCertFile == nil || spKeyFile == nil {
		log.Fatalln("Cogynt SSO Initialization failed due to errors")
	}

	//Load the SP's cert and key
	spCertPEM, err = ioutil.ReadAll(spCertFile)
	if err != nil {
		log.Fatalf("Read of SP certificate PEM file failed: %s\n", err)
	}
	spKeyPEM, err = ioutil.ReadAll(spKeyFile)
	if err != nil {
		log.Fatalf("Read of SP certificate key PEM file failed: %s\n", err)
	}

	//Verify that the SP key/cert can be PEM decoded and that the key can be parsed as an RSA Private Key
	spKeyBlock, _ = pem.Decode(spKeyPEM)
	if spKeyBlock == nil {
		log.Fatalf("PEM decode of private key failed: \n")
	}
	_, err = x509.ParsePKCS1PrivateKey(spKeyBlock.Bytes)
	if err != nil {
		log.Fatalf("\nPKCS Parse of the private key failed\nprivate key:\n%+v\nerror: %s\n", spKeyBlock, err)
	}
	spCertBlock, _ = pem.Decode(spCertPEM)
	if spCertBlock == nil {
		log.Fatalf("PEM decode of SP cert failed: %s\n", err)
	}

	//Create a AES256 key for the AEAD cipher
	_, err = rand.Read(aeadKeyBytes)
	if err != nil {
		log.Fatalf("Create of AEAD key failed: %s\n", err)
	}

	//Connect to the Postgres DB server
	db, err = sql.Open("postgres", dbConnStr)
	if err != nil {
		log.Fatalf("Connection to Postgres DB server failed: %s\n", err)
	}

	//Drop the cogynt_sso_dev DB if it exists and recreate it
	_, err = db.Exec("DROP DATABASE IF EXISTS cogynt_sso_dev")
	if err != nil {
		log.Fatalf("DROP DATABASE IF EXISTS cogynt_sso_dev failed: %s\n", err)
	}
	_, err = db.Exec("CREATE DATABASE cogynt_sso_dev")
	if err != nil {
		log.Fatalf("CREATE DATABASE cogynt_sso_dev failed: %s\n", err)
	}

	//Close the DB connection and reconnect to the newly created DB
	err = db.Close()
	if err != nil {
		log.Fatalf("Close connection to Postgres DB failed: %s\n", err)
	}
	db, err = sql.Open("postgres", dbConnDBStr)
	if err != nil {
		log.Fatalf("Connection to cogynt_sso_dev Postgres DB failed: %s\n", err)
	}

	//Create the credential table
	_, err = db.Exec("CREATE TABLE credential (key VARCHAR(2000) NOT NULL, cert VARCHAR(10000) NOT NULL, aeadKey VARCHAR(2000) NOT NULL, idpMetadataXML VARCHAR(10000) NOT NULL, baseDomain VARCHAR(1000) NOT NULL, ssoMode VARCHAR(200) NOT NULL, dnAttr VARCHAR(200) NOT NULL, roleAttr VARCHAR(200) NOT NULL);")
	if err != nil {
		log.Fatalf("CREATE TABLE credential (key VARCHAR(2000) NOT NULL, cert VARCHAR(10000) NOT NULL, aeadKey VARCHAR(2000) NOT NULL, idpMetadataXML VARCHAR(10000) NOT NULL, baseDomain VARCHAR(1000) NOT NULL, ssoMode VARCHAR(200) NOT NULL, dnAttr VARCHAR(200) NOT NULL, roleAttr VARCHAR(200) NOT NULL); failed: %s\n", err)
	}

	//Verify the lengths of the SSO config values don't exceed their DB column size
	if len(spCertPEM) > 10000 {
		log.Fatalf("SP_CERT can have a maximum length of 10000. Its current length is %d\n", len(spCertPEM))
	}
	if len(spKeyPEM) > 2000 {
		log.Fatalf("SP_KEY can have a maximum length of 2000. Its current length is %d\n", len(spKeyPEM))
	}
	b64AEADKey = base64.StdEncoding.EncodeToString(aeadKeyBytes)
	if len(b64AEADKey) > 2000 {
		log.Fatalf("base64 encoded AEAD key can have a maximum length of 10000. Its current length is %d\n", len(b64AEADKey))
	}
	if len(samlIdpMetadataXML) > 10000 {
		log.Fatalf("SAML_IDP_METADATA can have a maximum length of 10000. Its current length is %d\n", len(samlIdpMetadataXML))
	}
	if len(baseDomain) > 1000 {
		log.Fatalf("BASE_DOMAIN can have a maximum length of 1000. Its current length is %d\n", len(baseDomain))
	}
	if len(ssoMode) > 200 {
		log.Fatalf("SSO_MODE can have a maximum length of 200. Its current length is %d\n", len(ssoMode))
	}
	if len(dnAttr) > 200 {
		log.Fatalf("DN_ATTR can have a maximum length of 200. Its current length is %d\n", len(dnAttr))
	}
	if len(roleAttr) > 200 {
		log.Fatalf("ROLE_ATTR can have a maximum length of 200. Its current length is %d\n", len(roleAttr))
	}

	//Store the configuration of the SP as the first row of it's credential table
	_, err = db.Exec("INSERT INTO credential (key, cert, aeadKey, idpMetadataXML, baseDomain, ssoMode, dnAttr, roleAttr) VALUES($1, $2, $3, $4, $5, $6, $7, $8)", string(spKeyPEM), string(spCertPEM), b64AEADKey, samlIdpMetadataXML, baseDomain, ssoMode, dnAttr, roleAttr)
	if err != nil {
		log.Fatalf("INSERT INTO credential (key, cert, aeadKey, idpMetadataXML, baseDomain, ssoMode, dnAttr, roleAttr) VALUES($1, $2, $3, $4, $5, $6, $7, $8) failed: %s\n", err)
	}
	log.Println("The cogynt_sso_dev Postgres DB has been created and initialized")

} //setConfig

//getConfig
func getConfig() {
	var (
		dbConnStr  = "user=" + dbUser + " password=" + dbPW + " host=" + dbHost + " dbname=cogynt_sso_dev"
		db         *sql.DB
		row        *sql.Row
		b64AEADKey string
		err        error
	)

	//Verify the required ENVs are provided and log them
	if (dbHost == "") || (dbUser == "") || (dbPW == "") {
		log.Fatalf("A required ENV is blank or missing\n DB = %s\nDB_USER = %s\nDB_PW = %s\n", dbHost, dbUser, dbPW)
	}
	log.Printf("cogynt_sso environment variables\nDB = %s\nDB_USER = %s\nDB_PW = %s\n", dbHost, dbUser, dbPW)

	//Connect to the DB
	db, err = sql.Open("postgres", dbConnStr)
	if err != nil {
		log.Fatalf("Connection to cogynt_sso_dev DB failed: %s\n", err)
	}

	//Select the first and only row of the credential table
	row = db.QueryRow("SELECT key, cert, aeadKey, idpMetadataXML, baseDomain, ssoMode, dnAttr, roleAttr FROM credential")

	//Retrieve the row's private key PEM and b64 cert DER
	err = row.Scan(&spKeyPEM, &spCertPEM, &b64AEADKey, &samlIdpMetadataXML, &baseDomain, &ssoMode, &dnAttr, &roleAttr)
	if err != nil {
		log.Fatalf("Scan of SELECT key, cert, aeadKey, idpMetadataXML, baseDomain, ssoMode, dnAttr, roleAttr FROM credential row failed: %s\n", err)
	}

	aeadKey, err = base64.StdEncoding.DecodeString(b64AEADKey)
	if err != nil {
		log.Fatalf("base64 decode of AEAD key failed: %s\n", err)
	}

} //getConfig

//initAEAD initializes the cipher block used to AEAD secure authn-session cookies
func initAEAD(key []byte) error {
	var (
		block cipher.Block
		err   error
	)

	//Create a cipher block
	block, err = aes.NewCipher(key)
	if err != nil {
		return err
	}

	//Initialize the global AEAD cipher used to seal authn-session cookies
	aeadCipher, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}

	return nil

} //initAEAD

//authnSessionSeal produces a JSON marshalled authnPublicSessionT that is used to set the user's authn-session cookie
func authnSessionSeal(authnPrivateSession *authnPrivateSessionT) (string, error) {
	var (
		authnPublicSession        authnPublicSessionT
		authnPublicSessionJSON    []byte
		b64AuthnPublicSessionJSON string
		authnPrivateSessionJSON   []byte
		err                       error
	)

	//Create a nonce for this authnSession
	authnPublicSession.Nonce = make([]byte, aeadCipher.NonceSize())
	_, err = rand.Read(authnPublicSession.Nonce)
	if err != nil {
		return "", err
	}

	//Marshal the authnPrivateSession
	authnPrivateSessionJSON, err = json.Marshal(authnPrivateSession)
	if err != nil {
		return "", err
	}

	//AEAD seal authnPrivateSession
	authnPublicSession.AEADBytes = aeadCipher.Seal(nil, authnPublicSession.Nonce, authnPrivateSessionJSON, nil)

	//Marshal the authnPublicSession which will be the value of an authn-session cookie
	authnPublicSessionJSON, err = json.Marshal(authnPublicSession)
	if err != nil {
		return "", err
	}
	b64AuthnPublicSessionJSON = base64.StdEncoding.EncodeToString(authnPublicSessionJSON)

	return b64AuthnPublicSessionJSON, nil

} //authnSessionSeal

//authnSessionOpen authenticates, decrypts and unmarshals the authnPrivateSession which is the content of an authnPublicSession AEADBytes
func authnSessionOpen(b64AuthnPublicSessionJSON string) (*authnPrivateSessionT, error) {
	var (
		authnPublicSessionJSON  []byte
		authnPublicSession      authnPublicSessionT
		authnPrivateSessionJSON []byte
		authnPrivateSession     authnPrivateSessionT
		err                     error
	)

	//Unmarshal the authnPublicSession
	authnPublicSessionJSON, err = base64.StdEncoding.DecodeString(b64AuthnPublicSessionJSON)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(authnPublicSessionJSON, &authnPublicSession)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshal of authnPublicSessionJSON failed: %s", err)
	}

	//Open and unmarshal the AEAD secured authn private session
	authnPrivateSessionJSON, err = aeadCipher.Open(nil, authnPublicSession.Nonce, authnPublicSession.AEADBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("aeadCipher.Open failed: %s", err)
	}
	err = json.Unmarshal(authnPrivateSessionJSON, &authnPrivateSession)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshal of authnPrivateSessionJSON failed: %s", err)
	}

	return &authnPrivateSession, nil

} //authnSessionOpen

//initSP initializes the SAML SP and returns its XML formatted SP metadata
func initSP() {
	var (
		idpMetadata  types.EntityDescriptor
		idpCertStore = dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{}}
		idpCertDER   []byte
		idpCert      *x509.Certificate
		spKey        *rsa.PrivateKey
		spKeyBlock   *pem.Block
		spCertBlock  *pem.Block
		spKeyStore   spKeyStoreT
		err          error
	)

	//Decode the stored SP key, cert and AEAD key
	spKeyBlock, _ = pem.Decode(spKeyPEM)
	if spKeyBlock == nil {
		log.Fatalf("PEM decode of private key failed: \n")
	}
	spKey, err = x509.ParsePKCS1PrivateKey(spKeyBlock.Bytes)
	if err != nil {
		log.Fatalf("PKCS Parse of the private key failed: %s\n", err)
	}
	spCertBlock, _ = pem.Decode(spCertPEM)
	if spCertBlock == nil {
		log.Fatalf("PEM decode of SP cert failed: %s\n", err)
	}

	//init sp keystore
	spKeyStore.setKeyPair(spKey, spCertBlock.Bytes)

	//Unmarshal IdP metadata
	err = xml.Unmarshal([]byte(samlIdpMetadataXML), &idpMetadata)
	if err != nil {
		log.Fatalf("XML unmarshal of IdP metadata failed: %s\n", err)
	}

	//Initialize the idpCertStore using the IdP cert in the IdP's metadata
	for _, kd := range idpMetadata.IDPSSODescriptor.KeyDescriptors {
		for _, b64CertDER := range kd.KeyInfo.X509Data.X509Certificates {
			if b64CertDER.Data == "" {
				log.Fatalf("IdP metadata cert is empty\n")
			}
			idpCertDER, err = base64.StdEncoding.DecodeString(b64CertDER.Data)
			if err != nil {
				log.Fatalf("IdP metadata cert b64 decode failed: %s\n", err)
			}
			idpCert, err = x509.ParseCertificate(idpCertDER)
			if err != nil {
				log.Fatalf("IdP metadata cert parse failed: %s\n", err)
			}
			idpCertStore.Roots = append(idpCertStore.Roots, idpCert)
		}
	}

	//Initialize the SAML SP
	sp = &saml.SAMLServiceProvider{
		IdentityProviderSSOURL:      idpMetadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IdentityProviderIssuer:      idpMetadata.EntityID,
		ServiceProviderIssuer:       baseDomain,
		AssertionConsumerServiceURL: "https://sso-cogynt." + baseDomain + "/authn",
		SignAuthnRequests:           false,
		AudienceURI:                 baseDomain,
		IDPCertificateStore:         &idpCertStore,
		SPKeyStore:                  &spKeyStore,
		AllowMissingAttributes:      false,
	}

} //initSP

//spMetadata returns the SP metadata
func spMetadata() []byte {
	var (
		spMetadata    *types.EntityDescriptor
		spMetadataXML []byte
		err           error
	)

	//Return the SP metadata as XML
	spMetadata, err = sp.Metadata()
	if err != nil {
		log.Fatalf("Creation of SP metadata failed: %s\n", err)
	}
	spMetadataXML, err = xml.Marshal(spMetadata)
	if err != nil {
		log.Fatalf("XML marshall of SP metadata failed: %s\n", err)
	}

	return spMetadataXML

} //spMetadata

//spMetadataHandler returns Cogynt SSO metadata. This is used to register this SP with the customer's IdP
func spMetadataHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

	w.Header().Set("Content-Type", "application/xml")
	_, err := w.Write(spMetadata())
	if err != nil {
		log.Printf("Error writing SP metadata: %s\n", err)
	}

} //spMetadataHandler

//loginHandler handles user logon requests that send a SAML authn request to the IdP via the SAML Redirect binding. This
//binding is a 302 Found status to the IdP endpoint with a SAMLRequest query parameter containing an unsigned,
//unencrypted SAML Authn request. Since the IdP response is signed and encrypted, there is no risk that an unsecured
//request can be responded to by other than the correct IdP.
func loginHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

	//The SP generates the SAML IdP Authn request via the SAML Redirect binding
	err := sp.AuthRedirect(w, r, "")
	if err != nil {
		log.Printf("SP Authn Redirect request failed: %s\n", err)
	}

} //logonHandler

//authnHandler handles authn responses from an IdP; if authn succeeds the user's authn-session cookie is set
func authnHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var (
		assertionInfo             *saml.AssertionInfo
		authnPrivateSession       *authnPrivateSessionT
		b64AuthnPublicSessionJSON string
		authnSessionCookie        *http.Cookie
		notOnOrAfterGob           []byte
		b64NotOnOrAfterGob        string
		userName                  string
		roles                     = make([]string, 0, 5)
		nameAttribute             types.Attribute
		rolesAttribute            types.Attribute
		ok                        bool
		err                       error
	)

	//An IdP responds to an authn request with an HTTP POST form with an action of this endpoint and a hidden
	//SAMLResponse input containing a SAML Authn Assertion (a SAML POST binding)
	err = r.ParseForm()
	if err != nil {
		log.Printf("Parse of the POST binding form failed: %s\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Extract the SAML Authn Assertion and, if not found, redirect to the authn failure endpoint
	assertionInfo, err = sp.RetrieveAssertionInfo(r.FormValue("SAMLResponse"))
	if err != nil {
		log.Printf("Retrieve of the POST binding assertion failed: %s\n", err)
		w.Header().Set("Location", "https://app-cogynt."+baseDomain+"/authentication-failure")
		w.WriteHeader(http.StatusFound)
		return
	}

	//If the assertion reports these warnings, it is rejected and the user is redirected to the authn failure endpoint
	if assertionInfo.WarningInfo.InvalidTime {
		log.Printf("assertionInfo.WarningInfo.InvalidTime\n")
		w.Header().Set("Location", "https://app-cogynt."+baseDomain+"/authentication-failure")
		w.WriteHeader(http.StatusFound)
		return
	}
	if assertionInfo.WarningInfo.NotInAudience {
		log.Printf("assertionInfo.WarningInfo.NotInAudience\n")
		w.Header().Set("Location", "https://app-cogynt.//"+baseDomain+"/authentication-failure")
		w.WriteHeader(http.StatusFound)
		return
	}

	//Transform dn attribute to name
	nameAttribute, ok = assertionInfo.Values[dnAttr]
	if !ok {
		log.Printf("User's distinguished name is missing\n")
		w.Header().Set("Location", "https://app-cogynt.//"+baseDomain+"/authentication-failure")
		w.WriteHeader(http.StatusFound)
		return
	}
	userName = nameAttribute.Values[0].Value

	//Transform roles attribute to roles []string filtering out any non-Cogynt roles
	rolesAttribute, ok = assertionInfo.Values[roleAttr]
	if !ok {
		log.Printf("User's roles are missing\n")
		w.Header().Set("Location", "https://app-cogynt.//"+baseDomain+"/authentication-failure")
		w.WriteHeader(http.StatusFound)
		return
	}
	for _, roleAttr := range rolesAttribute.Values {
		if roleAttr.Value[:len("cogynt")] == "cogynt" {
			roles = append(roles, roleAttr.Value)
		}
	}
	if len(roles) == 0 {
		log.Printf("User's roles are missing\n")
		w.Header().Set("Location", "https://app-cogynt.//"+baseDomain+"/authentication-failure")
		w.WriteHeader(http.StatusFound)
		return
	}

	//Auth sessions enforce the SAML NotOnOrAfter assertion condition. This value is stored in the session as a
	//b64 encoded time gob. Assertions without this condition are not accepted.
	if assertionInfo.SessionNotOnOrAfter == nil {
		log.Println("NotOnOrAfter is missing", err)
		w.Header().Set("Location", "https://app-cogynt."+baseDomain+"/authentication-failure")
		w.WriteHeader(http.StatusFound)
		return
	}
	notOnOrAfterGob, err = assertionInfo.SessionNotOnOrAfter.GobEncode()
	if err != nil {
		log.Printf("Gob encode of the assertion NotOnOrAfter failed: %s\n", err)
		w.Header().Set("Location", "https://app-cogynt."+baseDomain+"/authentication-failure")
		w.WriteHeader(http.StatusFound)
		return
	}
	b64NotOnOrAfterGob = base64.StdEncoding.EncodeToString(notOnOrAfterGob)

	//Initialize the user's private authn session
	authnPrivateSession = &authnPrivateSessionT{UserName: userName, Roles: roles, NotOnOrAfter: b64NotOnOrAfterGob}

	//Generate and set an authn-session cookie containing a sealed authn private session
	b64AuthnPublicSessionJSON, err = authnSessionSeal(authnPrivateSession)
	if err != nil {
		log.Printf("authnHandler authnSessionSeal error: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	authnSessionCookie = &http.Cookie{Name: "authn-session", Value: b64AuthnPublicSessionJSON, Domain: "." + baseDomain, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	http.SetCookie(w, authnSessionCookie)

	//Redirect to Cogynt authenticated endpoint
	w.Header().Set("Location", "https://app-cogynt."+baseDomain+"/authenticated")
	w.WriteHeader(http.StatusFound)

} //authnHandler

//validateHandler handles validation of a user's authn-session cookie and retrieval of the user name and roles it contains
func validateHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var (
		b64uthnPublicSessionJSON []byte
		authnPrivateSession      *authnPrivateSessionT
		userAndRoles             userAndRolesT
		userAndRolesJSON         []byte
		notOnOrAfterGob          []byte
		notOnOrAfter             = &time.Time{}
		err                      error
	)

	//Read the POSTed authnPublicSession
	b64uthnPublicSessionJSON, err = ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("validateHandler failed to read b64uthnPublicSessionJSON: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Open the authnPrivateSession and return its user name and roles
	authnPrivateSession, err = authnSessionOpen(string(b64uthnPublicSessionJSON))
	if err != nil {
		log.Printf("validateHandler authnSessionOpen failed: %s\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Enforce SAML NotOnOrAfter
	if authnPrivateSession.NotOnOrAfter == "" {
		log.Printf("NotOnOrAfter condition is missing\n")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	notOnOrAfterGob, err = base64.StdEncoding.DecodeString(authnPrivateSession.NotOnOrAfter)
	if err != nil {
		log.Printf("B64 decode of NotOnOrAfter failed: %s\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err = notOnOrAfter.GobDecode(notOnOrAfterGob)
	if err != nil {
		log.Printf("Gob decode of NotOnOrAfter failed: %s\n", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if time.Now().After(*notOnOrAfter) {
		log.Printf("NotOnOrAfter condition has elapsed\n")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	//Return the authn-session name and roles
	userAndRoles = userAndRolesT{UserName: authnPrivateSession.UserName, Roles: authnPrivateSession.Roles}
	userAndRolesJSON, err = json.Marshal(userAndRoles)
	if err != nil {
		log.Printf("JSON marshal of userAndRoles failed: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(userAndRolesJSON)
	if err != nil {
		log.Printf("http.Write of userAndRoles failed: %s\n", err)
	}

} //validateHandler

func main() {
	var (
		router = httprouter.New()
		err    error
	)

	//Parse command flags
	flag.Parse()

	//If init mode, initialize the cogynt_sso_dev DB with the cogynt_sso config
	if *initDB {
		setConfig()

		//Initialize the SP to verify that this is possible.
		initSP()

		return
	}

	//The cogynt_sso config is retrieved from the cogynt_sso_dev Postgress DB
	getConfig()

	//Initialize the SAML SP
	initSP()

	//Initialize the AEAD cipher used to protect authn-session cookies
	err = initAEAD(aeadKey)
	if err != nil {
		log.Fatalf("cogynt_sso has terminated with an initAEAD error: %s\n", err)
	}

	//Register request handlers
	router.GET("/sp/metadata", spMetadataHandler)
	router.GET("/login", loginHandler)
	router.POST("/authn", authnHandler)
	router.POST("/validate", validateHandler)

	//Start cogynt_sso
	log.Println("Starting cogynt_sso on port " + *port)
	log.Fatal(http.ListenAndServe(":"+*port, router))
}
