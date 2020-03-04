# Cogynt Core SSO

This repo contains a Go Module that consists of the cogynt_core_sso microservice and services for testing it.

The systemd unit files, NginX configs and cert/key files are for deploying test services. Only the `cogynt_core_sso/cogynt_core_sso.go` source is for production use. The binary for each of these services is created with the `go install` command. The `go.mod` file contains the package dependencies of this module.

* **cogynt_core_sso** - a single-signon service for the Cogynt product
* **mock_idp** - a mock SAML Identity Provider containing mock users
* **mock_cogynt** - a mock of a Cogynt login page

## cogynt_core_sso

See the godoc for in `cogynt_core_sso/cogynt_core_sso.go` for a full description of its functionality.
