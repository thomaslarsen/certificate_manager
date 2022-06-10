# Certificate manager

This Certificate Manager (CM) provides an API for the following certificate actions:

  * Create root CAs
  * Create intermediate CAs
  * Issue end-entity (EE) certificates, signed with any of the CAs
  * Sign CSRs with any of the CAs

The primary usecase is to issue certificates for server endpoints within a private security domain.

# Use cases

## How to manage access

Example domain

* Platform team, who manages the CM
* Intermediate CAs for teams, split into a live and a test CA
* Certificate sub-domains based on <live|non-live>.<team>.<org>.local
* Roles to issue _server_ type certificates

The user roles are:

* platform-admin - allowed to create intermediate CAs for teams
* team-admin - allowed to create roles for team scoped intermediate CAs
* team-user - allowed to issue certs using live/non-live intermediate CAs respectively

In this example we will use a team called _business_. We will create the following intermediate CAs:

* business-live
* business-test

We will create the following root CA:

* root

General policy:

Allowed paths:

* `/ca` - GET
* `/ca/*/cert` - GET
* `/ca/*/ca-chain` - GET

platform-admin policy:


Allowed paths:

* `/ca/root` - POST
* `/ca/*` - GET, DELETE
* `/ca/*/intermediate` - POST


team-admin policy:

Allowed paths:

* `/ca/business-*` - GET
* `/ca/business-*/roles/*` - GET, PUT, DELETE
* `/ca/business-*/roles` - GET

team-user policy:

Allowed paths:

* `/ca/business-*/roles` - GET
* `/ca/business-*/roles/*` - GET
* `/cert/business-*/issue/*` - POST
* `/cert/business-*/sign/*` - POST

A more specific policy allowing only a certain role can be created:

* `/cert/business-live/issue/server` - POST
* `/cert/business-live/sign/server` - POST
* `/ca/business-live/roles/server` - GET
