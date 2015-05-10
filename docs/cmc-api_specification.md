#cmc-api specification


## Features

######Required
* It must allow the client to get all certificates.
* It must allow the client to get all certificates with their expiration statuses. (Expired/WillExpired/UpToDate)
* It must allow the client to search certificate by common name (CN).
* It must allow the client to add/import/edit new certificate.
* It must allow the client to get certificate core information.

######Optional
* It must allow the client to get all certificates on a server.
* It must allow the client to download certificate in a specific format (PEM).
* It must allow the client to get all certificates for a service.
* It must allow the client to self-signed a certificate.
* It must allow the client to sign a certificate.
* It must allow the client to generate a certificate request.


<br/>
## Resources


####Certificate resource

######Required
|Activity|Noun/Verb Mapping |
|:------------ | ------------- |
|List certificates | GET /certificates  |
|Get certificate | GET /certificates/**{id}**  |
|Get certificate status | GET /certificates/**{id}**/status  |
|Create certiticate | POST /certificates  |
|Edit certiticate | PUT /certificates/**{id}**  |
|Delete certiticate | DELETE /certificates/**{id}**  |
|Search certificate by common name | GET /certificates?cn=**{common_name}** |

<br/>
######Optional
|Activity|Noun/Verb Mapping |
|:------------ | ------------- |
|Download certificate as format | GET /certificates/{id}?format=**{format}**|
|List certificates on server  | GET /certificates?server=**{server_name}**|
|List certificate's servers  | GET /certificates/**{id}**/servers|
|List certificates for service  | GET /certificates?service=**{service_name}** |
|Sign/Self-sign certificate | POST /certificates/**{id}**/sign?self=[true|false]|
|Generate certificate request | POST /certificates/**{id}**/request|


<br/>
## Requirements 

####Design constraints

######Database
All certificates data/metadata will be stored in a SQLite3 database. All records will be stored in a file named **cmc.db**

<br/>
####Interface to external services

######Authentification
The System authenticate client via a Central Authentication Service (CAS).

<br/>
####Implementation

######Language
The language used to build the API will be the **Go programming language**. Go application are too easy to deploy. In fact, the deployment process is as simple as copying a binary onto the server.

######Third-party libraries or components

**[crypto](https://golang.org/pkg/crypto/)** : A package that provides cryptograpic tools and helps to manage everything certificates related. 

**[martini](http://martini.codegangsta.io/)** : A web framework wirtten in Go. It provides a way to create great and fast API.

**[golang-cas-client](https://github.com/lucasuyezu/golang-cas-client)** : A experimental go client for CAS.

**[gorm](https://github.com/jinzhu/gorm)** : An ORM library for Golang. It will be used to interact with the database.