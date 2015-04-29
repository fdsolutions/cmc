#cmc-api specification


## Features

######Required:

* It must allow the client to get all certificates.
* It must allow the client to get all certificates with their expiration statuses. (Expired/WillExpired/UpToDate)
* It must allow the client to search certificate by common name (CN).
* It must allow the client to add/import/edit new certificate.
* It must allow the client to get certificate core information.

######Optional:
* It must allow the client to get all certificates on a server.
* It must allow the client to download certificate in a specific format (PEM).
* It must allow the client to get all certificates for a service.


<br/>
### Resources


###### Certificate resource

|Activity|Noun/Verb Mapping |
|:------------ | ------------- |
|List certificates | GET /certificates  |
|Get certificate | GET /certificates/**{id}**  |
|Get certificate status | GET /certificates/**{id}**/status  |
|Create certiticate | POST /certificates  |
|Edit certiticate | PUT /certificates/**{id}**  |
|Delete certiticate | DELETE /certificates/**{id}**  |
|Search certificate | GET /certificates?search=**{criterias}** |
|Download certificate as format | GET /certificates/{id}?format=**{format}** |
|List certificates on server  | GET /certificates?server=**{server_name}** |
|List certificate's servers  | GET /certificates/**{id}**/servers |
|List certificates for service  | GET /certificates?service=**{service_name}** |




