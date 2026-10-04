# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 0 |
| Low | 1 |
| Informational | 3 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Low | Warning |  | ZAP warnings logged - see the zap.log file for details | 3    |
| Info | Informational | http://host.docker.internal:8000 | Percentage of responses with status code 2xx | 27 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of responses with status code 4xx | 72 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with content type application/json | 100 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method DELETE | 5 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method GET | 66 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method POST | 22 % |
| Info | Informational | http://host.docker.internal:8000 | Percentage of endpoints with method PUT | 5 % |
| Info | Informational | http://host.docker.internal:8000 | Count of total endpoints | 18    |
| Info | Informational | http://host.docker.internal:8000 | Percentage of slow responses | 5 % |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Timestamp Disclosure - Unix | Low | 2 |
| A Client Error response code was returned by the server | Informational | 13 |
| Authentication Request Identified | Informational | 1 |
| Non-Storable Content | Informational | Systemic |




## Alert Detail



### [ Timestamp Disclosure - Unix ](https://www.zaproxy.org/docs/alerts/10096/)



##### Low (Low)

### Description

A timestamp was disclosed by the application/web server. - Unix

* URL: http://host.docker.internal:8000/auth/eu
  * Node Name: `http://host.docker.internal:8000/auth/eu`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1791073609`
  * Other Info: `1791073609, which evaluates to: 2026-10-04 00:26:49.`
* URL: http://host.docker.internal:8000/auth/eu
  * Node Name: `http://host.docker.internal:8000/auth/eu`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `1791074509`
  * Other Info: `1791074509, which evaluates to: 2026-10-04 00:41:49.`


Instances: 2

### Solution

Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.

### Reference


* [ https://cwe.mitre.org/data/definitions/200.html ](https://cwe.mitre.org/data/definitions/200.html)


#### CWE Id: [ 497 ](https://cwe.mitre.org/data/definitions/497.html)


#### WASC Id: 13

#### Source ID: 3

### [ A Client Error response code was returned by the server ](https://www.zaproxy.org/docs/alerts/100000/)



##### Informational (High)

### Description

A response code of 401 was returned by the server.
This may indicate that the application is failing to handle unexpected input correctly.
Raised by the 'Alert on HTTP Response Code Error' script

* URL: http://host.docker.internal:8000/consultas/10
  * Node Name: `http://host.docker.internal:8000/consultas/10`
  * Method: `DELETE`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/auditoria%3Flimite=100
  * Node Name: `http://host.docker.internal:8000/admin/auditoria (limite)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `403`
  * Other Info: ``
* URL: http://host.docker.internal:8000/admin/usuarios
  * Node Name: `http://host.docker.internal:8000/admin/usuarios`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `403`
  * Other Info: ``
* URL: http://host.docker.internal:8000/consultas%3Fdata=
  * Node Name: `http://host.docker.internal:8000/consultas (data)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/consultas/10
  * Node Name: `http://host.docker.internal:8000/consultas/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/consultas/agenda%3Fdata=
  * Node Name: `http://host.docker.internal:8000/consultas/agenda (data)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `403`
  * Other Info: ``
* URL: http://host.docker.internal:8000/laboratorio/horarios-disponiveis%3Fespecialidade=cardiologia&data=
  * Node Name: `http://host.docker.internal:8000/laboratorio/horarios-disponiveis (data,especialidade)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `403`
  * Other Info: ``
* URL: http://host.docker.internal:8000/pacientes/10
  * Node Name: `http://host.docker.internal:8000/pacientes/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``
* URL: http://host.docker.internal:8000/auth/mfa
  * Node Name: `http://host.docker.internal:8000/auth/mfa ()({challenge_id,codigo})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/auth/token
  * Node Name: `http://host.docker.internal:8000/auth/token ()(client_id,client_secret,grant_type,password,scope,username)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `401`
  * Other Info: ``
* URL: http://host.docker.internal:8000/consultas
  * Node Name: `http://host.docker.internal:8000/consultas ()({paciente_id,inicio,duracao_minutos,motivo,observacoes})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``
* URL: http://host.docker.internal:8000/pacientes
  * Node Name: `http://host.docker.internal:8000/pacientes ()({nome,cpf,data_nascimento,email,telefone,profissional_responsavel_id})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `403`
  * Other Info: ``
* URL: http://host.docker.internal:8000/consultas/10
  * Node Name: `http://host.docker.internal:8000/consultas/10 ()({inicio,duracao_minutos,status,motivo,observacoes})`
  * Method: `PUT`
  * Parameter: ``
  * Attack: ``
  * Evidence: `404`
  * Other Info: ``


Instances: 13

### Solution



### Reference



#### CWE Id: [ 388 ](https://cwe.mitre.org/data/definitions/388.html)


#### WASC Id: 20

#### Source ID: 4

### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (Low)

### Description

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: http://host.docker.internal:8000/auth/token
  * Node Name: `http://host.docker.internal:8000/auth/token ()(client_id,client_secret,grant_type,password,scope,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=username
passwordParam=password`


Instances: 1

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ Non-Storable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.

* URL: http://host.docker.internal:8000/auth/eu
  * Node Name: `http://host.docker.internal:8000/auth/eu`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://host.docker.internal:8000/consultas/10
  * Node Name: `http://host.docker.internal:8000/consultas/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://host.docker.internal:8000/consultas/agenda%3Fdata=
  * Node Name: `http://host.docker.internal:8000/consultas/agenda (data)`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://host.docker.internal:8000/pacientes/10
  * Node Name: `http://host.docker.internal:8000/pacientes/10`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://host.docker.internal:8000/consultas
  * Node Name: `http://host.docker.internal:8000/consultas ()({paciente_id,inicio,duracao_minutos,motivo,observacoes})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``

Instances: Systemic


### Solution

The content may be marked as storable by ensuring that the following conditions are satisfied:
The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)
The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)
The "no-store" cache directive must not appear in the request or response header fields
For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response
For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)
In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:
It must contain an "Expires" header field
It must contain a "max-age" response directive
For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive
It must contain a "Cache Control Extension" that allows it to be cached
It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3


