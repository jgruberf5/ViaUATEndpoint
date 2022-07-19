# ViaUATEndpoint
Via UAT Endpoint Application

This application lets you set a configuration policy which will match
source IP CIDR of a client (IPv4 and IPv6), HTTP method, Header, and
path regex to enable the injection of latency in responce, issuing of
response status codes, and response body content.

The application has OpenAPI Swagger interface at `/docs`.

The applicaiton has Redoc documentation inteface at `redoc`.


## Build

```
docker build -t viauatapp:latest
```

## Run from Dockerhub

```
docker run --name='testapp' --rm  -p 80:80 jgruberf5/viauatapp:latest
```
