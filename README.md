# ViaUATEndpoint
Via UAT Endpoint Application

This application lets you set a configuration policy which will match
source IP CIDR of a client (IPv4 and IPv6), HTTP method, Header, and
path regex to enable the injection of latency in response, issuing of
response status codes, and response body content.

The application has OpenAPI Swagger interface at `/docs`.

The applicaiton has Redoc documentation inteface at `/redoc`.

![SwaggerIO](/static/images/swaggerui.jpg)

## Build

```
docker build -t viauatapp:latest
```

## Run from Dockerhub

```
docker run --name='testapp' --rm  -p 80:80 jgruberf5/viauatapp:latest
```


## Overriding Reload Setting

To disable configuration reload, set an environment variable:

```
BYPASS_RELOAD=true
```

This will only stop the configuration reloading from happening on any 
container with this environment variable set. It will not override the
value of the `reload_timer` value in settings.
