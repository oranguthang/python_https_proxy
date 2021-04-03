# python_https_proxy
Example of HTTP/HTTPS proxy with the possibility of mitm attack in pure Python

This proxy passes browser traffic through itself and send all responses to user

To use it, you need to generate certificates using the commands:

1. `openssl genrsa -out ca.key 2048`
1. `openssl req -new -x509 -days 7 -key ca.key -out ca.crt -subj "/CN=python_https_proxy CA"`
1. `openssl genrsa -out cert.key 2048`

Then install the ca.crt certificate to the browser and specify the address and port
of the proxy server in the browser settings