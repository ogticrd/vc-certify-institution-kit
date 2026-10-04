{
	email $CADDY_ACME_EMAIL
}

$IP_HOSTNAME {
	route /.well-known/did.json {
		rewrite * /v1/certify/.well-known/did.json
		reverse_proxy certify:8090
	}
	route /.well-known/openid-credential-issuer {
		rewrite * /v1/certify/.well-known/openid-credential-issuer
		reverse_proxy certify:8090
	}
	reverse_proxy /v1/certify/* certify:8090
}
