{
	email $CADDY_ACME_EMAIL
}

# Fragmento `certify_comun` (templates/Caddyfile.comun.inc): actuator, did.json, contextos, logos y
# proxy a Certify. generate-caddy.sh lo inserta aquí, ANTES del bloque de sitio: Caddy exige que un
# fragmento esté definido antes de importarlo.
$CADDY_FRAGMENTO_COMUN

$IP_HOSTNAME {
	import certify_comun
}
