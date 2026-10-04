# Modo proxy (R6, D5): hay un proxy inverso de la institución delante (nginx, F5, balanceador…) que
# termina el TLS. Caddy solo habla HTTP, en :80 dentro del contenedor (el servidor publica
# CADDY_HTTP_PORT), sin certificados, sin ACME y sin correo: nada sale a Let's Encrypt.
{
	auto_https off

	# CONFIANZA EN EL PROXY. Detrás de un proxy TODA petición llega desde una IP privada (la del
	# proxy), así que `remote_ip private_ranges` daría por «interno» a cualquiera de internet y el
	# `health` del actuator quedaría público. Con trusted_proxies, Caddy cree en X-Forwarded-For SOLO
	# si la conexión viene de uno de esos rangos (TRUSTED_PROXIES, `private_ranges` por defecto), y
	# el comparador `client_ip` del fragmento común usa la IP real del cliente. `trusted_proxies_strict`
	# lee X-Forwarded-For de derecha a izquierda (la primera IP que no es de confianza), de modo que un
	# cliente no puede colar una IP privada al principio de la cabecera.
	# SU PROXY DEBE enviar X-Forwarded-For con la IP real del cliente; si no la envía, `client_ip` es
	# la del proxy (privada) y `health` —solo `{"status":"UP"}`, sin detalles— queda visible desde fuera.
	servers {
		trusted_proxies static $TRUSTED_PROXIES
		trusted_proxies_strict
	}
}

# Fragmento `certify_comun` (templates/Caddyfile.comun.inc): actuator, did.json, contextos, logos y
# proxy a Certify. generate-caddy.sh lo inserta aquí, ANTES del bloque de sitio: Caddy exige que un
# fragmento esté definido antes de importarlo.
$CADDY_FRAGMENTO_COMUN

:80 {
	import certify_comun
}
