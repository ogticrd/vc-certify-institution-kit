# ---------------------------------------------------------------------------------------------
# Rutas comunes a todos los modos (domain, ip y proxy). generate-caddy.sh lo inserta en el
# Caddyfile de cada modo (variable CADDY_FRAGMENTO_COMUN), antes del bloque de sitio; cada plantilla
# de modo lo usa con `import certify_comun` dentro de su bloque de sitio. Así hay UNA sola copia de
# la lógica de rutas.
#
# Procedencia: forma tomada del Caddyfile del emisor propio (inji-vc/stack/Caddyfile, 4-oct-2026):
# actuator bloqueado, did.json como fichero, /contextos y /logos con no-cache.
#
# Montajes de docker-compose.yml (solo lectura):
#   ./generated/did       -> /srv/did        (did.json corregido; lo escribe generate-did.sh)
#   ./generated/contextos -> /srv/contextos  (contexto JSON-LD propio; generate-context.sh)
#   ./generated/logos     -> /srv/logos      (logo PNG de la institución; generate-logo.sh)
# Se montan las tres carpetas por separado y NO generated/ entera: ahí vive .env.runtime (secretos).
# ---------------------------------------------------------------------------------------------
(certify_comun) {
	# El actuator NO se publica (R9). Solo `health`, y solo desde rangos privados (la red de Docker
	# y localhost); desde internet es 404, como todo lo demás del actuator. Un comodín en MEDIO de la
	# ruta no casa en Caddy: las rutas van explícitas. Defensa en profundidad: Certify además solo
	# expone `health` (T4).
	# `client_ip` y no `remote_ip`: en domain e ip no hay proxies de confianza y es lo mismo que
	# remote_ip; en proxy (T5) la IP de conexión es siempre la del proxy ajeno (privada), y client_ip
	# usa la IP real del cliente según trusted_proxies del Caddyfile de ese modo.
	handle /v1/certify/actuator/health {
		@interno client_ip private_ranges
		handle @interno {
			reverse_proxy certify:8090
		}
		handle {
			respond 404
		}
	}
	handle /v1/certify/actuator* {
		respond 404
	}

	# `handle` y no `route`: con el `handle` final (404) del fragmento, una `route` quedaría detrás de él
	# (Caddy ordena las directivas: handle, handle_path, route) y nunca se alcanzaría.
	handle /.well-known/openid-credential-issuer {
		rewrite * /v1/certify/.well-known/openid-credential-issuer
		reverse_proxy certify:8090
	}

	# DID: si existe el fichero corregido (generate-did.sh, que corre cuando Certify ya está UP) se
	# sirve ese, con no-cache; si no existe todavía, se reescribe al DID de Certify (sin corregir:
	# assertionMethod con el DID pelado) para que el arranque no quede roto.
	handle /.well-known/did.json {
		@corregido file {
			root /srv/did
			try_files /did.json
		}
		handle @corregido {
			root * /srv/did
			rewrite * /did.json
			header Cache-Control "no-cache"
			header Content-Type "application/json"
			file_server
		}
		handle {
			rewrite * /v1/certify/.well-known/did.json
			reverse_proxy certify:8090
		}
	}

	# El @context propio de la credencial, que la firma necesita poder descargar. Con no-cache el
	# cliente guarda su copia pero la revalida siempre (304 si no cambió); sin él, un verificador
	# puede seguir usando un contexto viejo en caché durante un tiempo que calcula él.
	# `handle` + `uri strip_prefix` en lugar de `handle_path` (es exactamente lo mismo): así todas las rutas
	# son la misma directiva y el `handle` final sin matcher queda de verdad el último.
	handle /contextos/* {
		uri strip_prefix /contextos
		root * /srv/contextos
		header Cache-Control "no-cache"
		header Content-Type "application/ld+json"
		file_server
	}

	# El logo de la credencial, referenciado desde su bloque `display`.
	handle /logos/* {
		uri strip_prefix /logos
		root * /srv/logos
		header Cache-Control "no-cache"
		header Content-Type "image/png"
		file_server
	}

	# --- /v1/certify/*: LISTA BLANCA (K8) --------------------------------------------------------------
	# Antes se publicaba `handle /v1/certify/* { reverse_proxy … }` entero, y con él la fábrica de
	# credenciales (flujo de código pre-autorizado: emite una credencial completa SIN ciudadano),
	# `credential-configurations` (POST/PUT/DELETE reescriben la plantilla, el contexto y el DID de la
	# credencial), la revocación (`credentials/status`) y `system-info` (certificados). Todo eso lo
	# permitía `ignore-auth-urls` de Certify. Ahora solo pasa a Certify lo que la cartera y los
	# verificadores usan; lo demás es 404 EXPLÍCITO (y el comodín `/v1/certify/*` también). Procedencia de la
	# regla: inji-vc/stack/Caddyfile («La FÁBRICA DE CREDENCIALES, cerrada a internet»). Un comodín EN
	# MEDIO de la ruta no casa en Caddy: las rutas van explícitas, sin `/v1/*/algo`.
	#
	# Permitidas:
	#  - metadata del emisor, DID y JWKS de Certify (la metadata también cuelga de la raíz, arriba);
	#  - POST /issuance/credential: el endpoint de emisión, que valida el token del ciudadano;
	#  - GET /credentials/status-list/*: la lista de estado pública (Certify la sirve ahí si la credencial
	#    lleva credentialStatus; `credential_status_purpose` está activo en el SQL);
	#  - GET /rendering-template/*: la plantilla de presentación (pública, solo lectura).
	handle /v1/certify/.well-known/openid-credential-issuer {
		reverse_proxy certify:8090
	}
	handle /v1/certify/.well-known/did.json {
		reverse_proxy certify:8090
	}
	handle /v1/certify/.well-known/jwks.json {
		reverse_proxy certify:8090
	}
	handle /v1/certify/issuance/credential {
		@post method POST
		handle @post {
			reverse_proxy certify:8090
		}
		handle {
			respond 404
		}
	}
	handle /v1/certify/credentials/status-list/* {
		@lectura method GET
		handle @lectura {
			reverse_proxy certify:8090
		}
		handle {
			respond 404
		}
	}
	handle /v1/certify/rendering-template/* {
		@lectura method GET OPTIONS
		handle @lectura {
			reverse_proxy certify:8090
		}
		handle {
			respond 404
		}
	}

	# Cerradas, una a una (el 404 es explícito aunque el comodín de abajo ya las cubra: si alguien
	# añade una regla permisiva por error, estas siguen cerrando lo peligroso).
	#  - la FÁBRICA DE CREDENCIALES: oferta, canje del código y token pre-autorizados;
	handle /v1/certify/pre-authorized-data* {
		respond 404
	}
	handle /v1/certify/credential-offer-data* {
		respond 404
	}
	handle /v1/certify/oauth* {
		respond 404
	}
	#  - la configuración de la credencial (plantilla, contexto, DID) y la revocación;
	handle /v1/certify/credential-configurations* {
		respond 404
	}
	handle /v1/certify/credentials/status {
		respond 404
	}
	handle /v1/certify/credentials/v2/* {
		respond 404
	}
	#  - certificados, libro de emisiones, documentación de la API y lo demás de la emisión (vd11/vd12…).
	handle /v1/certify/system-info* {
		respond 404
	}
	handle /v1/certify/ledger-search* {
		respond 404
	}
	handle /v1/certify/v2/* {
		respond 404
	}
	handle /v1/certify/swagger-ui* {
		respond 404
	}
	handle /v1/certify/v3/api-docs* {
		respond 404
	}
	handle /v1/certify/issuance/* {
		respond 404
	}
	# Y todo lo demás bajo /v1/certify/ (incluidas rutas inventadas): 404.
	handle /v1/certify/* {
		respond 404
	}

	# Lo que no está listado: 404 explícito y no el 200 vacío que Caddy da por defecto (un balanceador lo leería
	# como «sano»). Para sondear el servicio use /.well-known/openid-credential-issuer. Tiene que ser el
	# ÚLTIMO `handle` y de la misma directiva que los demás (por eso no hay `route` ni `handle_path` arriba).
	handle {
		respond 404
	}
}
