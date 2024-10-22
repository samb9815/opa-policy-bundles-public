package lightbulbs

import rego.v1

iss := "https://dev-mbt7ieoqd8u1bjwl.us.auth0.com"
aud := "https://kong.portasecura.com:8443"

default allow = false

allow if {
	print("Path as expected: ", input.path[0] == "lightbulbs-opa")
    input.path[0] == "lightbulbs-opa"
    allow_model
}

allow if {
    input.request.path == "/lightbulbs-opa/1"
    allow_1
}

#################################################
##### Below this point are helper functions #####
#################################################
claims := payload if {
    jwks := jwks_request(concat("",[iss,"/.well-known/jwks.json"])).raw_body
    constraints := {
        "cert": jwks,
        "iss": concat("",[iss,"/"]),
        "aud": aud
    }
    #io.jwt.decode_verify returns a three-element array: 
    #header, signature, payload.
    [_,_,payload] := io.jwt.decode_verify(bearer_token,constraints) 
}

jwks_request(url) := http.send({
    "url": url,
    "method": "GET",
    "force_cache": true,
    "force_cache_duration_seconds": 60 
})

bearer_token := t if {
	# Bearer tokens are contained inside of the HTTP Authorization header. This rule
	# parses the header and extracts the Bearer token value. If no Bearer token is
	# provided, the `bearer_token` value is undefined.
	v := input.headers.authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}
