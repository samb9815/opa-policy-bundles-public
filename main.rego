package lightbulbs

import rego.v1

iss := "https://dev-mbt7ieoqd8u1bjwl.us.auth0.com"
aud := "https://kong.portasecura.com:8443"

default allow = false

allow if {
	input.path[0] == "lightbulbs-opa"
	jwt.is_valid
	allow_model	
}

allow if {
	input.request.path == "/lightbulbs-opa/1"
	allow_1
}

#################################################
##### Below this point are helper functions #####
#################################################
jwt := {"claims": payload, "is_valid": valid} if {
	jwks := jwks_request(concat("",[iss,"/.well-known/jwks.json"])).raw_body
	constraints := {
	"cert": jwks,
	"iss": concat("",[iss,"/"]),
	"aud": aud
	}
	[valid,_,payload] := io.jwt.decode_verify(bearer_token,constraints)
	valid
}

claims := jwt.claims

jwks_request(url) := http.send({
	"url": url,
	"method": "GET",
	"force_cache": true,
	"force_cache_duration_seconds": 60 
})

get_lightbulb(id) := http.send({
	"url": concat("",["https://api.portasecura.com/lightbulbs/",id,"?"]),
	"method": "GET",
	"force_cache": true,
	"force_cache_duration_seconds": 60 
})

get_owner(id) := owner if {
	lightbulb := get_lightbulb(id).body
	owner := lightbulb.body
	print("Owner: ", owner)
}

bearer_token := t if {
	# Bearer tokens are contained inside of the HTTP Authorization header. This rule
	# parses the header and extracts the Bearer token value. If no Bearer token is
	# provided, the `bearer_token` value is undefined.
	v := input.headers.authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}
