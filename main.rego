package lightbulbs

import rego.v1

default allow = false

allow if {
	correct_path
	print("The path is correct")

	default_policy
	print("The default policy is used")
	
	jwt.is_valid
	print("The JWT is valid")

	allow_default
	print("Access is allowed per the default/solution policy")
}

default_policy if {
	"policy", "default" in input.body_args
}

default_policy if {
	not input.body_args.policy
}

allow if {
	correct_path
	"policy", "Michael" in input.body_args
	print("Michael's policy is used)
	jwt.is_valid
	allow_Michael
}

allow if {
	correct_path
	"policy", "NAME" in input.body_args
	print("NAME's policy is used")
	jwt.is_valid
	allow_NAME
}

#################################################
##### Below this point are helper functions #####
#################################################
iss := "https://dev-mbt7ieoqd8u1bjwl.us.auth0.com"
aud := "https://kong.portasecura.com:8443"

correct_path if {
	input.path[0] == "lightbulbs-opa"
}

jwt := {"claims": payload, "is_valid": valid} if {
	jwks := jwks_request(concat("",[iss,"/.well-known/jwks.json"])).raw_body
	constraints := {
	"cert": jwks,
	"iss": concat("",[iss,"/"]),
	"aud": aud
	}
	[valid,_,payload] := io.jwt.decode_verify(bearer_token,constraints)
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
	owner := lightbulb.owner
}

bearer_token := t if {
	# Bearer tokens are contained inside of the HTTP Authorization header. This rule
	# parses the header and extracts the Bearer token value. If no Bearer token is
	# provided, the `bearer_token` value is undefined.
	v := input.headers.authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}
