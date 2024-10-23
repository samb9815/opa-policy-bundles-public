package lightbulbs

import rego.v1

default allow = false

allow if {
	correct_path #Defined in the helper function section below
	print("The path is correct")

	"policy", "michael" in input.body_args
	print("Michael's policy is used")

	jwt.is_valid #Defined in the helper function section below
	print("The JWT is valid")

	allow_michael #Defined in policy_michael.rego
	print("Access is allowed per Michael's policy")
}


######################################################
#####     Copy the following piece of code       #####
#####     Substitute NAME for your own name      #####
######################################################
allow if {
	correct_path
	"policy", "NAME" in input.body_args
	print("NAME's policy is used")
	jwt.is_valid
	allow_NAME #To be defined in your own rego-file
}
######################################################

















######################################################
##### The following piece of code is active via  #####
##### a hidden file but is left here for clarity #####
######################################################
#allow if {
#	correct_path #Defined in the helper function section below
#	print("The path is correct")

#	default_policy #Defined underneath this rule
#	print("The default policy is used")
	
#	jwt.is_valid #Defined in the helper function section below
#	print("The JWT is valid")

#	allow_default #Defined in the (for now hidden) file policy_solution.rego
#	print("Access is allowed per the default/solution policy")
#}

#default_policy if {
#	"policy", "default" in input.body_args
#}

#default_policy if {
#	not input.body_args.policy
#}

######################################################
#####   Below this point are helper functions    #####
######################################################
iss := "https://dev-mbt7ieoqd8u1bjwl.us.auth0.com"
aud := "https://kong.portasecura.com:8443"

correct_path if {
	input.path[0] == "lightbulbs-opa"
}

jwt := {"claims": payload, "is_valid": valid} if {
#Decodes the JWT bearer token and verifies its signature
	jwks := jwks_request(concat("",[iss,"/.well-known/jwks.json"])).raw_body
	constraints := {
	"cert": jwks,
	"iss": concat("",[iss,"/"]),
	"aud": aud
	}
	[valid,_,payload] := io.jwt.decode_verify(bearer_token,constraints)
}

#Extracts the claims that were contained in the JWT token and stores them in a dedicated variable
claims := jwt.claims

jwks_request(url) := http.send({
#Constructs an HTTP request, with the intent of fetching the JWKS (JSON Web Key Set) from Auth0 for JWT signature verification
	"url": url,
	"method": "GET",
	"force_cache": true,
	"force_cache_duration_seconds": 60 
})

get_lightbulb(id) := http.send({
#Fetches information on a lightbulb at the API server, the Policy Information Point (PIP)
	"url": concat("",["https://api.portasecura.com/lightbulbs/",id,"?"]),
	"method": "GET",
	"force_cache": true,
	"force_cache_duration_seconds": 60 
})

get_owner(id) := owner if {
#Extracts the owner out of all the lightbulb information
	lightbulb := get_lightbulb(id).body
	owner := lightbulb.owner
}

bearer_token := t if {
#Extracts the JWT/bearer token from the request's authorization header and removes the initial "Bearer " part.
#If no bearer token is provided, the `bearer_token` value is undefined.
	v := input.headers.authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}
