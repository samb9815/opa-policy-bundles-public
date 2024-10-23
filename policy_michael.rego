package lightbulbs

import rego.v1

default allow_michael = false

allow if {
	correct_path #Defined in the helper function section below
	print("The path is correct")

	"policy", "michael" in input.uri_args
	print("Michael's policy is used")

	jwt.is_valid #Defined in the helper function section below
	print("The JWT is valid")

	allow_michael #Defined in policy_michael.rego
	print("Access is allowed per Michael's policy")
}

allow_michael if {
  input.method == "POST"
  print("Allowed because of POST")
}
