package lightbulbs

import rego.v1

default allow_dante = false


allow if {
	correct_path #Defined in the helper function section below
	print("The path is correct")

	"policy", "dante" in input.uri_args
	print("Dante's policy is used")

	jwt.is_valid #Defined in the helper function section below
	print("The JWT is valid")

	allow_dante #Defined in policy_michael.rego
	print("Access is allowed per Michael's policy")
}

allow_dante if {
  input.method == "POST"
  print("Allowed because of POST")
}
