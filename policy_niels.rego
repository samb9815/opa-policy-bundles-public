package lightbulbs

import rego.v1

default allow_NIELS = false

######################################################
#####     Substitute NAME for your own name      #####
######################################################
allow if {
	correct_path
	"policy", "NIELS" in input.uri_args
	print("NIELS's policy is used")
	jwt.is_valid
	allow_NIELS #To be defined in your own rego-file
}
######################################################

allow_NIELS if {
  input.method == "POST"
  print("Allowed because of POST")
}
