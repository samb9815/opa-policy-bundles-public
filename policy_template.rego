package lightbulbs

import rego.v1

default allow_NAME = false

######################################################
#####     Substitute NAME for your own name      #####
######################################################
allow if {
	correct_path
	"policy", "NAME" in input.uri_args
	print("NAME's policy is used")
	jwt.is_valid
	allow_NAME #To be defined in your own rego-file
}
######################################################

allow_NAME if {
  input.method == "POST"
  print("Allowed because of POST")
}
