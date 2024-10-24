package lightbulbs

import rego.v1

default allow_opberg = false

######################################################
#####     Substitute NAME for your own name      #####
######################################################
allow if {
	correct_path
	"policy", "opberg" in input.uri_args
	print("Opberg's policy is used")
	jwt.is_valid
	allow_opberg #To be defined in your own rego-file
}
######################################################

allow_opberg if {
  input.method == "POST"
  print("Allowed because of POST")
}

allow_opberg if {
  input.method == "GET"
  print("Allowed because of GET")
}

allow_opberg if {
  input.method == "PUT"
  get_owner(input.path[1]) == jwt.sub
  print("Allowed because of owner and PUT")
}

allow_opberg if {
  input.method == "DELETE"
  get_owner(input.path[1]) == jwt.sub
  print("Allowed because of owner and DELETE")
}
