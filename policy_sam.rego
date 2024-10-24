package lightbulbs

import rego.v1

default allow_sam = true

allow if {
	correct_path
	Print ("Dit is correct")

	"policy", "sam" in input.uri_args
	print("sam's policy is used")

	jwt.is_valid
	print ("The JWT is valid")

	allow_sam
}

allow_sam if {
  input.method == "POST"
  print("Allowed because of POST")
}
