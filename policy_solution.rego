package lightbulbs

import rego.v1

default allow_def = false

allow_def if {
#Anyone can create lightbulbs
  input.method == "POST"
  print("Allowed because of POST")  
}

allow_def if {
#Anyone can retrieve lightbulb information
  input.method == "GET"
  print("Allowed because of GET")
}

allow_def if {
#Only lucifers older than 16 years can turn lightbulbs on
  input.method == "PUT"
  input.body_args.status == "on"
  
  some r in claims.role
  r == "lucifer"
  print("Valid role")

  to_number(claims.age) >= 16
  print("Valid age")
}

allow_def if {
#Only snuffers can turn lightbulbs off and only their own
  input.method == "PUT"
  input.body_args.status == "off"
  
  some r in claims.role
  r == "snuffer"
  print("Valid role")

  is_owner
  print("Valid owner")
}

allow_def if {
#Only the owner (and lord-of-lumen) can delete a lightbulb
  input.method == "DELETE"

  is_owner
  print("Valid owner")
}

is_owner if {
#Verifies whether the requester owns the impacted lightbulb
  id := input.path[1]
  not is_null(id)
  owner := get_owner(id)
  owner == input.headers["x-user-sub"]
}

is_owner if {
#For convenience, lords of lumens are also seen as owners -- of any lightbulb
  some r in claims.role
  r == "lord-of-lumen"
}

is_owner if {
#Anyone can act as owner for lightbulbs without owner
  id := input.path[1]
  not is_null(id)
  is_null(get_owner(id))
}
