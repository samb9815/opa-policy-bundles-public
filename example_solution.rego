package lightbulbs

import rego.v1

default allow_model = false

allow_model if {
  input.method == "POST"
  print("Allowed because of POST")
}

allow_model if {
  input.method == "PUT"
  input.body_args.status == "on"
  
  some r in claims.role
  print("Claims:", claims)
  r == "lucifer"
  print("Valid role")

  to_number(claims.age) >= 16
  print("Valid age")

  is_owner
  print("Valid owner")
}

allow_model if {
  input.method == "PUT"
  input.body_args.status == "off"
  
  some r in claims.role
  r == "snuffer"
  print("Valid role")

  is_owner
  print("Valid owner")
}

is_owner if {
  not is_null(input.path[1])
  owner := get_owner(input.path[1])
  owner == input.headers["x-user-sub"]
}
