package lightbulbs

import rego.v1

default allow_default = false

allow_default if {
  input.method == "POST"
  print("Allowed because of POST")
}

allow_default if {
  input.method == "GET"
  print("Allowed because of GET")
}

allow_default if {
  input.method == "PUT"
  input.body_args.status == "on"
  
  some r in claims.role
  r == "lucifer"
  print("Valid role")

  to_number(claims.age) >= 16
  print("Valid age")
}

allow_default if {
  input.method == "PUT"
  input.body_args.status == "off"
  
  some r in claims.role
  r == "snuffer"
  print("Valid role")

  is_owner
  print("Valid owner")
}

allow_default if {
  input.method == "DELETE"

  is_owner
  print("Valid owner")
}

is_owner if {
  id := input.path[1]
  not is_null(id)
  owner := get_owner(id)
  owner == input.headers["x-user-sub"]
}

is_owner if {
  some r in claims.role
  r == "lord-of-lumen"
}

is_owner if {
  id := input.path[1]
  not is_null(id)
  is_null(get_owner(id))
}
