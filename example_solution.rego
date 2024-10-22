package lightbulbs

import rego.v1

default allow_model = false

allow_model if {
  input.method == "POST"
}

allow_model if {
  input.method == "PUT"
  input.body_args.status == "on"
  
  some r in claims.role
  r == "lucifer"

  to_number(claims.age) >= 16

  is_owner
}

allow_model if {
  input.method == "PUT"
  input.body_args.status == "off"
  
  some r in claims.role
  r == "snuffer"

  is_owner
}

is_owner if {
  not is_null(input.path[1])
  owner := get_owner(input.path[1])
  owner == input.headers["x-user-sub"]
}
