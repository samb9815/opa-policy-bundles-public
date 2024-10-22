package lightbulbs

default allow_model = false

allow_model if {
  input.request.method == "POST"
}

allow_model if {
  input.request.method == "PUT"
  input.body_args.status == "on"
  
  some r in claims.role
  r == "lucifer"
  to_number(claims.age) >= 16
}
