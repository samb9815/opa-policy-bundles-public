package lightbulbs

import rego.v1

default allow_NAME = false

allow_NAME if {
  input.method == "POST"
  print("Allowed because of POST")
}
