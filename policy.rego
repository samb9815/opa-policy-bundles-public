package lightbulbs

import rego.v1

default allow = true

allow if {
    input.request.path == "/lightbulbs-opa/0"
    input.request.method == "POST"
    allow_0
}

allow if {
    input.request.path == "/lightbulbs-opa/1"
    allow_1
}
