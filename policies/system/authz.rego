# Policy defines access control to OPA API itself.
package system.authz

import input.path
import input.method

default allow = false  # Reject requests by default.

allow {
    method == { "GET", "POST" }[_]
    path[0] == "v1"
    path[1] == "data"
    path[2] == "service"
}

allow {
    method == "GET"
    path[0] == "v1"
    path[1] == "policies"
}

allow {
    method == "GET"
    path == {
        ["health"],
        ["metrics"]
    }[_]
}
