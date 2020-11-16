package service.authz.api.binapi

# Set of assertions which tell why operation under the input context is allowed.
# When the set is empty operation is not explicitly allowed.
# Each element must be a 2-item array of the following form:
# ```
# ["code", "description"]
# ```

import input.binapi.op

allowed[why] {
    operation_allowed
    bin_lookup_allowed
    op.id == "LookupCardInfo"
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows this operation"
    }
}

bin_lookup_allowed
    { input.auth.bin_lookup_allowed == true}

operation_allowed
    { op.id == "LookupCardInfo" }
