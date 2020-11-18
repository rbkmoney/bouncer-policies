package service.authz.api.binapi

# Set of assertions which tell why operation under the input context is allowed.
# When the set is empty operation is not explicitly allowed.
# Each element must be a 2-item array of the following form:
# ```
# ["code", "description"]
# ```

import input.binapi.op
import data.service.authz.whitelists

allowed[why] {
    operation_allowed
    bin_lookup_allowed
    op.id == "LookupCardInfo"
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows this operation"
    }
}

warning[why] {
    not whitelists.bin_lookup_allowed_party_ids
    why := "Whitelist 'bin_lookup_allowed_party_ids' is not defined, whitelisting by partyID will NOT WORK."
}

bin_lookup_allowed {
    op.party.id = whitelists.bin_lookup_allowed_party_ids[_]
}

operation_allowed
    { op.id == "LookupCardInfo" }
