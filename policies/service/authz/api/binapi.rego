package service.authz.api.binapi

import input.binapi.op
import data.service.authz.whitelists

allowed[why] {
    bin_lookup_allowed
    op.id == "LookupCardInfo"
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows this operation"
    }
}

bin_lookup_allowed {
    op.party.id == whitelists.binapi_party_ids.entries[_]
}
