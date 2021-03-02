package test.service.authz.api.binapi

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_lookup_card_info_allowed {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.session_token_valid,
        context.op_binapi_lookup_card_info
    ]) with data.service.authz.whitelists.binapi_party_ids as {
        "entries": ["PARTY_2"]
    }
    not result.forbidden
    count(result.allowed) == 1
    result.allowed[_].code == "session_token_allows_operation"
}

test_lookup_card_info_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.session_token_valid,
        context.op_binapi_lookup_card_info
    ]) with data.service.authz.whitelists.binapi_party_ids as {
        "entries": ["PARTY_3"]
    }
    not result.forbidden
    not result.allowed
}
