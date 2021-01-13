package test.service.authz.api.binapi

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures

test_lookup_card_info_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.session_token_valid,
        fixtures.op_binapi_lookup_card_info
    ]) with data.service.authz.whitelists.bin_lookup_allowed_party_ids as ["PARTY_2"]
    not result.forbidden
    count(result.allowed) == 1
    result.allowed[_].code == "session_token_allows_operation"
}

test_lookup_card_info_forbidden {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.session_token_valid,
        fixtures.op_binapi_lookup_card_info
    ]) with data.service.authz.whitelists.bin_lookup_allowed_party_ids as ["PARTY_3"]
    not result.forbidden
    not result.allowed
}
