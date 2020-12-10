package test.service.authz.api

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures

test_no_warnings {
    count(api.warnings) == 0
}

test_blacklist_warnings {
    result := api.warnings with data.service.authz.blacklists as {}
    result[_] == "Blacklist 'source_ip_range' is not defined, blacklisting by IP will NOT WORK."
}

test_whitelist_warnings {
    result := api.warnings with data.service.authz.whitelists as {}
    result[_] == "Whitelist 'bin_lookup_allowed_party_ids' is not defined, whitelisting by partyID will NOT WORK."
}

test_empty_context_forbidden {
    result := api.assertions with input as {}
    result.forbidden[_].code == "auth_required"
}

test_token_blacklisted_local_ip {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_local,
        fixtures.session_token_valid,
        fixtures.op_capi_create_invoice
    ])
    result.forbidden[_].code == "ip_range_blacklisted"
}

test_token_blacklisted_local_ipv6 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_local_ipv6,
        fixtures.session_token_valid,
        fixtures.op_capi_create_invoice
    ])
    result.forbidden[_].code == "ip_range_blacklisted"
}
