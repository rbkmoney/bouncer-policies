package test.authz.api

import data.service.authz.api
import data.test.authz.util
import data.test.authz.fixtures

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

test_session_token_valid_when_user_is_owner {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_owner,
        fixtures.session_token_valid,
        fixtures.op_capi_create_invoice
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
    result.allowed[_].code == "user_is_owner"
}

test_session_token_valid_when_user_has_role{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_create_invoice
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
    result.allowed[_].code == "user_has_role"
}

test_session_token_valid_when_user_has_role_with_no_scope{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_with_role_without_scope,
        fixtures.session_token_valid,
        fixtures.op_capi_create_invoice
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
    result.allowed[_].code == "user_has_role"
}

test_session_token_valid_orgmgmt_op{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default_administrator,
        fixtures.session_token_valid,
        fixtures.op_orgmgmt_create_invitation
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
    result.allowed[_].code == "user_has_role"
}
