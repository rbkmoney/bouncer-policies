package test.service.authz.api

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_no_warnings {
    count(api.warnings) == 0
}

test_blacklist_warnings {
    result := api.warnings with data.service.authz.blacklists as {}
    result[_]
}

test_whitelist_warnings {
    result := api.warnings with data.service.authz.whitelists as {}
    result[_]
}

test_empty_context_forbidden {
    result := api.assertions with input as {}
    result.forbidden[_].code == "auth_required"
}

test_token_blacklisted_local_ip {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_local,
        context.session_token_valid,
        context.op_capi_create_invoice
    ])
    result.forbidden[_].code == "ip_range_blacklisted"
}

test_token_blacklisted_local_ipv6 {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_local_ipv6,
        context.session_token_valid,
        context.op_capi_create_invoice
    ])
    result.forbidden[_].code == "ip_range_blacklisted"
}

test_session_token_missing_id_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.session_token_missing_id,
        context.op_capi_create_invoice
    ])
    result.forbidden[_].code == "auth_token_missing_id"
}

test_api_token_missing_id_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_missing_id,
        context.op_capi_create_invoice
    ])
    result.forbidden[_].code == "auth_token_missing_id"
}

test_token_w_empty_id_blacklisted {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.session_token_empty_id,
        context.op_capi_create_invoice
    ])
    result.forbidden[_].code == "auth_token_blacklisted"
}

test_session_token_no_expiration_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.session_token_no_expiration,
        context.op_capi_create_invoice
    ])
    result.forbidden[_].code == "auth_no_token_expiration"
}
