package test.service.authz.decision

import data.service.authz.judgement
import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context
import data.test.service.authz.fixtures.restrictions

test_judgement {
    result := api.judgement with input as {}
    result.resolution[0] == "forbidden"
    count(result.resolution[1]) > 0
}

test_judgement_forbidden {
    assertions := api.assertions with input as {}
    result := judgement.judge(assertions).resolution
    result[0] == "forbidden"
    count(result[1]) > 0
}

test_judgement_forbidden_1 {
    assertions := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid_party_2,
        context.op_capi_create_payment_resource
    ])
    result := judgement.judge(assertions).resolution
    result[0] == "forbidden"
    count(result[1]) == 0
}

test_judgement_restricted {
    assertions := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_anapi
    ])
    result0 := judgement.judge(assertions)
    result0.restrictions == restrictions.op_anapi_restrictions
    result1 := result0.resolution
    result1[0] == "restricted"
    count(result1[1]) > 0
}

test_judgement_allowed {
    assertions := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_create_payment_resource
    ])
    result := judgement.judge(assertions).resolution
    result[0] == "allowed"
    count(result[1]) > 0
}
