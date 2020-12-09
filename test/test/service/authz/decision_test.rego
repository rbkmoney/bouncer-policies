package test.service.authz.decision

import data.service.authz.decision
import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures

test_decision_forbidden {
    assertions := api.assertions with input as {}
    result := decision.decide(assertions)
    result[0] == "forbidden"
    count(result[1]) == 1
}

test_decision_forbidden_1 {
    assertions := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid_party_2,
        fixtures.op_capi_create_payment_resource
    ])
    result := decision.decide(assertions)
    result[0] == "forbidden"
    count(result[1]) == 0
}

test_decision_allowed {
    assertions := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_create_payment_resource
    ])
    result := decision.decide(assertions)
    result[0] == "allowed"
    count(result[1]) > 0
}
