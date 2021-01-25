package service.authz.api.capi.customer_access_token

# Set of assertions which tell why operation under the input context is allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

import input.capi.op
import input.payment_processing

allowed[why] {
    op.id == "CreatePaymentResource"
    party_matches_token_scope
    why := {
        "code": "customer_access_token_allows_tokenization",
        "description": "Customer access token allows payment resource tokenization"
    }
}

allowed[why] {
    is_customer_access_token_operation
    customer_matches_token_scope
    why := {
        "code": "customeraccess_token_allows_operation",
        "description": "Customer access token allows operation on this customer"
    }
}

party_matches_token_scope {
    scope := input.auth.scope[_]
    scope.party.id == op.party.id
}

customer_matches_token_scope {
    scope := input.auth.scope[_]
    scope.customer.id == op.customer.id
    scope.party.id == payment_processing.customer.party.id
}

is_customer_access_token_operation
    { op.id == "GetCustomerById" }
    { op.id == "CreateBinding" }
    { op.id == "GetBinding" }
    { op.id == "GetCustomerEvents" }
