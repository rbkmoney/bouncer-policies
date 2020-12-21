package service.authz.api.capi.invoice_access_token

# Set of assertions which tell why operation under the input context is allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

import input.capi.op

allowed[why] {
    op.id == "CreatePaymentResource"
    party_matches_token_scope
    why := {
        "code": "invoice_access_token_allows_tokenization",
        "description": "Invoice access token allows payment resource tokenization"
    }
}

allowed[why] {
    is_invoice_access_token_operation
    invoice_matches_token_scope
    why := {
        "code": "invoice_access_token_allows_operation",
        "description": "Invoice access token allows operation on this invoice"
    }
}

party_matches_token_scope {
    scope := input.auth.scope[_]
    scope.party.id == op.party.id
}

invoice_matches_token_scope {
    scope := input.auth.scope[_]
    scope.party.id == op.party.id
    scope.invoice.id == op.invoice.id
}

is_invoice_access_token_operation
    { op.id == "GetInvoiceByID" }
    { op.id == "GetInvoiceEvents" }
    { op.id == "GetInvoicePaymentMethods" }
    { op.id == "CreatePayment" }
    { op.id == "GetPaymentByID" }
