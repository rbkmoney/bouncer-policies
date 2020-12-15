package service.authz.api.capi.invoice_template_access_token

# Set of assertions which tell why operation under the input context is allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

import input.capi.op

allowed[why] {
    operation_allowed
    invoice_template_matches_token_scope
    why := {
        "code": "invoice_template_access_token_allows_operation",
        "description": "Invoice template access token allows operation on this invoice template"
    }
}

invoice_template_matches_token_scope {
    scope := input.auth.scope[_]
    scope.party.id == op.party.id
    scope.invoice_template.id == op.invoice_template.id
}

operation_allowed
    { op.id == "GetInvoiceTemplateByID" }
    { op.id == "CreateInvoiceWithTemplate" }
    { op.id == "GetInvoicePaymentMethodsByTemplateID" }
