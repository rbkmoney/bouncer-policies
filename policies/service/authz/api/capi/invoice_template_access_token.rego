package service.authz.api.capi.invoice_template_access_token

# Set of assertions which tell why operation under the input context is allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

import input.capi.op
import input.payment_processing

allowed[why] {
    is_invoice_template_access_token_operation
    invoice_template_matches_token_scope
    why := {
        "code": "invoice_template_access_token_allows_operation",
        "description": "Invoice template access token allows operation on this invoice template"
    }
}

invoice_template_matches_token_scope {
    scope := input.auth.scope[_]
    scope.invoice_template.id == op.invoice_template.id
    scope.party.id == payment_processing.invoice_template.party.id
}

is_invoice_template_access_token_operation
    { op.id == "GetInvoiceTemplateByID" }
    { op.id == "CreateInvoiceWithTemplate" }
    { op.id == "GetInvoicePaymentMethodsByTemplateID" }
