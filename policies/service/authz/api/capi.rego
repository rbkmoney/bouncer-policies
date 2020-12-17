package service.authz.api.capi

import data.service.authz.api.capi.invoice_access_token
import data.service.authz.api.capi.customer_access_token
import data.service.authz.api.capi.invoice_template_access_token
import data.service.authz.api.utils

import input.capi.op
import input.payment_processing

api_name := "CommonAPI"

# Set of assertions which tell why operation under the input context is allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

allowed[why] {
    input.auth.method == "SessionToken"
    utils.user_is_owner with input.abstract_party_id as op.party.id
    input_matches_invoicing_context
    why := {
        "code": "org_ownership_allows_operation",
        "description": "User is owner of organization that is subject of this operation"
    }
}

allowed[why] {
    input.auth.method == "SessionToken"
    user_role_id := utils.user_roles_by_operation[_].id
        with input.abstract_party_id as op.party.id
        with input.abstract_op_id as op.id
        with input.abstract_api_name as api_name
    input_matches_invoicing_context
    why := {
        "code": "org_role_allows_operation",
        "description": sprintf("User has role that permits this operation: %v", [user_role_id])
    }
}

allowed[why] {
    input.auth.method == "SessionToken"
    operation_allowed
    input_matches_invoicing_context
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows this operation"
    }
}

allowed[why] {
    input.auth.method == "InvoiceAccessToken"
    invoice_access_token.allowed[why]
}

allowed[why] {
    input.auth.method == "CustomerAccessToken"
    customer_access_token.allowed[why]
}

allowed[why] {
    input.auth.method == "InvoiceTemplateAccessToken"
    invoice_template_access_token.allowed[why]
}

matching_shop {
    op.shop.id
    op.shop.id == input.abstract_shop_id
}

matching_invoice {
    op.invoice.id
    op.invoice.id == payment_processing.invoice.id
    op.party.id == payment_processing.invoice.party.id
    matching_shop with input.abstract_shop_id as payment_processing.invoice.shop.id
}

matching_invoice {
    not op.invoice.id
}

matching_payment {
    op.payment.id
    matching_invoice
    op.payment.id == payment_processing.invoice.payments[_].id
}

matching_payment {
    not op.payment.id
}

matching_refund {
    op.refund.id
    matching_payment
    op.payment.id == payment_processing.invoice.payments[i].id
    op.refund.id == payment_processing.invoice.payments[i].refunds[_].id
}

matching_refund {
    not op.refund.id
}

matching_invoice_template {
    op.invoice_template.id
    op.invoice_template.id == payment_processing.invoice_template.id
    op.party.id == payment_processing.invoice_template.party.id
    matching_shop with input.abstract_shop_id as payment_processing.invoice_template.shop.id
}

matching_invoice_template {
    not op.invoice_template.id
}

matching_customer {
    op.customer.id
    op.customer.id == payment_processing.customer.id
    op.party.id == payment_processing.customer.party.id
    matching_shop with input.abstract_shop_id as payment_processing.customer.shop.id
}

matching_customer {
    not op.customer.id
}

matching_binding {
    op.binding.id
    matching_customer
    op.binding.id == payment_processing.customer.bindings[_].id
}

matching_binding {
    not op.binding.id
}

input_matches_invoicing_context {
    matching_invoice
    matching_payment
    matching_refund
    matching_invoice_template
    matching_customer
    matching_binding
}

operation_allowed
    { op.id == "GetAccountByID" }
    { op.id == "GetCategories" }
    { op.id == "GetCategoryByRef" }
    { op.id == "GetLocationsNames" }
    { op.id == "GetPaymentInstitutions" }
    { op.id == "GetPaymentInstitutionByRef" }
    { op.id == "GetPaymentInstitutionPaymentTerms" }
    { op.id == "GetPaymentInstitutionPayoutMethods" }
    { op.id == "GetPaymentInstitutionPayoutSchedules" }
    { op.id == "GetScheduleByRef" }
