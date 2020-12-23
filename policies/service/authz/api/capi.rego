package service.authz.api.capi

import data.service.authz.api.capi.invoice_access_token
import data.service.authz.api.capi.customer_access_token
import data.service.authz.api.capi.invoice_template_access_token
import data.service.authz.api.utils

import input.capi.op
import input.payment_processing

api_name := "CommonAPI"

# Set of assertions which tell why operation under the input context is forbidden.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

forbidden[why] {
    input.auth.method == "SessionToken"
    not_session_token_operation
    why := {
        "code": "operation_not_allowed_for_session_token",
        "description": "Operation not allowed for session token"
    }
}

# Set of assertions which tell why operation under the input context is allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

allowed[why] {
    input.auth.method == "SessionToken"
    session_token_allowed[why]
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

session_token_allowed[why] {
    utils.user_is_owner(op.party.id)
    input_matches_payment_processing_context
    why := {
        "code": "org_ownership_allows_operation",
        "description": "User is owner of organization that is subject of this operation"
    }
}

session_token_allowed[why] {
    utils.user_is_administrator(op.party.id)
    input_matches_payment_processing_context
    why := {
        "code": "administrator_role_allows_operation",
        "description": "User is administrator of organization that is subject of this operation"
    }
}

session_token_allowed[why] {
    not utils.user_is_administrator(op.party.id)
    user_role_id := utils.user_roles_by_operation(op.party.id, api_name, op.id)[_].id
    input_matches_payment_processing_context
    why := {
        "code": "org_role_allows_operation",
        "description": sprintf("User has role that permits this operation: %v", [user_role_id])
    }
}

session_token_allowed[why] {
    is_session_token_operation
    input_matches_payment_processing_context
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows this operation"
    }
}

##

match_shop {
    op.shop.id
    user_roles := utils.user_roles_by_operation(op.party.id, api_name, op.id)
    op.shop.id == user_roles[_].scope.shop.id
}

match_invoice {
    op.invoice.id
    match_shop
    op.invoice.id == payment_processing.invoice.id
    op.party.id == payment_processing.invoice.party.id
    validate_shop(payment_processing.invoice.shop.id)
}

match_payment {
    op.payment.id
    match_invoice
    op.payment.id == payment_processing.invoice.payments[_].id
}

match_refund {
    op.refund.id
    match_payment
    op.payment.id == payment_processing.invoice.payments[i].id
    op.refund.id == payment_processing.invoice.payments[i].refunds[_].id
}

match_invoice_template {
    op.invoice_template.id
    match_shop
    op.invoice_template.id == payment_processing.invoice_template.id
    op.party.id == payment_processing.invoice_template.party.id
    validate_shop(payment_processing.invoice_template.shop.id)
}

match_customer {
    op.customer.id
    match_shop
    op.customer.id == payment_processing.customer.id
    op.party.id == payment_processing.customer.party.id
    validate_shop(payment_processing.customer.shop.id)
}

match_binding {
    op.binding.id
    match_customer
    op.binding.id == payment_processing.customer.bindings[_].id
}

##

matching_shop {
    match_shop
}

matching_shop {
    not op.shop.id
    not need_access("shop")
}

matching_invoice {
    match_invoice
}

matching_invoice {
    not op.invoice.id
    not need_access("invoice")
}

matching_payment {
    match_payment
}

matching_payment {
    not op.payment.id
    not need_access("payment")
}

matching_refund {
    match_refund
}

matching_refund {
    not op.refund.id
    not need_access("refund")
}

matching_invoice_template {
    match_invoice_template
}

matching_invoice_template {
    not op.invoice_template.id
    not need_access("invoice_template")
}

matching_customer {
    match_customer
}

matching_customer {
    not op.customer.id
    not need_access("customer")
}

matching_binding {
    match_binding
}

matching_binding {
    not op.binding.id
    not need_access("binding")
}

input_matches_payment_processing_context {
    matching_shop
    matching_invoice
    matching_payment
    matching_refund
    matching_invoice_template
    matching_customer
    matching_binding
}

validate_shop(shop_id) {
    op.shop.id
    op.shop.id == shop_id
}

need_access(access_type) {
    utils.need_access(api_name, access_type, op.id)
}

is_session_token_operation
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

not_session_token_operation
    { op.id == "CreatePaymentResource" }
