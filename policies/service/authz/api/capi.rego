package service.authz.api.capi

import data.service.authz.api.capi.invoice_access_token
import data.service.authz.api.capi.customer_access_token
import data.service.authz.api.capi.invoice_template_access_token
import data.service.authz.api.user
import data.service.authz.access

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
    forbidden_session_token_operation
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
    has_access
    session_token_allowed[why]
}

allowed[why] {
    input.auth.method == "SessionToken"
    is_session_token_operation
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

session_token_allowed[why] {
    user.is_owner(op.party.id)
    why := {
        "code": "org_ownership_allows_operation",
        "description": "User is owner of organization that is subject of this operation"
    }
}

session_token_allowed[why] {
    user_role_id := user.roles_by_operation(op.party.id, api_name, op.id)[_].id
    why := {
        "code": "org_role_allows_operation",
        "description": sprintf("User has role that permits this operation: %v", [user_role_id])
    }
}

##

has_access {
    # We assume that the user has no access for any operation not explicitly listed in the "access" document.
    # Thus any new operation won't be silently allowed.
    access_by_operation[_]
    not missing_access
}

missing_access {
    entity := access_by_operation[_]
    not has_entity_access(entity)
}

access_by_operation[entity] {
    access[api_name][entity].operations[_] == op.id
}

has_entity_access("party") {
    op.party.id
    has_party_access(op.party.id)
}
has_entity_access("shop") {
    op.shop.id
    has_shop_access(op.shop.id, op.party.id)
}
has_entity_access("invoice") {
    op.invoice.id
    has_invoice_access(op.invoice.id)
}
has_entity_access("invoice_template") {
    op.invoice_template.id
    has_invoice_template_access(op.invoice_template.id)
}
has_entity_access("customer") {
    op.customer.id
    has_customer_access(op.customer.id)
}

has_party_access(id) {
    _ := user.org_by_party(id)
    true
}

has_shop_access(id, party_id) {
    roles := user.roles_by_operation(party_id, api_name, op.id)
    role := roles[_]
    user_role_has_shop_access(id, role)
}

has_shop_access(id, party_id) {
    user.is_owner(party_id)
}

user_role_has_shop_access(shop_id, role) {
    role.scope.shop
    shop_id == role.scope.shop.id
}
user_role_has_shop_access(shop_id, role) {
    not role.scope
}

has_invoice_access(id) {
    invoice := payment_processing.invoice
    invoice.id == id
    has_party_access(invoice.party.id)
    has_shop_access(invoice.shop.id, invoice.party.id)
}

has_invoice_template_access(id) {
    invoice_template := payment_processing.invoice_template
    invoice_template.id == id
    has_party_access(invoice_template.party.id)
    has_shop_access(invoice_template.shop.id, invoice_template.party.id)
}

has_customer_access(id) {
    customer := payment_processing.customer
    customer.id == id
    has_party_access(customer.party.id)
    has_shop_access(customer.shop.id, customer.party.id)
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

forbidden_session_token_operation
    { op.id == "CreatePaymentResource" }
