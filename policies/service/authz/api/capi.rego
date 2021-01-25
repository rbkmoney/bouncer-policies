package service.authz.api.capi

import data.service.authz.api.capi.invoice_access_token
import data.service.authz.api.capi.customer_access_token
import data.service.authz.api.capi.invoice_template_access_token
import data.service.authz.api.user
import data.service.authz.access

import input.capi.op
import input.payment_processing
import input.payouts
import input.webhooks
import input.reports

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
    # NOTE
    # We assume that the user has no access for any operation not explicitly listed in the "access" document.
    # Thus any new operation won't be silently allowed.
    access_by_operation.mandatory[_]
    not missing_mandatory_access
    not missing_discretionary_access
}

missing_mandatory_access {
    entity := access_by_operation.mandatory[_]
    not has_entity_access(entity)
}

missing_discretionary_access {
    entity := access_by_operation.discretionary[_]
    op_entity_specified(entity)
    not has_entity_access(entity)
}

access_by_operation := {
    requirement: names |
        entities := access.api[api_name][requirement]
        names := {
            name |
                entity := entities[name]
                entity.operations[_] == op.id
        }
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
has_entity_access("report") {
    op.report.id
    has_report_access(op.report.id)
}
has_entity_access("file") {
    op.file.id
    has_file_access(op.file.id)
}
has_entity_access("payout") {
    op.payout.id
    has_payout_access(op.payout.id)
}
has_entity_access("webhook") {
    op.webhook.id
    has_webhook_access(op.webhook.id)
}

op_entity_specified("party") {
    op.party.id
}
op_entity_specified("shop") {
    op.shop.id
}
op_entity_specified("invoice") {
    op.invoice.id
}
op_entity_specified("invoice_template") {
    op.invoice_template.id
}
op_entity_specified("customer") {
    op.customer.id
}
op_entity_specified("report") {
    op.report.id
}
op_entity_specified("file") {
    op.file.id
}
op_entity_specified("webhook") {
    op.webhook.id
}
op_entity_specified("payout") {
    op.payout.id
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

has_report_access(id) {
    report := reports.report
    report.id == id
    has_party_access(report.party.id)
    has_shop_access(report.shop.id, report.party.id)
}

has_file_access(id) {
    report := reports.report
    report.files[_].id == id
    has_report_access(report.id)
}

has_payout_access(id) {
    payout := payouts.payout
    payout.id == id
    has_party_access(payout.party.id)
    has_shop_access(payout.shop.id, payout.party.id)
}

has_webhook_access(id) {
    webhook := webhooks.webhook
    webhook.id == id
    has_party_access(webhook.party.id)
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