package test.service.authz.api.capi

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures

test_get_refunds_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_get_refunds,
        fixtures.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
    result.allowed[_].code == "org_role_allows_operation"
}

test_fulfill_invoice_forbidden_context_mismatch {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_fulfill_invoice,
        fixtures.payproc_invoice_another_shop
    ])
}

test_forbidden_create_payment_resource {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_create_payment_resource
    ])
    result.forbidden
}

test_forbidden_invoicing_context_no_shop {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_fulfill_invoice,
        fixtures.payproc_invoice_no_shop_context
    ])
}

test_forbidden_invoicing_context_no_party {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_fulfill_invoice,
        fixtures.payproc_invoice_no_party_context
    ])
}

test_create_invoice_access_token_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_create_invoice_access_token,
        fixtures.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_insufficient_input_forbidden {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_get_refund_by_id,
        fixtures.payproc_insufficient_input
    ])
}

test_op_insufficient_input_forbidden {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_create_payment_insufficient_input,
        fixtures.payproc_invoice
    ])
}

test_get_refund_by_id_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_get_refund_by_id,
        fixtures.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_rescind_invoice_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_rescind_invoice,
        fixtures.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

capi_public_operation_ctx = util.deepmerge([
    fixtures.env_default,
    fixtures.requester_default,
    fixtures.user_default,
    fixtures.session_token_valid,
    fixtures.op_capi_empty
])

test_capi_allowed_by_session_token_1 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetAccountByID"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_2 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetCategories"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_3 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetCategoryByRef"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_4 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetLocationsNames"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_5 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetPaymentInstitutions"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_6 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetPaymentInstitutionByRef"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_7 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetPaymentInstitutionPaymentTerms"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_8 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetPaymentInstitutionPayoutMethods"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_9 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetPaymentInstitutionPayoutSchedules"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_10 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetScheduleByRef"}
    not result.forbidden
    count(result.allowed) == 1
}

test_update_invoice_template_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_update_invoice_template,
        fixtures.payproc_invoice_template
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_create_binding_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_create_binding,
        fixtures.payproc_customer
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_get_binding_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_get_binding,
        fixtures.payproc_customer
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_session_token_and_owner_allowed {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_owner,
        fixtures.session_token_valid,
        fixtures.op_capi_get_binding,
        fixtures.payproc_customer
    ])
}

test_create_webhook_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_create_webhook
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_search_invoices_allowed {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_search_invoices
    ])
}

test_search_specific_invoice_allowed {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_search_specific_invoice,
        fixtures.payproc_invoice
    ])
}

test_search_specific_payout_allowed {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator_shop,
        fixtures.session_token_valid,
        fixtures.op_capi_search_specific_payout,
        fixtures.payouts_payout
    ])
}

test_search_foreign_invoice_forbidden {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_search_specific_invoice,
        fixtures.payproc_invoice_foreign
    ])
}

test_search_another_party_invoice_allowed_owner_another_party {
    # NOTE
    # This is kinda unusual: search within `PARTY` for specific invoice owned by
    # `PARTY_2`. It's **allowed** because the user has, independently, an access
    # to searches within `PARTY` **and** an access to invoice owned by `PARTY_2`,
    # even though such request as a whole doesn't make sense.
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator_owner_another_party,
        fixtures.session_token_valid,
        fixtures.op_capi_search_specific_invoice,
        fixtures.payproc_invoice_foreign
    ])
}

test_search_another_party_invoice_forbidden_manager_another_party {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator_manager_another_party,
        fixtures.session_token_valid,
        fixtures.op_capi_search_specific_invoice,
        fixtures.payproc_invoice_foreign
    ])
}

test_delete_webhook_allowed_administrator {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_delete_webhook,
        fixtures.webhooks_webhook
    ])
}

test_delete_webhook_allowed_owner {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator_owner_another_party,
        fixtures.session_token_valid,
        fixtures.op_capi_delete_webhook,
        fixtures.webhooks_webhook_foreign
    ])
}

test_delete_foreign_webhook_forbidden {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_delete_webhook,
        fixtures.webhooks_webhook_foreign
    ])
}

test_delete_webhook_forbidden_default_user {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_delete_webhook,
        fixtures.webhooks_webhook
    ])
}

test_download_file_allowed_administrator {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator_shop,
        fixtures.session_token_valid,
        fixtures.op_capi_download_file,
        fixtures.reports_report
    ])
}

test_download_missing_file_forbidden {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator_shop,
        fixtures.session_token_valid,
        fixtures.op_capi_download_missing_file,
        fixtures.reports_report
    ])
}

test_download_file_invalid_shop_forbidden {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator_shop,
        fixtures.session_token_valid,
        fixtures.op_capi_download_file_invalid_shop,
        fixtures.reports_report
    ])
}

test_download_file_invalid_party_forbidden {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator_owner_another_party,
        fixtures.session_token_valid,
        fixtures.op_capi_download_file_invalid_party,
        fixtures.reports_report
    ])
}

test_unknown_operation_forbidden_no_access {
    util.is_forbidden with input as capi_public_operation_ctx with input.capi.op as {"id" : "NewOperation"}
}
