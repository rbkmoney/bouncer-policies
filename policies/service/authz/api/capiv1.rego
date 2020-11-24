package service.authz.api.binapi

import input.capi.op
import input.invoicing

allowed[why] {
    requires_invoicing_context
    input_matches_invoicing_context
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows this operation"
    }
}

allowed[why] {
    operation_allowed
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows this operation"
    }
}

input_matches_invoicing_context {
    op.party.id == invoicing.party.id
    op.shop.id  == invoicing.shop.id
    op.invoice.id == invoicing.invoice.id
    op.payment.id == invoicing.payment.id
    op.refund.id == invoicing.refund.id
}

requires_invoicing_context
    { op.id == "CreateInvoiceAccessToken" }
    { op.id == "FulfillInvoice" }
    { op.id == "RescindInvoice" }
    { op.id == "CancelPayment" }
    { op.id == "CapturePayment" }
    { op.id == "CreateRefund" }
    { op.id == "GetRefunds" }
    { op.id == "GetRefundByID" }

operation_allowed
    { op.id == "CreateInvoice" }
    { op.id == "CreateInvoiceAccessToken" }
    { op.id == "FulfillInvoice" }
    { op.id == "RescindInvoice" }
    { op.id == "CancelPayment" }
    { op.id == "CapturePayment" }
    { op.id == "SearchInvoices" }
    { op.id == "SearchPayments" }
    { op.id == "SearchPayouts" }
    { op.id == "GetPaymentConversionStats" }
    { op.id == "GetPaymentRevenueStats" }
    { op.id == "GetPaymentGeoStats" }
    { op.id == "GetPaymentRateStats" }
    { op.id == "GetPaymentMethodStats" }
    { op.id == "CreateRefund" }
    { op.id == "GetRefunds" }
    { op.id == "GetRefundByID" }
    { op.id == "CreateInvoiceTemplate" }
    { op.id == "GetInvoiceTemplateByID" }
    { op.id == "UpdateInvoiceTemplate" }
    { op.id == "DeleteInvoiceTemplate" }
    { op.id == "CreateInvoiceWithTemplate" }
    { op.id == "ActivateShop" }
    { op.id == "SuspendShop" }
    { op.id == "GetShops" }
    { op.id == "GetShopByID" }
    { op.id == "GetReports" }
    { op.id == "DownloadFile" }
    { op.id == "GetContractByID" }
    { op.id == "GetPayoutTools" }
    { op.id == "GetPayoutToolByID" }
    { op.id == "GetContractAdjustments" }
    { op.id == "GetContractAdjustmentByID" }
    { op.id == "GetAccountByID" }
    { op.id == "GetClaims" }
    { op.id == "GetClaimByID" }
    { op.id == "CreateClaim" }
    { op.id == "RevokeClaimByID" }
    { op.id == "CreateWebhook" }
    { op.id == "GetWebhookByID" }
    { op.id == "DeleteWebhookByID" }
    { op.id == "CreateCustomer" }
    { op.id == "GetCustomerById" }
    { op.id == "DeleteCustomer" }
    { op.id == "CreateCustomerAccessToken" }
    { op.id == "CreateBinding" }
    { op.id == "GetBindings" }
    { op.id == "GetBinding" }
    { op.id == "GetCustomerEvents" }
    { op.id == "SuspendMyParty" }
    { op.id == "ActivateMyParty" }
    { op.id == "GetMyParty" }
    { op.id == "GetWebhooks" }
    { op.id == "GetScheduleByRef" }
    { op.id == "GetCategories" }
    { op.id == "GetCategoryByRef" }
    { op.id == "GetContracts" }
    { op.id == "GetLocationsNames" }
    { op.id == "GetPaymentInstitutions" }
    { op.id == "GetPaymentInstitutionByRef" }
    { op.id == "GetPaymentInstitutionPaymentTerms" }
    { op.id == "GetPaymentInstitutionPayoutMethods" }
    { op.id == "GetPaymentInstitutionPayoutSchedules" }
