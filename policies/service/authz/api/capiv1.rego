package service.authz.api.binapi

import input.capiv1.op

allowed[why] {
    requires_no_auth
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows this operation"
    }
}

allowed[why] {
    requires_auth
    # auth
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows this operation"
    }
}

requires_auth
    { op.id == "CreateInvoice" }
    { op.id == "CreateInvoiceAccessToken" }
    { op.id == "GetInvoiceByID" }
    { op.id == "FulfillInvoice" }
    { op.id == "RescindInvoice" }
    { op.id == "GetInvoiceEvents" }
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
    { op.id == "GetInvoicePaymentMethodsByTemplateID" }
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

requires_no_auth
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
