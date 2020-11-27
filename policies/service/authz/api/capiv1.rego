package service.authz.api.capiv1

import input.capi.op
import input.invoicing

allowed[why] {
    input.auth.method == "SessionToken"
    requires_invoicing_context
    input_matches_invoicing_context
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows this operation"
    }
}

allowed[why] {
    input.auth.method == "InvoiceAccessToken"
    allowed_w_invoice_access_token[why]
}

allowed_w_invoice_access_token[why] {
    op.id == "CreatePaymentResource"
    party_matches_token_scope
    why := {
        "code": "invoice_access_token_allows_tokenization",
        "description": "Invoice access token allows payment resource tokenization"
    }
}

allowed_w_invoice_access_token[why] {
    not op.id == "CreatePaymentResource"
    authorize_w_invoice_access_token
    invoice_matches_token_scope
    why := {
        "code": "invoice_access_token_allows_operation",
        "description": "Invoice access token allows operation on this invoice"
    }
}

matching_invoice {
    op.invoice.id
    op.invoice.id == invoicing.invoice.id
}

matching_party {
    op.party.id
    op.party.id == invoicing.party.id
}
matching_party {
    not op.party.id
    not invoicing.party.id
}

matching_shop {
    op.shop.id
    op.shop.id == invoicing.shop.id
}
matching_shop {
    not op.shop.id
    not invoicing.shop.id
}

matching_payment {
    op.payment.id
    op.payment.id == invoicing.payment.id
}
matching_payment {
    not op.payment.id
    not invoicing.payment.id
}

matching_refund {
    op.refund.id
    op.refund.id == invoicing.refund.id
}
matching_refund {
    not op.refund.id
    not invoicing.refund.id
}

input_matches_invoicing_context {
    matching_party
    matching_shop
    matching_invoice
    matching_payment
    matching_refund
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

party_matches_token_scope {
    scope := input.auth.scope[_]
    scope.party.id == op.party.id
}

invoice_matches_token_scope {
    scope := input.auth.scope[_]
    scope.party.id == op.party.id
    scope.invoice.id == op.invoice.id
}

authorize_w_invoice_access_token
    { op.id == "GetInvoiceByID" }
    { op.id == "GetInvoiceEvents" }
    { op.id == "GetInvoicePaymentMethods" }
    { op.id == "CreatePayment" }
    { op.id == "GetPayments" }
    { op.id == "GetPaymentByID" }
