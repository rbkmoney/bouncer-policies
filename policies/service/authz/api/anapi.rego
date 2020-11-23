package service.authz.api.anapi

import input.anapi.op
import data.service.authz.org

# Set of assertions which tell why operation under the input context is forbidden.
# When the set is empty operation is not explicitly forbidden.
# Each element must be either a string `"code"` or a 2-item array of the form:
# ```
# ["code", "description"]
# ```
forbidden[why] {
    ops_require_auth
    anapi_user_access_denied
    why := {
        "code": "user_access_denied",
        "description": "User didn't pass check"
    }
}

anapi_user_access_denied {
    not op_with_shops
    not user_is_owner
}

op_with_shops {
    count(op.shops) != 0
}

user_is_owner {
    organization := org.org_by_operation
    input.user.id == organization.owner.id
}

# Restrictions

restrictions[what] {
    not user_is_owner
    what := {
        "op": {
            "shops": [{"id": id} | id := op_shop_in_scope[_].id]
        }
    }
}

op_shop_in_scope[shop] {
    some i
    organization := org.org_by_operation
    op.shops[i].id == organization.roles[_].scope.shop.id
    shop := op.shops[i]
}

# Set of assertions which tell why operation under the input context is allowed.
# When the set is empty operation is not explicitly allowed.
# Each element must be a 2-item array of the following form:
# ```
# ["code", "description"]
# ```
allowed[why] {
    all_ops
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows this operation"
    }
}

all_ops
    { ops_require_auth }
    { ops_with_no_auth }

ops_require_auth
    { analytics_operation_allowed }
    { reports_operation_allowed }
    { searches_operation_allowed }

ops_with_no_auth
    { op.id == "DownloadFile" }

analytics_operation_allowed
    { op.id == "GetPaymentsToolDistribution" }
    { op.id == "GetPaymentsAmount" }
    { op.id == "GetAveragePayment" }
    { op.id == "GetPaymentsCount" }
    { op.id == "GetPaymentsErrorDistribution" }
    { op.id == "GetPaymentsSplitAmount" }
    { op.id == "GetPaymentsSplitCount" }
    { op.id == "GetRefundsAmount" }
    { op.id == "GetCurrentBalances" }
    { op.id == "GetPaymentsSubErrorDistribution" }
    { op.id == "GetCurrentBalancesGroupByShop" }

reports_operation_allowed
    { op.id == "SearchReports" }
    { op.id == "GetReport" }
    { op.id == "CreateReport" }
    { op.id == "CancelReport" }

searches_operation_allowed
    { op.id == "SearchInvoices" }
    { op.id == "SearchPayments" }
    { op.id == "SearchPayouts" }
    { op.id == "SearchRefunds" }
    { op.id == "SearchChargebacks" }
