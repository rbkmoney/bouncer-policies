package test.service.authz.api.orgmgmt

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_orgmgmt_allowed_org_owner {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_owner,
        context.session_token_valid,
        context.op_orgmgmt_create_invitation
    ])
}

test_forbidden_user_without_orgs {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_without_orgs,
        context.session_token_valid,
        context.op_orgmgmt_create_invitation
    ])
}

test_allowed_user_not_owner {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_orgmgmt_get_org_member
    ])
}

test_forbidden_not_exist_operation {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_owner,
        context.session_token_valid,
        context.op_orgmgmt_not_exist_operation
    ])
}

test_forbidden_user_not_in_organization {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_orgmgmt_foreign_org
    ])
}

test_forbidden_another_auth_method {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.invoice_access_token_valid,
        context.op_orgmgmt_get_org_member
    ])
}

test_forbidden_not_org_in_request {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_orgmgmt_without_org
    ])
}

test_allowed_universal_opeartion {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_orgmgmt_create_org
    ])
}

test_forbidden_user_with_manager_role {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_orgmgmt_create_invitation
    ])
}

test_allowed_user_without_role {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_no_roles,
        context.session_token_valid,
        context.op_orgmgmt_join_org
    ])
}

test_forbidden_member_not_in_user_organization {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_orgmgmt_expel_member_from_another_org
    ])
}

test_allowed_member_in_user_organization {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_orgmgmt_expel_member_from_org
    ])
}

test_allowed_assign_memeber_role_for_user_in_the_same_organization {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_orgmgmt_assign_member_role
    ])
}

test_forbidden_remove_memeber_role_for_user_in_another_organization {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_orgmgmt_remove_member_role_in_another_org
    ])
}

test_forbidden_cancel_org_membership {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_no_roles,
        context.session_token_valid,
        context.op_orgmgmt_cancel_org_membership
    ])
}

test_allowed_cancel_org_membership {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_accountant,
        context.session_token_valid,
        context.op_orgmgmt_cancel_org_membership
    ])
}
