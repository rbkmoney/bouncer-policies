# Bouncer Policies

A repository with a set of access control policies consumable by the [bouncer][1] service, written in [Rego][2] language.

## Authoring

New access control policies go to `/policies/service` directory. Each new policy **MUST** be accompanied by a set of test cases, those go `/test/test` directory. The `/policies` and the `/test` directories as a whole are [policy bundles][3], please follow documented conventions carefully.

Each policy under `/policies/service` can be specified as _ruleset id_ when talking to [bouncer][1]. For example, ruleset identified with `"service/authz/api"` maps to `/policies/service/authz/api.rego` policy.

[Bouncer][1] expects each policy to define document with the name `"assertions"`, with following structure:
```
{
    // Set of assertions which tell why operation under the input context is forbidden.
    // When the set is empty operation is not explicitly forbidden.
    // Each element must be an object containing at least a "code" property, meant
    // primarily for machines to read and analyze. Though a "description" property meant
    // for humans won't hurt.
    // ```
    // {"code": "auth_expired", "description": "...", ...}
    // ```
    "forbidden" : [...],

    // Set of assertions which tell why operation under the input context is allowed.
    // When the set is empty operation is not explicitly allowed.
    // Each element must be a similar object, containing at least a "code" property.
    "allowed"   : [...]
}
```

When evaluating some policy [bouncer][1] will provide [bouncer context][4] in a JSON representation as an input document.

## Testing

Running `make test` in the project directory will execute all [test cases][5] in the `/test` bundle under docker container with OPA binary of the fixed version, consult Makefile to find out which version is currently in use.

Please put all context instances used for testing purposes in data documents under `fixtures/` subdirectory, this way the validator can pick them up and validate against [Thrift schema][4]. Run `make wc_validate` to do that.

## Running

Running `make build_image` will produce another Docker image tagged with HEAD commit hash, as always. This image is essentially an OPA binary set up to serve documents defined in the policy bundle.

Most of the usual OPA API operations are secured with the help of a system authorization policy defined under `/policies/system`.

[1]: https://github.com/rbkmoney/bouncer
[2]: https://www.openpolicyagent.org/docs/latest/policy-language/
[3]: https://www.openpolicyagent.org/docs/latest/management/#bundle-file-format
[4]: https://github.com/rbkmoney/bouncer-proto/blob/master/proto/context_v1.thrift
[5]: https://www.openpolicyagent.org/docs/latest/policy-testing/
