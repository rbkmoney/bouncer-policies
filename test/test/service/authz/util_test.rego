package test.service.authz.util

import data.service.authz.util

test_deepmerge_empty {
    deepmerge([]) == {}
}

test_deepmerge_1 {
    deepmerge([{"ice": "borg"}]) == {"ice": "borg"}
}

test_deepmerge_2 {
    deepmerge([
        {"a": 1},
        {"a": 3, "b": 2}
    ]) == {"a": 3, "b": 2}
}

test_deepmerge_3 {
    deepmerge([
        {"a": 1, "c": {"sub": 41}},
        {"b": 2, "c": {}},
        {"a": 3, "c": {"sub": []}}
    ]) == {"a":3, "b":2, "c":{"sub": []}}
}

test_deepmerge_4 {
    deepmerge([
        {"a": 1, "c": {"sub": 41}},
        {"b": 2, "c": {"mlem": {}}},
        {"a": 3, "c": {"sub": []}},
        {"b": 4, "c": {"mlem": "blep", "sub": null}}
    ]) == {"a": 3, "b": 4, "c": {"sub": null, "mlem": "blep"}}
}

test_member_of_true {
    util.member_of(1, [1])
}

test_member_of_false {
    false == util.member_of(1, [2])
}

test_member_of_empty_list {
    false == util.member_of(1, [])
}
