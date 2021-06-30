package test.service.authz.util

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

test_concat_empty {
    concat([]) == {}
}

test_concat_1 {
    concat([[1]]) == [1]
}

test_concat_2 {
    concat([
        [1],
        [2]
    ]) == [1, 2]
}

test_concat_3 {
    concat([
        [1],
        [2],
        [3]
    ]) == [1, 2, 3]
}

test_concat_4 {
    concat([
        [1],
        [2],
        [3],
        [4]
    ]) == [1, 2, 3, 4]
}

test_concat_5 {
    concat([
        [1],
        [2],
        [3],
        [4],
        [5]
    ]) == [1, 2, 3, 4, 5]
}

test_concat_6 {
    concat([
        [1],
        [2],
        [3],
        [4],
        [5],
        [6, 7]
    ]) == [1, 2, 3, 4, 5, 6, 7]
}
