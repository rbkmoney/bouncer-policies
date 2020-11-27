package test.service.authz.util

deepmerge([]) = out {
    out := {}
}
deepmerge([o1]) = out {
    out := o1
}
deepmerge([o1, o2]) = out {
    out := object.union(o1, o2)
}
deepmerge([o1, o2, o3]) = out {
    out := object.union(object.union(o1, o2), o3)
}
deepmerge([o1, o2, o3, o4]) = out {
    out := object.union(object.union(object.union(o1, o2), o3), o4)
}
deepmerge([o1, o2, o3, o4, o5]) = out {
    out := object.union(object.union(object.union(object.union(o1, o2), o3), o4), o5)
}
