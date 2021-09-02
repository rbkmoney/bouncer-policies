package service.authz.util

member_of(element, list) = false {
  count(list) = 0
}

member_of(element, list) = result {
  count(list) > 0
  result := list[_] == element
}
