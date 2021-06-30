package service.authz.api.entity

try_find_by_id(type, id, entities) = entity {
    entity := entities[_]
    entity.type == type
    entity.id == id
}

try_find_first(type, entities) = entity {
    entity := entities[_]
    entity.type == type
}
