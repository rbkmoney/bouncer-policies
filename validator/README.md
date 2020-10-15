# Validator

The purpose of this little project is to produce a script to validate JSON objects as bouncer context instances, namely `context_v1.ContextFragment` for the time being. The input file **must** contain a valid JSON object with mapping from names to context instances, for example:
```json
{
    "ctx1": {"auth": {...}},
    "ctx2": {"user": {...}},
    ...
}
```

## Running

Just pass the filename as the only argument on the command line:
```
$ validator ../test/authz/fixtures/data.json
```

Script will exit:
* with `0` exit code if all instances are valid,
* with `1` if it can not process the input,
* with `2` if there are one or more invalid instances.

## Roadmap

* Better way to share `bouncer_context_v1` implementation with **bouncer** itself.
* Allow to specify input representation: a mapping (the only supported currently), single instance, etc.
