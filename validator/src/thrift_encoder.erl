-module(thrift_encoder).

-type format() :: thrift.

-export([encode/3]).

%%

-spec encode(format(), jsx:json_term(), validator:struct()) ->
    {ok, _Content} | {error, _}.
encode(thrift, Mapping, Struct) ->
    Codec = thrift_strict_binary_codec:new(),
    try to_thrift_value(Struct, Mapping) of
        CtxThrift ->
            case thrift_strict_binary_codec:write(Codec, Struct, CtxThrift) of
                {ok, Codec1} ->
                    {ok, thrift_strict_binary_codec:close(Codec1)};
                {error, _} = Error ->
                    Error
            end
    catch throw:{?MODULE, Reason} ->
        {error, Reason}
    end.

to_thrift_struct(StructDef, Map, Acc) ->
    % NOTE
    % This 2 refers to the first field in a record tuple.
    to_thrift_struct(StructDef, Map, 2, Acc).

to_thrift_struct([{_Tag, _Req, Type, Name, Default} | Rest], Map, Idx, Acc) ->
    case maps:take(Name, Map) of
        {V, MapLeft} ->
            Acc1 = erlang:setelement(Idx, Acc, to_thrift_value(Type, V)),
            to_thrift_struct(Rest, MapLeft, Idx + 1, Acc1);
        error when Default /= undefined ->
            Acc1 = erlang:setelement(Idx, Acc, Default),
            to_thrift_struct(Rest, Map, Idx + 1, Acc1);
        error ->
            to_thrift_struct(Rest, Map, Idx + 1, Acc)
    end;
to_thrift_struct([], MapLeft, _Idx, Acc) ->
    case map_size(MapLeft) of
        0 ->
            Acc;
        _ ->
            throw({?MODULE, {excess_mapping_data, MapLeft}})
    end.

to_thrift_value({struct, struct, {Mod, Name}}, V = #{}) ->
    {struct, _, StructDef} = Mod:struct_info(Name),
    Acc = erlang:make_tuple(length(StructDef) + 1, undefined, [{1, Mod:record_name(Name)}]),
    to_thrift_struct(StructDef, V, Acc);
to_thrift_value({set, Type}, Vs) ->
    ordsets:from_list([to_thrift_value(Type, V) || V <- ordsets:to_list(Vs)]);
to_thrift_value(string, V) ->
    V;
to_thrift_value(i64, V) ->
    V;
to_thrift_value(i32, V) ->
    V;
to_thrift_value(i16, V) ->
    V;
to_thrift_value(byte, V) ->
    V.
