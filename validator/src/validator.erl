-module(validator).

-include_lib("bouncer_proto/include/bouncer_context_v1_thrift.hrl").
-include_lib("bouncer_proto/include/bouncer_restriction_thrift.hrl").

-export([main/1]).

-export_type([thrift_record/0]).
-export_type([struct/0]).

-define(SUCCESS, 0).
-define(INPUT_ERROR, 1).
-define(VALIDATION_FAILED, 2).

-type thrift_record() :: bouncer_context_v1_thrift:'ContextFragment'() | bouncer_restriction_thrift:'Restrictions'().

-type struct() :: {
    {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'} | {bouncer_restriction_thrift, 'Restrictions'}},
    bouncer_context_v1_thrift:struct_info() | bouncer_restriction_thrift:struct_info(),
    thrift_record()
}.

%%

-spec main(_Args :: [string()]) -> no_return().
main([Filepath, StructName]) ->
    Struct = validate_struct(StructName),
    #{total := Total, valid := Valid, errors := Errors} = validate_file(Filepath, Struct),
    case Valid of
        Total ->
            abort(?SUCCESS, "~p of ~p instance(s) valid", [Valid, Total]);
        _ ->
            abort(?VALIDATION_FAILED, "~p of ~p instance(s) INVALID", [maps:size(Errors), Total])
    end;
main([_]) ->
    abort(?INPUT_ERROR, "No input file or StructName");
main([]) ->
    abort(?INPUT_ERROR, "No input file and StructName");
main(_Args) ->
    abort(?INPUT_ERROR, "Too many arguments").

%%

validate_file(Filepath, Struct) ->
    case file:read_file(Filepath) of
        {ok, Data} ->
            validate_json(Data, Struct);
        {error, Reason} ->
            abort(?INPUT_ERROR, "Input file read failed: ~0p", [Reason])
    end.

validate_json(Data, Struct) ->
    try jsx:decode(Data, [{labels, atom}]) of
        Mapping ->
            validate_instances(Mapping, Struct)
    catch error:badarg ->
        abort(?INPUT_ERROR, "Input file contains invalid JSON")
    end.

validate_instances(Mapping, Struct) ->
    maps:fold(
        fun (Name, Instance, Report = #{total := T, valid := V, errors := Es}) ->
            Report1 = Report#{total := T + 1},
            case thrift_encoder:encode(thrift, Instance, Struct) of
                {ok, _Content} ->
                    _ = report_validation_success(T + 1, Name),
                    Report1#{valid := V + 1};
                {error, Reason} ->
                    _ = report_validation_error(T + 1, Name, Reason),
                    Report1#{errors := Es#{Name => Reason}}
            end
        end,
        #{
            total => 0,
            valid => 0,
            errors => #{}
        },
        Mapping
    ).

report_validation_success(I, Name) ->
    io:format(standard_error, "~3.B. Instance '~p' valid~n", [I, Name]).

report_validation_error(I, Name, Reason) ->
    io:format(standard_error, "~3.B. Instance '~p' invalid: ~0p~n", [I, Name, Reason]).

-spec validate_struct(string()) -> struct().
validate_struct("Context") ->
    {
        {struct, struct, {bouncer_context_v1_thrift, 'ContextFragment'}},
        bouncer_context_v1_thrift:struct_info('ContextFragment'),
        #bctx_v1_ContextFragment{}
    };
validate_struct("Restrictions") ->
    {
        {struct, struct, {bouncer_restriction_thrift, 'Restrictions'}},
        bouncer_restriction_thrift:struct_info('Restrictions'),
        #brstn_Restrictions{}
    };
validate_struct(StructName) ->
    abort(?INPUT_ERROR, "StructName: '~p' is invalid. Permitted values: 'Context', 'Restrictions'", [StructName]).

%%

-spec abort(integer(), string()) -> no_return().
abort(Code, Reason) ->
    abort(Code, Reason, []).

-spec abort(integer(), string(), list()) -> no_return().
abort(Code, Reason, Details) ->
    Pre = case Code of
        0 -> "[OK] ";
        _ -> "[ERROR] "
    end,
    io:format(standard_error, Pre ++ Reason ++ "~n", Details),
    erlang:halt(Code).
