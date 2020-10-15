-module(validator).

-export([main/1]).

-define(SUCCESS, 0).
-define(INPUT_ERROR, 1).
-define(VALIDATION_FAILED, 2).

%%

-spec main(_Args :: [string()]) -> no_return().
main([Filepath]) ->
    #{total := Total, valid := Valid, errors := Errors} = validate_file(Filepath),
    case Valid of
        Total ->
            abort(?SUCCESS, "~p of ~p instance(s) valid", [Valid, Total]);
        _ ->
            abort(?VALIDATION_FAILED, "~p of ~p instance(s) INVALID", [maps:size(Errors), Total])
    end;
main([]) ->
    abort(?INPUT_ERROR, "No input file");
main(_Args) ->
    abort(?INPUT_ERROR, "Too many arguments").

%%

validate_file(Filepath) ->
    case file:read_file(Filepath) of
        {ok, Data} ->
            validate_json(Data);
        {error, Reason} ->
            abort(?INPUT_ERROR, "Input file read failed: ~0p", [Reason])
    end.

validate_json(Data) ->
    try jsx:decode(Data, [{labels, atom}]) of
        Mapping ->
            validate_instances(Mapping)
    catch error:badarg ->
        abort(?INPUT_ERROR, "Input file contains invalid JSON")
    end.

validate_instances(Mapping) ->
    maps:fold(
        fun (Name, Instance, Report = #{total := T, valid := V, errors := Es}) ->
            Report1 = Report#{total := T + 1},
            case bouncer_context_v1:encode(thrift, Instance) of
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

%%

abort(Code, Reason) ->
    abort(Code, Reason, []).

abort(Code, Reason, Details) ->
    Pre = case Code of
        0 -> "[OK] ";
        _ -> "[ERROR] "
    end,
    io:format(standard_error, Pre ++ Reason ++ "~n", Details),
    erlang:halt(Code).
