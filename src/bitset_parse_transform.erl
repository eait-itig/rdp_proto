%% rdp_proto
%%
%% Copyright 2022 The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(bitset_parse_transform).

-export([parse_transform/2, parse_transform_info/0]).

-record(?MODULE, {
    opts :: [term()],
    file :: undefined | string()
    }).

-spec parse_transform_info() -> #{'error_location' => 'column' | 'line'}.
parse_transform_info() ->
    #{error_location => column}.

-spec parse_transform([erl_parse:abstract_form()], [compile:option()]) ->
    [erl_parse:abstract_form()].
parse_transform(Forms, Options) ->
    S0 = #?MODULE{opts = Options},
    transform_all(Forms, S0).

transform_all([], _) -> [];
transform_all([Form0 | Rest], S0 = #?MODULE{}) ->
    {Forms1, S1} = transform(erl_syntax:type(Form0), Form0, S0),
    Forms1 ++ transform_all(Rest, S1).

transform(attribute, Form, S0 = #?MODULE{}) ->
    case erl_syntax:atom_value(erl_syntax:attribute_name(Form)) of
        bitset ->
            transform_bitset(Form, S0);
        file ->
            [FileNameTree, _] = erl_syntax:attribute_arguments(Form),
            S1 = S0#?MODULE{file = erl_syntax:string_value(FileNameTree)},
            {[Form], S1};
        _Other ->
            {[Form], S0}
    end;
transform(_Type, Form, S0) ->
    {[Form], S0}.

transform_bitset(Form, S0 = #?MODULE{file = FN}) ->
    Loc0 = erl_syntax:get_pos(Form),
    Loc1 = erl_anno:set_file(FN, Loc0),
    Loc2 = erl_anno:set_generated(true, Loc1),
    [ArgsAbs] = erl_syntax:attribute_arguments(Form),
    {Name, Bits} = erl_syntax:concrete(ArgsAbs),
    Forms0 = compile_bitset(Name, Bits),
    Forms1 = lists:flatten([[X, unused_gag(X)] || X <- Forms0]),
    Forms2 = Forms1 ++ [compile_bitset_type(Name, Bits)],
    Forms3 = [erl_syntax:revert(X) || X <- Forms2],
    Forms4 = [erl_parse:map_anno(fun (_) -> Loc2 end, X) || X <- Forms3],
    % lists:foreach(fun (FForm) ->
    %  io:format("~s\n", [erl_pp:form(FForm)])
    % end, lists:reverse(Forms4)),
    {Forms4, S0}.

compile_bitset(Name, Bits) ->
    [
        compile_bitset_encode(Name, Bits),
        compile_bitset_decode(Name, Bits),
        compile_bitset_encode_int(Name, Bits),
        compile_bitset_decode_int(Name, Bits)
    ].

unused_gag(Func) ->
    Name = erl_syntax:function_name(Func),
    Arity = erl_syntax:function_arity(Func),
    ArgsAbs = erl_syntax:abstract([{nowarn_unused_function,
        [{erl_syntax:atom_value(Name), Arity}]}]),
    erl_syntax:attribute(erl_syntax:atom(compile), [ArgsAbs]).

-type expr() :: erl_syntax:syntaxTree().
-type var() :: erl_syntax:syntaxTree().

-spec concat_atoms([atom()]) -> expr().
concat_atoms(List) ->
    erl_syntax:atom(
        list_to_atom(
            lists:flatten(
                lists:join("_", [atom_to_list(X) || X <- List])))).

flag_types([]) -> [];
flag_types([skip | Rest]) -> flag_types(Rest);
flag_types([{skip, _} | Rest]) -> flag_types(Rest);
flag_types([BitName | Rest]) when is_atom(BitName) ->
    [erl_syntax:atom(BitName) | flag_types(Rest)];
flag_types([{BitName, _Size} | Rest]) when is_atom(BitName) ->
    [erl_syntax:type_union([
        erl_syntax:atom(BitName),
        erl_syntax:tuple_type([erl_syntax:atom(BitName),
            erl_syntax:type_application(
                erl_syntax:atom(integer), [])])]) | flag_types(Rest)].

compile_bitset_type(Name, Bits) ->
    TypeDef0 = erl_syntax:type_application(
        erl_syntax:atom(list),
        [erl_syntax:type_union(flag_types(Bits))]),
    TypeDef1 = erl_syntax:revert(TypeDef0),
    TypeDefAbs = erl_syntax:abstract({Name, TypeDef1, []}),
    erl_syntax:attribute(erl_syntax:atom(type), [TypeDefAbs]).

-spec var(string(), integer()) -> var().
var(Prefix, N) ->
    erl_syntax:variable(list_to_atom(Prefix ++ integer_to_list(N))).

-spec tvar(integer()) -> var().
tvar(N) -> var("T", N).
-spec vvar(integer()) -> var().
vvar(N) -> var("V", N).

bit_fields(SkipExpr, Bits) -> bit_fields(0, SkipExpr, Bits).
bit_fields(_N, _SkipExpr, []) -> [];
bit_fields(N, SkipExpr, [skip | Rest]) ->
    F = erl_syntax:binary_field(SkipExpr, erl_syntax:integer(1), []),
    [F | bit_fields(N, SkipExpr, Rest)];
bit_fields(N, SkipExpr, [{skip, SkipN} | Rest]) when is_integer(SkipN) ->
    F = erl_syntax:binary_field(SkipExpr, erl_syntax:integer(SkipN), []),
    [F | bit_fields(N, SkipExpr, Rest)];
bit_fields(N, SkipExpr, [BitName | Rest]) when is_atom(BitName) ->
    F = erl_syntax:binary_field(tvar(N), erl_syntax:integer(1), []),
    [F | bit_fields(N + 1, SkipExpr, Rest)];
bit_fields(N, SkipExpr, [{BitName, Bits} | Rest]) when is_atom(BitName) and is_integer(Bits) ->
    F = erl_syntax:binary_field(tvar(N), erl_syntax:integer(Bits),
        [erl_syntax:atom(big)]),
    [F | bit_fields(N + 1, SkipExpr, Rest)].

encode_case_forms(InVar, Bits) -> encode_case_forms(0, InVar, Bits).
encode_case_forms(_N, _InVar, []) -> [];
encode_case_forms(N, InVar, [skip | Rest]) ->
    encode_case_forms(N, InVar, Rest);
encode_case_forms(N, InVar, [{skip, _} | Rest]) ->
    encode_case_forms(N, InVar, Rest);
encode_case_forms(N, InVar, [BitName | Rest]) when is_atom(BitName) ->
    F = erl_syntax:match_expr(tvar(N),
        erl_syntax:case_expr(
            erl_syntax:application(erl_syntax:atom(lists),
                erl_syntax:atom(member), [erl_syntax:atom(BitName), InVar]),
            [erl_syntax:clause([erl_syntax:atom(true)], [],
                [erl_syntax:integer(1)]),
             erl_syntax:clause([erl_syntax:atom(false)], [],
                [erl_syntax:integer(0)])])),
    [F | encode_case_forms(N + 1, InVar, Rest)];
encode_case_forms(N, InVar, [{BitName,_} | Rest]) when is_atom(BitName) ->
    F = erl_syntax:match_expr(tvar(N),
        erl_syntax:case_expr(
            erl_syntax:application(erl_syntax:atom(lists),
                erl_syntax:atom(keyfind),
                [erl_syntax:atom(BitName), erl_syntax:integer(1), InVar]),
            [erl_syntax:clause(
                [erl_syntax:tuple([erl_syntax:atom(BitName), vvar(N)])], [],
                [vvar(N)]),
             erl_syntax:clause([erl_syntax:atom(false)], [],
                [erl_syntax:case_expr(
                    erl_syntax:application(erl_syntax:atom(lists),
                        erl_syntax:atom(member), [erl_syntax:atom(BitName), InVar]),
                    [erl_syntax:clause([erl_syntax:atom(true)], [],
                        [erl_syntax:integer(1)]),
                     erl_syntax:clause([erl_syntax:atom(false)], [],
                        [erl_syntax:integer(0)])])])])),
    [F | encode_case_forms(N + 1, InVar, Rest)].

compile_bitset_encode(Name, Bits) ->
    InVar = erl_syntax:variable('Input'),
    CaseForms = encode_case_forms(InVar, Bits),
    BinForm = erl_syntax:binary(bit_fields(erl_syntax:integer(0), Bits)),
    erl_syntax:function(
        concat_atoms([encode, Name, bin]),
        [erl_syntax:clause([InVar], [], CaseForms ++ [BinForm])]).

decode_case_forms(Bits) -> decode_case_forms(0, Bits).
decode_case_forms(N, []) ->
    [vvar(N)];
decode_case_forms(N, [skip | Rest]) ->
    decode_case_forms(N, Rest);
decode_case_forms(N, [{skip,_} | Rest]) ->
    decode_case_forms(N, Rest);
decode_case_forms(N, [BitName | Rest]) when is_atom(BitName) ->
    F = erl_syntax:match_expr(vvar(N + 1),
        erl_syntax:case_expr(tvar(N),
            [erl_syntax:clause([erl_syntax:integer(1)], [],
                [erl_syntax:list([erl_syntax:atom(BitName)], vvar(N))]),
             erl_syntax:clause([erl_syntax:integer(0)], [],
                [vvar(N)])])),
    [F | decode_case_forms(N+1, Rest)];
decode_case_forms(N, [{BitName,_} | Rest]) when is_atom(BitName) ->
    F = erl_syntax:match_expr(vvar(N + 1),
        erl_syntax:case_expr(tvar(N),
            [erl_syntax:clause([erl_syntax:integer(1)], [],
                [erl_syntax:list([erl_syntax:atom(BitName)], vvar(N))]),
             erl_syntax:clause([erl_syntax:integer(0)], [],
                [vvar(N)]),
             erl_syntax:clause([erl_syntax:underscore()], [],
                [erl_syntax:list([
                    erl_syntax:tuple([erl_syntax:atom(BitName), tvar(N)])],
                    vvar(N))])])),
    [F | decode_case_forms(N+1, Rest)].

compile_bitset_decode(Name, Bits) ->
    InVar = erl_syntax:variable('Input'),
    BinForm = erl_syntax:match_expr(
        erl_syntax:binary(bit_fields(erl_syntax:underscore(), Bits)),
        InVar),
    EmptyForm = erl_syntax:match_expr(vvar(0), erl_syntax:list([])),
    CaseForms = decode_case_forms(Bits),
    erl_syntax:function(
        concat_atoms([decode, Name, bin]),
        [erl_syntax:clause([InVar], [], [BinForm, EmptyForm] ++ CaseForms)]).

encode_int_forms(InVar, Bits) -> encode_int_forms(0, 0, InVar, Bits).
encode_int_forms(N, _Shift, _InVar, []) ->
    [vvar(N)];
encode_int_forms(N, Shift, InVar, [skip | Rest]) ->
    encode_int_forms(N, Shift + 1, InVar, Rest);
encode_int_forms(N, Shift, InVar, [{skip, Bits} | Rest]) ->
    encode_int_forms(N, Shift + Bits, InVar, Rest);
encode_int_forms(N, Shift, InVar, [BitName | Rest]) when is_atom(BitName) ->
    Mask = 1 bsl Shift,
    F = erl_syntax:match_expr(vvar(N + 1),
        erl_syntax:case_expr(
            erl_syntax:application(erl_syntax:atom(lists),
                erl_syntax:atom(member), [erl_syntax:atom(BitName), InVar]),
            [erl_syntax:clause([erl_syntax:atom(true)], [],
                [erl_syntax:infix_expr(vvar(N), erl_syntax:operator('bor'),
                    erl_syntax:integer(Mask))]),
             erl_syntax:clause([erl_syntax:atom(false)], [],
                [vvar(N)])])),
    [F | encode_int_forms(N + 1, Shift + 1, InVar, Rest)];
encode_int_forms(N, Shift, InVar, [{BitName,Bits} | Rest]) when is_atom(BitName) ->
    Mask = (1 bsl (Bits + 1)) - 1,
    LowBit = 1 bsl Shift,
    F = erl_syntax:match_expr(vvar(N + 1),
        erl_syntax:case_expr(
            erl_syntax:application(erl_syntax:atom(lists),
                erl_syntax:atom(keyfind),
                [erl_syntax:atom(BitName), erl_syntax:integer(1), InVar]),
            [erl_syntax:clause(
                [erl_syntax:tuple([erl_syntax:atom(BitName), tvar(N)])], [],
                [erl_syntax:infix_expr(vvar(N), erl_syntax:operator('bor'),
                    erl_syntax:infix_expr(
                        erl_syntax:infix_expr(tvar(N), erl_syntax:operator('band'),
                            erl_syntax:integer(Mask)),
                        erl_syntax:operator('bsl'), erl_syntax:integer(Shift)))]),
             erl_syntax:clause([erl_syntax:atom(false)], [],
                [erl_syntax:case_expr(
                    erl_syntax:application(erl_syntax:atom(lists),
                        erl_syntax:atom(member), [erl_syntax:atom(BitName), InVar]),
                    [erl_syntax:clause([erl_syntax:atom(true)], [],
                        [erl_syntax:infix_expr(vvar(N), erl_syntax:operator('bor'),
                            erl_syntax:integer(LowBit))]),
                     erl_syntax:clause([erl_syntax:atom(false)], [],
                        [vvar(N)])])])])),
    [F | encode_int_forms(N + 1, Shift + Bits, InVar, Rest)].

compile_bitset_encode_int(Name, Bits) ->
    InVar = erl_syntax:variable('Input'),
    EmptyForm = erl_syntax:match_expr(vvar(0), erl_syntax:integer(0)),
    CaseForms = encode_int_forms(InVar, lists:reverse(Bits)),
    erl_syntax:function(
        concat_atoms([encode, Name]),
        [erl_syntax:clause([InVar], [], [EmptyForm | CaseForms])]).

decode_int_forms(InVar, Bits) -> decode_int_forms(0, 0, InVar, Bits).
decode_int_forms(N, _Shift, _InVar, []) ->
    [vvar(N)];
decode_int_forms(N, Shift, InVar, [skip | Rest]) ->
    decode_int_forms(N, Shift + 1, InVar, Rest);
decode_int_forms(N, Shift, InVar, [{skip, Bits} | Rest]) ->
    decode_int_forms(N, Shift + Bits, InVar, Rest);
decode_int_forms(N, Shift, InVar, [BitName | Rest]) when is_atom(BitName) ->
    Mask = 1 bsl Shift,
    F = erl_syntax:match_expr(vvar(N + 1),
        erl_syntax:case_expr(
            erl_syntax:infix_expr(InVar, erl_syntax:operator('band'),
                    erl_syntax:integer(Mask)),
            [erl_syntax:clause([erl_syntax:integer(0)], [],
                [vvar(N)]),
             erl_syntax:clause([erl_syntax:underscore()], [],
                [erl_syntax:list([erl_syntax:atom(BitName)], vvar(N))])])),
    [F | decode_int_forms(N + 1, Shift + 1, InVar, Rest)];
decode_int_forms(N, Shift, InVar, [{BitName,Bits} | Rest]) when is_atom(BitName) ->
    Mask = (1 bsl (Bits + 1)) - 1,
    Expr = erl_syntax:infix_expr(
        erl_syntax:infix_expr(InVar, erl_syntax:operator('bsr'),
            erl_syntax:integer(Shift)),
        erl_syntax:operator('band'), erl_syntax:integer(Mask)),
    F = erl_syntax:match_expr(vvar(N + 1),
        erl_syntax:case_expr(Expr,
            [erl_syntax:clause([erl_syntax:integer(0)], [], [vvar(N)]),
             erl_syntax:clause([erl_syntax:integer(1)], [],
                [erl_syntax:list([erl_syntax:atom(BitName)], vvar(N))]),
             erl_syntax:clause([tvar(N)], [], [
                erl_syntax:list([erl_syntax:tuple([
                    erl_syntax:atom(BitName), tvar(N)])], vvar(N))])])),
    [F | decode_int_forms(N + 1, Shift + Bits, InVar, Rest)].

compile_bitset_decode_int(Name, Bits) ->
    InVar = erl_syntax:variable('Input'),
    EmptyForm = erl_syntax:match_expr(vvar(0), erl_syntax:list([])),
    CaseForms = decode_int_forms(InVar, lists:reverse(Bits)),
    erl_syntax:function(
        concat_atoms([decode, Name]),
        [erl_syntax:clause([InVar], [], [EmptyForm | CaseForms])]).
