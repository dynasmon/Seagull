from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from app.features.events.domain.hunt_dialects import HuntQueryError

_KEYWORD_AND = "and"
_KEYWORD_OR = "or"
_KEYWORD_NOT = "not"
_RANGE_OPERATORS: Dict[str, str] = {">=": "gte", "<=": "lte", ">": "gt", "<": "lt"}
_INTEGER_FIELD_TYPES = frozenset({"integer", "long", "short"})
_RANGE_FIELD_TYPES = frozenset({"date", "ip"}) | _INTEGER_FIELD_TYPES
_WILDCARD_FIELD_TYPES = frozenset({"keyword", "text", "flattened"})
_TIMESTAMP_FIELDS = frozenset({"timestamp", "@timestamp"})
_WORD_BREAK_CHARS = frozenset('():<>"')
_WILDCARD_CHARS = ("*", "?")
_MAX_GROUP_DEPTH = 16
_EXTRA_FIELD_PREFIX = "extra."


class _TokenKind(Enum):
    LPAREN = "lparen"
    RPAREN = "rparen"
    COLON = "colon"
    OPERATOR = "operator"
    WORD = "word"
    PHRASE = "phrase"
    END = "end"


@dataclass(frozen=True)
class _Token:
    kind: _TokenKind
    value: str
    position: int


class _Node:
    pass


@dataclass(frozen=True)
class _AndNode(_Node):
    children: Tuple[_Node, ...]


@dataclass(frozen=True)
class _OrNode(_Node):
    children: Tuple[_Node, ...]


@dataclass(frozen=True)
class _NotNode(_Node):
    child: _Node


@dataclass(frozen=True)
class _MatchNode(_Node):
    field: str
    value: str
    phrase: bool
    position: int


@dataclass(frozen=True)
class _RangeNode(_Node):
    field: str
    operator: str
    value: str
    position: int


@dataclass(frozen=True)
class _FreeTextNode(_Node):
    text: str
    phrase: bool
    position: int


@dataclass(frozen=True)
class CompiledKql:
    query: Dict[str, Any]
    clause_count: int
    has_wildcard: bool
    has_timestamp_range: bool


def _read_phrase(text: str, start: int) -> Tuple[str, int]:
    out: List[str] = []
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text):
            out.append(text[index + 1])
            index += 2
            continue
        if char == '"':
            return "".join(out), index + 1
        out.append(char)
        index += 1
    raise HuntQueryError(
        f"KQL syntax error at position {start + 1}: unterminated quoted string",
        reason="syntax",
    )


def _tokenize(text: str) -> List[_Token]:
    tokens: List[_Token] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char == "(":
            tokens.append(_Token(_TokenKind.LPAREN, char, index))
            index += 1
            continue
        if char == ")":
            tokens.append(_Token(_TokenKind.RPAREN, char, index))
            index += 1
            continue
        if char == ":":
            tokens.append(_Token(_TokenKind.COLON, char, index))
            index += 1
            continue
        if text.startswith(">=", index) or text.startswith("<=", index):
            tokens.append(_Token(_TokenKind.OPERATOR, text[index:index + 2], index))
            index += 2
            continue
        if char in "<>":
            tokens.append(_Token(_TokenKind.OPERATOR, char, index))
            index += 1
            continue
        if char == '"':
            value, next_index = _read_phrase(text, index)
            tokens.append(_Token(_TokenKind.PHRASE, value, index))
            index = next_index
            continue
        start = index
        while index < length and not text[index].isspace() and text[index] not in _WORD_BREAK_CHARS:
            index += 1
        tokens.append(_Token(_TokenKind.WORD, text[start:index], start))
    tokens.append(_Token(_TokenKind.END, "", length))
    return tokens


class _Parser:
    def __init__(self, tokens: Sequence[_Token]) -> None:
        self._tokens = tokens
        self._index = 0
        self._depth = 0

    def parse(self) -> _Node:
        node = self._parse_or()
        tail = self._peek()
        if tail.kind is not _TokenKind.END:
            raise self._error(tail, "expected 'and' or 'or' between clauses")
        return node

    def _peek(self) -> _Token:
        return self._tokens[self._index]

    def _advance(self) -> _Token:
        token = self._tokens[self._index]
        if token.kind is not _TokenKind.END:
            self._index += 1
        return token

    def _keyword(self, token: _Token) -> str:
        return token.value.lower() if token.kind is _TokenKind.WORD else ""

    def _error(self, token: _Token, expectation: str) -> HuntQueryError:
        found = "end of query" if token.kind is _TokenKind.END else f"'{token.value}'"
        return HuntQueryError(
            f"KQL syntax error at position {token.position + 1}: {expectation}, found {found}",
            reason="syntax",
        )

    def _parse_or(self) -> _Node:
        nodes = [self._parse_and()]
        while self._keyword(self._peek()) == _KEYWORD_OR:
            self._advance()
            nodes.append(self._parse_and())
        if len(nodes) == 1:
            return nodes[0]
        return _OrNode(tuple(nodes))

    def _parse_and(self) -> _Node:
        nodes = [self._parse_not()]
        while self._keyword(self._peek()) == _KEYWORD_AND:
            self._advance()
            nodes.append(self._parse_not())
        if len(nodes) == 1:
            return nodes[0]
        return _AndNode(tuple(nodes))

    def _parse_not(self) -> _Node:
        if self._keyword(self._peek()) == _KEYWORD_NOT:
            self._advance()
            return _NotNode(self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> _Node:
        token = self._peek()
        if token.kind is _TokenKind.LPAREN:
            self._depth += 1
            if self._depth > _MAX_GROUP_DEPTH:
                raise self._error(token, f"grouping deeper than {_MAX_GROUP_DEPTH} levels is not allowed")
            self._advance()
            node = self._parse_or()
            closing = self._advance()
            if closing.kind is not _TokenKind.RPAREN:
                raise self._error(closing, "expected ')'")
            self._depth -= 1
            return node
        if token.kind is _TokenKind.PHRASE:
            self._advance()
            if self._peek().kind in (_TokenKind.COLON, _TokenKind.OPERATOR):
                raise self._error(token, "field names cannot be quoted")
            return _FreeTextNode(token.value, True, token.position)
        if token.kind is _TokenKind.WORD:
            if self._keyword(token) in (_KEYWORD_AND, _KEYWORD_OR):
                raise self._error(token, "expected a clause before the operator")
            self._advance()
            upcoming = self._peek()
            if upcoming.kind is _TokenKind.COLON:
                self._advance()
                return self._parse_field_value(token)
            if upcoming.kind is _TokenKind.OPERATOR:
                operator = self._advance()
                value = self._expect_value(f"expected a value after '{operator.value}'")
                return _RangeNode(token.value, operator.value, value.value, value.position)
            return _FreeTextNode(token.value, False, token.position)
        raise self._error(token, "expected a field clause, a value or '('")

    def _parse_field_value(self, field_token: _Token) -> _Node:
        token = self._peek()
        if token.kind is _TokenKind.LPAREN:
            return self._parse_value_group(field_token)
        if token.kind in (_TokenKind.WORD, _TokenKind.PHRASE):
            self._advance()
            return _MatchNode(field_token.value, token.value, token.kind is _TokenKind.PHRASE, token.position)
        raise self._error(token, f"expected a value after '{field_token.value}:'")

    def _parse_value_group(self, field_token: _Token) -> _Node:
        self._advance()
        values = [self._expect_value("expected a value inside the group")]
        connector: str | None = None
        while True:
            token = self._peek()
            if token.kind is _TokenKind.RPAREN:
                self._advance()
                break
            keyword = self._keyword(token)
            if keyword not in (_KEYWORD_AND, _KEYWORD_OR):
                raise self._error(token, "expected 'and', 'or' or ')' inside a value group")
            if connector is None:
                connector = keyword
            elif connector != keyword:
                raise self._error(token, "value groups cannot mix 'and' with 'or'")
            self._advance()
            values.append(self._expect_value("expected a value after the connector"))
        nodes: Tuple[_Node, ...] = tuple(
            _MatchNode(field_token.value, value.value, value.kind is _TokenKind.PHRASE, value.position)
            for value in values
        )
        if len(nodes) == 1:
            return nodes[0]
        if connector == _KEYWORD_AND:
            return _AndNode(nodes)
        return _OrNode(nodes)

    def _expect_value(self, expectation: str) -> _Token:
        token = self._peek()
        if token.kind not in (_TokenKind.WORD, _TokenKind.PHRASE):
            raise self._error(token, expectation)
        return self._advance()


def _valid_fields_hint(field_types: Mapping[str, str]) -> str:
    return ", ".join(sorted(set(field_types) | {"extra.*"}))


class _Compiler:
    def __init__(
        self,
        *,
        field_types: Mapping[str, str],
        free_text_fields: Sequence[str],
        max_clauses: int,
    ) -> None:
        self._field_types = dict(field_types)
        self._free_text_fields = list(free_text_fields)
        self._max_clauses = max(1, int(max_clauses))
        self.clause_count = 0
        self.has_wildcard = False
        self.has_timestamp_range = False

    def compile(self, node: _Node) -> Dict[str, Any]:
        if isinstance(node, _AndNode):
            return {"bool": {"filter": [self.compile(child) for child in node.children]}}
        if isinstance(node, _OrNode):
            return {
                "bool": {
                    "should": [self.compile(child) for child in node.children],
                    "minimum_should_match": 1,
                }
            }
        if isinstance(node, _NotNode):
            return {"bool": {"must_not": [self.compile(node.child)]}}
        if isinstance(node, _MatchNode):
            return self._compile_match(node)
        if isinstance(node, _RangeNode):
            return self._compile_range(node)
        if isinstance(node, _FreeTextNode):
            return self._compile_free_text(node)
        raise HuntQueryError("KQL query could not be compiled", reason="syntax")

    def _count_clause(self) -> None:
        self.clause_count += 1
        if self.clause_count > self._max_clauses:
            raise HuntQueryError(
                f"KQL query exceeds the maximum of {self._max_clauses} clauses",
                reason="too_many_clauses",
            )

    def _resolve_field_type(self, field: str) -> str:
        field_type = self._field_types.get(field)
        if field_type is not None:
            return str(field_type)
        if field.startswith(_EXTRA_FIELD_PREFIX) and len(field) > len(_EXTRA_FIELD_PREFIX):
            return "flattened"
        raise HuntQueryError(
            f"Unknown field '{field}'. Valid fields: {_valid_fields_hint(self._field_types)}",
            reason="unknown_field",
        )

    def _coerce_int(self, field: str, value: str) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            raise HuntQueryError(
                f"Field '{field}' expects a numeric value, got '{value}'",
                reason="invalid_value",
            ) from None

    def _compile_match(self, node: _MatchNode) -> Dict[str, Any]:
        field_type = self._resolve_field_type(node.field)
        self._count_clause()
        value = node.value
        if not node.phrase:
            if value == "*":
                return {"exists": {"field": node.field}}
            if any(marker in value for marker in _WILDCARD_CHARS):
                if value[0] in "*?":
                    raise HuntQueryError(
                        f"Leading wildcards are not allowed (field '{node.field}', value '{value}')",
                        reason="leading_wildcard",
                    )
                if field_type not in _WILDCARD_FIELD_TYPES:
                    raise HuntQueryError(
                        f"Wildcards are not supported on {field_type} field '{node.field}'",
                        reason="invalid_value",
                    )
                self.has_wildcard = True
                return {"wildcard": {node.field: {"value": value, "case_insensitive": True}}}
        if field_type == "date":
            raise HuntQueryError(
                f"Use range operators (>=, <=, >, <) to filter the date field '{node.field}'",
                reason="invalid_value",
            )
        if field_type in _INTEGER_FIELD_TYPES:
            return {"term": {node.field: self._coerce_int(node.field, value)}}
        if field_type == "text":
            if node.phrase:
                return {"match_phrase": {node.field: value}}
            return {"match": {node.field: {"query": value, "operator": "and"}}}
        return {"term": {node.field: value}}

    def _compile_range(self, node: _RangeNode) -> Dict[str, Any]:
        field_type = self._resolve_field_type(node.field)
        self._count_clause()
        if field_type not in _RANGE_FIELD_TYPES:
            raise HuntQueryError(
                f"Range operators are not supported on {field_type} field '{node.field}'",
                reason="invalid_value",
            )
        value: Any = node.value
        if field_type in _INTEGER_FIELD_TYPES:
            value = self._coerce_int(node.field, node.value)
        if node.field in _TIMESTAMP_FIELDS:
            self.has_timestamp_range = True
        return {"range": {node.field: {_RANGE_OPERATORS[node.operator]: value}}}

    def _compile_free_text(self, node: _FreeTextNode) -> Dict[str, Any]:
        self._count_clause()
        text = node.text
        if not node.phrase and text and text[0] in "*?":
            raise HuntQueryError(
                f"Leading wildcards are not allowed in free-text terms ('{text}')",
                reason="leading_wildcard",
            )
        query = f'"{text.replace(chr(34), " ")}"' if node.phrase else text
        return {
            "simple_query_string": {
                "query": query,
                "fields": self._free_text_fields,
                "default_operator": "and",
                "lenient": True,
            }
        }


def compile_kql(
    text: str,
    *,
    field_types: Mapping[str, str],
    free_text_fields: Sequence[str],
    max_clauses: int,
) -> CompiledKql:
    raw = str(text or "").strip()
    if not raw:
        raise HuntQueryError("KQL query must contain non-whitespace characters", reason="syntax")
    node = _Parser(_tokenize(raw)).parse()
    compiler = _Compiler(
        field_types=field_types,
        free_text_fields=free_text_fields,
        max_clauses=max_clauses,
    )
    query = compiler.compile(node)
    return CompiledKql(
        query=query,
        clause_count=compiler.clause_count,
        has_wildcard=compiler.has_wildcard,
        has_timestamp_range=compiler.has_timestamp_range,
    )
