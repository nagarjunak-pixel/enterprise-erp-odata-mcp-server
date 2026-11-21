"""Zero-`eval()` recursive-descent OData v4 `$filter` AST parser, type-checker & evaluator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from erp_odata_mcp.types import EdmPropertySpec, EntitySetSchema


class FilterParseError(ValueError):
    """Syntax error in OData v4 `$filter` expression."""


class UnknownFilterFieldError(ValueError):
    """Referenced field does not exist in Clean-Core OData EntitySet schema."""

    def __init__(self, field: str) -> None:
        super().__init__(f"Unknown field {field!r}")
        self.field = field


class UnfilterableFieldError(ValueError):
    """Referenced field is marked `filterable=False` (e.g. restricted PII column)."""

    def __init__(self, field: str) -> None:
        super().__init__(f"Field {field!r} is not filterable")
        self.field = field


class FilterTypeMismatchError(ValueError):
    """Literal value violates declared EDM property type."""

    def __init__(self, field: str, edm_type: str, literal: Any) -> None:
        super().__init__(f"Field {field!r} ({edm_type}) incompatible with literal {literal!r}")
        self.field = field


@dataclass(frozen=True)
class _Token:
    kind: str  # IDENT, STRING, NUMBER, BOOL, OP, LPAREN, RPAREN, COMMA
    value: str


FilterNode = tuple[Any, ...]

_CMP_OPS = {"eq", "ne", "gt", "ge", "lt", "le"}
_FUNCS = {"startswith", "endswith", "contains"}


def _tokenize_odata(expr: str) -> list[_Token]:
    tokens: list[_Token] = []
    n = len(expr)
    i = 0
    while i < n:
        ch = expr[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "(":
            tokens.append(_Token("LPAREN", "("))
            i += 1
            continue
        if ch == ")":
            tokens.append(_Token("RPAREN", ")"))
            i += 1
            continue
        if ch == ",":
            tokens.append(_Token("COMMA", ","))
            i += 1
            continue
        if ch == "'":
            i += 1
            buf: list[str] = []
            closed = False
            while i < n:
                if expr[i] == "'":
                    if i + 1 < n and expr[i + 1] == "'":
                        buf.append("'")
                        i += 2
                        continue
                    i += 1
                    closed = True
                    break
                buf.append(expr[i])
                i += 1
            if not closed:
                raise FilterParseError("Unclosed single-quoted string literal in $filter")
            tokens.append(_Token("STRING", "".join(buf)))
            continue
        if ch.isdigit() or (ch == "-" and i + 1 < n and expr[i + 1].isdigit()):
            start = i
            i += 1
            while i < n and (expr[i].isdigit() or expr[i] == "."):
                i += 1
            num_txt = expr[start:i]
            if num_txt.count(".") > 1:
                raise FilterParseError(f"Malformed numeric literal: {num_txt}")
            tokens.append(_Token("NUMBER", num_txt))
            continue
        if ch.isalpha() or ch == "_":
            start = i
            while i < n and (expr[i].isalnum() or expr[i] in {"_", "-"}):
                i += 1
            word = expr[start:i]
            low = word.lower()
            if low in {"true", "false"}:
                tokens.append(_Token("BOOL", low))
            elif low in _CMP_OPS or low in {"and", "or", "not"}:
                tokens.append(_Token("OP", low))
            else:
                tokens.append(_Token("IDENT", word))
            continue
        raise FilterParseError(f"Unexpected character {ch!r} at offset {i} in $filter")
    return tokens


def _coerce_and_validate_literal(prop: EdmPropertySpec, lit_tok: _Token) -> Any:
    et = prop.edm_type
    if et in {"Edm.String", "Edm.Date"}:
        if lit_tok.kind != "STRING":
            raise FilterTypeMismatchError(prop.name, et, lit_tok.value)
        return lit_tok.value
    if et == "Edm.Boolean":
        if lit_tok.kind != "BOOL":
            raise FilterTypeMismatchError(prop.name, et, lit_tok.value)
        return lit_tok.value == "true"
    if et == "Edm.Int32":
        if lit_tok.kind != "NUMBER" or "." in lit_tok.value:
            raise FilterTypeMismatchError(prop.name, et, lit_tok.value)
        return int(lit_tok.value)
    # Edm.Decimal
    if lit_tok.kind != "NUMBER":
        raise FilterTypeMismatchError(prop.name, et, lit_tok.value)
    return float(lit_tok.value)


class _Parser:
    def __init__(self, tokens: list[_Token], props: dict[str, EdmPropertySpec]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.props = props

    def _peek(self) -> _Token | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _consume(self) -> _Token:
        tok = self._peek()
        if tok is None:
            raise FilterParseError("Unexpected end of $filter expression")
        self.pos += 1
        return tok

    def parse(self) -> FilterNode:
        node = self._parse_or()
        if self._peek() is not None:
            nxt = self._peek()
            assert nxt is not None
            raise FilterParseError(f"Unexpected trailing token {nxt.value!r}")
        return node

    def _parse_or(self) -> FilterNode:
        left = self._parse_and()
        while (tok := self._peek()) is not None and tok.kind == "OP" and tok.value == "or":
            self._consume()
            right = self._parse_and()
            left = ("or", left, right)
        return left

    def _parse_and(self) -> FilterNode:
        left = self._parse_not()
        while (tok := self._peek()) is not None and tok.kind == "OP" and tok.value == "and":
            self._consume()
            right = self._parse_not()
            left = ("and", left, right)
        return left

    def _parse_not(self) -> FilterNode:
        tok = self._peek()
        if tok is not None and tok.kind == "OP" and tok.value == "not":
            self._consume()
            return ("not", self._parse_not())
        return self._parse_primary()

    def _check_prop(self, field_name: str) -> EdmPropertySpec:
        prop = self.props.get(field_name)
        if prop is None:
            raise UnknownFilterFieldError(field_name)
        if not prop.filterable:
            raise UnfilterableFieldError(field_name)
        return prop

    def _parse_primary(self) -> FilterNode:
        tok = self._peek()
        if tok is None:
            raise FilterParseError("Expected predicate in $filter")
        if tok.kind == "LPAREN":
            self._consume()
            inner = self._parse_or()
            close = self._consume()
            if close.kind != "RPAREN":
                raise FilterParseError("Expected ')' in $filter")
            return inner

        if tok.kind == "IDENT" and tok.value.lower() in _FUNCS:
            fn_name = self._consume().value.lower()
            if self._consume().kind != "LPAREN":
                raise FilterParseError(f"Expected '(' after {fn_name}")
            fld_tok = self._consume()
            if fld_tok.kind != "IDENT":
                raise FilterParseError(f"Expected field identifier in {fn_name}(...)")
            prop = self._check_prop(fld_tok.value)
            if prop.edm_type != "Edm.String":
                raise FilterTypeMismatchError(prop.name, prop.edm_type, fn_name)
            if self._consume().kind != "COMMA":
                raise FilterParseError(f"Expected ',' in {fn_name}(...)")
            val_tok = self._consume()
            if val_tok.kind != "STRING":
                raise FilterTypeMismatchError(prop.name, prop.edm_type, val_tok.value)
            if self._consume().kind != "RPAREN":
                raise FilterParseError(f"Expected ')' after {fn_name}(...)")
            return ("func", fn_name, prop.name, val_tok.value)

        if tok.kind == "IDENT":
            fld_tok = self._consume()
            prop = self._check_prop(fld_tok.value)
            op_tok = self._consume()
            if op_tok.kind != "OP" or op_tok.value not in _CMP_OPS:
                raise FilterParseError(
                    f"Expected OData comparison operator (eq/ne/gt/ge/lt/le), got {op_tok.value!r}"
                )
            lit_tok = self._consume()
            if lit_tok.kind not in {"STRING", "NUMBER", "BOOL"}:
                raise FilterParseError(f"Expected literal value after {op_tok.value!r}")
            typed_val = _coerce_and_validate_literal(prop, lit_tok)
            return ("cmp", op_tok.value, prop.name, typed_val)

        raise FilterParseError(f"Invalid $filter token {tok.value!r}; expected field or '('")


def parse_odata_filter(expr: str, schema: EntitySetSchema) -> FilterNode:
    """Tokenize, parse, and EDM-typecheck an OData v4 `$filter` string."""
    tokens = _tokenize_odata(expr)
    if not tokens:
        raise FilterParseError("Empty $filter expression")
    props = {p.name: p for p in schema.properties}
    return _Parser(tokens, props).parse()


def evaluate_filter_ast(node: FilterNode, row: dict[str, Any]) -> bool:
    """Evaluate a validated `FilterNode` AST against an entity dictionary."""
    tag = node[0]
    if tag == "and":
        return evaluate_filter_ast(node[1], row) and evaluate_filter_ast(node[2], row)
    if tag == "or":
        return evaluate_filter_ast(node[1], row) or evaluate_filter_ast(node[2], row)
    if tag == "not":
        return not evaluate_filter_ast(node[1], row)
    if tag == "func":
        _, fn_name, field, needle = node
        hay = str(row.get(field, ""))
        if fn_name == "startswith":
            return hay.startswith(needle)
        if fn_name == "endswith":
            return hay.endswith(needle)
        return needle in hay

    _, op, field, rhs = node
    lhs = row.get(field)
    if op == "eq":
        return bool(lhs == rhs)
    if op == "ne":
        return bool(lhs != rhs)
    if op == "gt":
        return bool(lhs > rhs)
    if op == "ge":
        return bool(lhs >= rhs)
    if op == "lt":
        return bool(lhs < rhs)
    return bool(lhs <= rhs)
