"""Hypothesis property-based parity tests & edge-case checks for C++20 OData guardrail kernels."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from erp_odata_mcp.kernels import (
    GENESIS_SEED,
    backend_name,
    benchmark_kernels,
    filter_company_rows,
    scan_filter_security,
    step_audit_hash,
    verify_audit_chain,
)


def test_cpp20_backend_active_and_edge_cases() -> None:
    assert "c++20-native" in backend_name()
    assert filter_company_rows([], [1000]) == ([], 0)
    assert verify_audit_chain([], []) == (True, -1)
    with pytest.raises(ValueError, match="non-negative"):
        filter_company_rows([1000], [1000], top_limit=-1)
    with pytest.raises(ValueError, match="equal length"):
        verify_audit_chain([1], [1, 2])
    nul_scan = scan_filter_security("CompanyCode eq '1000'\x00;drop")
    assert nul_scan.has_injection_pattern is True


@given(
    expr=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'() ;-*$/=",
        max_size=140,
    )
)
@settings(max_examples=120, deadline=None)
def test_hypothesis_parity_scan_filter_security(expr: str) -> None:
    cpp_res = scan_filter_security(expr, use_native=True)
    py_res = scan_filter_security(expr, use_native=False)
    assert cpp_res.paren_balanced == py_res.paren_balanced
    assert cpp_res.max_paren_depth == py_res.max_paren_depth
    assert cpp_res.boolean_clause_count == py_res.boolean_clause_count
    assert cpp_res.has_injection_pattern == py_res.has_injection_pattern
    assert cpp_res.unclosed_quote == py_res.unclosed_quote
    assert cpp_res.cost_score == py_res.cost_score


@pytest.mark.parametrize(
    "malicious",
    [
        "CompanyCode eq '1000'; DROP TABLE",
        "CompanyCode eq '1000' -- comment",
        "CompanyCode eq '1000' /* block */",
        "CompanyCode eq '1000' and __dunder eq 'x'",
        "CompanyCode eq '1000' $batch",
        "CompanyCode eq '1000' or 1 eq 1",
        "Supplier eq 'O''Reilly' and 1 eq 1",
    ],
)
def test_injection_patterns_caught_in_both_backends(malicious: str) -> None:
    assert scan_filter_security(malicious, use_native=True).has_injection_pattern is True
    assert scan_filter_security(malicious, use_native=False).has_injection_pattern is True


@given(
    rows=st.lists(st.integers(min_value=1000, max_value=1005), max_size=120),
    allowed=st.lists(st.integers(min_value=1000, max_value=1005), max_size=4),
    top=st.integers(min_value=0, max_value=50),
    skip=st.integers(min_value=0, max_value=30),
)
@settings(max_examples=100, deadline=None)
def test_hypothesis_parity_filter_company_rows(
    rows: list[int], allowed: list[int], top: int, skip: int
) -> None:
    cpp_out = filter_company_rows(rows, allowed, top_limit=top, skip_offset=skip, use_native=True)
    py_out = filter_company_rows(rows, allowed, top_limit=top, skip_offset=skip, use_native=False)
    assert cpp_out == py_out


@given(
    payloads=st.lists(st.integers(min_value=0, max_value=(1 << 63) - 1), min_size=1, max_size=60),
    tamper_idx=st.integers(min_value=-1, max_value=59),
)
@settings(max_examples=90, deadline=None)
def test_hypothesis_parity_audit_hash_chain(payloads: list[int], tamper_idx: int) -> None:
    chain_cpp: list[int] = []
    chain_py: list[int] = []
    prev_c = GENESIS_SEED
    prev_p = GENESIS_SEED
    for p in payloads:
        prev_c = step_audit_hash(prev_c, p, use_native=True)
        prev_p = step_audit_hash(prev_p, p, use_native=False)
        chain_cpp.append(prev_c)
        chain_py.append(prev_p)
    assert chain_cpp == chain_py

    if 0 <= tamper_idx < len(chain_cpp):
        chain_cpp[tamper_idx] ^= 0x12345

    assert verify_audit_chain(payloads, chain_cpp, use_native=True) == verify_audit_chain(
        payloads, chain_cpp, use_native=False
    )


def test_benchmark_kernels_executes_cleanly() -> None:
    res = benchmark_kernels(num_rows=1000, audit_len=1000)
    assert res["num_rows"] == 1000
    assert float(res["native_ms"]) >= 0.0
