"""C++20 ctypes bridge (`-O3 -std=c++20`) + bit-exact pure-Python reference twins."""

from __future__ import annotations

import array
import ctypes
import hashlib
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from erp_odata_mcp.types import FilterSecurityScan

GENESIS_SEED: int = 0x4F444154414D4350  # "ODATAMCP"
_MASK64: int = (1 << 64) - 1


def _splitmix64_py(x: int) -> int:
    x = (x + 0x9E3779B97F4A7C15) & _MASK64
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & _MASK64
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & _MASK64
    return (x ^ (x >> 31)) & _MASK64


def _compile_native_lib() -> tuple[ctypes.CDLL | None, str]:
    src_path = Path(__file__).resolve().parents[3] / "csrc" / "odata_guard_kernels.cpp"
    compiler = shutil.which("clang++") or shutil.which("g++")
    if not src_path.exists() or compiler is None:
        return None, "python-fallback"

    digest = hashlib.sha256(src_path.read_bytes()).hexdigest()[:16]
    out_dir = Path(tempfile.gettempdir()) / "erp_odata_mcp_native_cache"
    out_dir.mkdir(parents=True, exist_ok=True)
    ext = ".dylib" if Path("/System/Library").exists() else ".so"
    lib_path = out_dir / f"libodata_guard_{digest}{ext}"

    if not lib_path.exists():
        cmd = [
            compiler,
            "-O3",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-shared",
            "-fPIC",
            str(src_path),
            "-o",
            str(lib_path),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return None, "python-fallback"

    lib = ctypes.CDLL(str(lib_path))
    i32p = ctypes.POINTER(ctypes.c_int32)
    u64p = ctypes.POINTER(ctypes.c_uint64)

    lib.odata_scan_filter_security.argtypes = [ctypes.c_char_p, ctypes.c_int32, i32p]
    lib.odata_scan_filter_security.restype = ctypes.c_int32

    lib.odata_filter_company_rows.argtypes = [
        ctypes.c_int32,
        i32p,
        i32p,
        ctypes.c_int32,
        ctypes.c_int32,
        ctypes.c_int32,
        i32p,
        i32p,
    ]
    lib.odata_filter_company_rows.restype = ctypes.c_int32

    lib.odata_verify_audit_chain.argtypes = [ctypes.c_int32, u64p, u64p, i32p]
    lib.odata_verify_audit_chain.restype = ctypes.c_int32

    lib.odata_step_audit_hash.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
    lib.odata_step_audit_hash.restype = ctypes.c_uint64

    return lib, f"c++20-native ({Path(compiler).name} -O3)"


_NATIVE_LIB, _BACKEND_NAME = _compile_native_lib()


def backend_name() -> str:
    """Return active C++20/Python kernel backend label."""
    return _BACKEND_NAME


def _is_ident_byte(b: int) -> bool:
    return (97 <= b <= 122) or (65 <= b <= 90) or (48 <= b <= 57) or b == 95


def _to_lower_byte(b: int) -> int:
    return b + 32 if 65 <= b <= 90 else b


def _scan_filter_python(raw: bytes) -> tuple[bool, int, int, bool, bool, int]:
    n = len(raw)
    depth = 0
    max_depth = 0
    balanced = True
    in_quote = False
    clauses = 1 if n > 0 else 0
    injection = False

    i = 0
    while i < n:
        b = raw[i]
        if in_quote:
            if b == 39:  # '\''
                if i + 1 < n and raw[i + 1] == 39:
                    i += 2
                    continue
                in_quote = False
            i += 1
            continue

        if b == 39:
            in_quote = True
            i += 1
            continue
        if b == 40:  # '('
            depth += 1
            if depth > max_depth:
                max_depth = depth
            i += 1
            continue
        if b == 41:  # ')'
            depth -= 1
            if depth < 0:
                balanced = False
            i += 1
            continue

        if b == 59:  # ';'
            injection = True
        if b == 45 and i + 1 < n and raw[i + 1] == 45:  # '--'
            injection = True
        if b == 47 and i + 1 < n and raw[i + 1] == 42:  # '/*'
            injection = True
        if b == 95 and i + 1 < n and raw[i + 1] == 95:  # '__'
            injection = True
        if b == 36 and i + 6 <= n:  # '$batch'
            sub = bytes(_to_lower_byte(x) for x in raw[i + 1 : i + 6])
            if sub == b"batch":
                injection = True
        if b == 49 and (i == 0 or not _is_ident_byte(raw[i - 1])) and i + 6 <= n:
            if (
                raw[i + 1] == 32
                and _to_lower_byte(raw[i + 2]) == 101
                and _to_lower_byte(raw[i + 3]) == 113
                and raw[i + 4] == 32
                and raw[i + 5] == 49
                and (i + 6 == n or not _is_ident_byte(raw[i + 6]))
            ):
                injection = True

        prev_sep = (i == 0) or (not _is_ident_byte(raw[i - 1]))
        if prev_sep:
            if (
                i + 3 <= n
                and _to_lower_byte(raw[i]) == 97
                and _to_lower_byte(raw[i + 1]) == 110
                and _to_lower_byte(raw[i + 2]) == 100
                and (i + 3 == n or not _is_ident_byte(raw[i + 3]))
            ):
                clauses += 1
            elif (
                i + 2 <= n
                and _to_lower_byte(raw[i]) == 111
                and _to_lower_byte(raw[i + 1]) == 114
                and (i + 2 == n or not _is_ident_byte(raw[i + 2]))
            ):
                clauses += 1
        i += 1

    if depth != 0:
        balanced = False
    cost = clauses * 10 + max_depth * 15 + (n // 16)
    return balanced, max_depth, clauses, injection, in_quote, cost


def scan_filter_security(filter_expr: str | None, *, use_native: bool = True) -> FilterSecurityScan:
    """Scan an OData v4 `$filter` expression for nesting, clause count, and injection smuggling."""
    raw = (filter_expr or "").encode("utf-8")
    # Embedded NUL bytes would truncate C strings; reject via Python path or flag injection
    if b"\x00" in raw:
        bal, md, cl, _, uq, cost = _scan_filter_python(raw.replace(b"\x00", b";"))
        return FilterSecurityScan(
            paren_balanced=bal,
            max_paren_depth=md,
            boolean_clause_count=cl,
            has_injection_pattern=True,
            unclosed_quote=uq,
            cost_score=cost,
            backend=_BACKEND_NAME if use_native else "python-fallback",
        )

    if use_native and _NATIVE_LIB is not None:
        out_arr = array.array("i", [0] * 6)
        out_ptr = ctypes.cast(
            ctypes.c_void_p(out_arr.buffer_info()[0]), ctypes.POINTER(ctypes.c_int32)
        )
        rc = _NATIVE_LIB.odata_scan_filter_security(raw, len(raw), out_ptr)
        if rc == 0:
            return FilterSecurityScan(
                paren_balanced=bool(out_arr[0]),
                max_paren_depth=int(out_arr[1]),
                boolean_clause_count=int(out_arr[2]),
                has_injection_pattern=bool(out_arr[3]),
                unclosed_quote=bool(out_arr[4]),
                cost_score=int(out_arr[5]),
                backend=_BACKEND_NAME,
            )

    bal, md, cl, inj, uq, cost = _scan_filter_python(raw)
    return FilterSecurityScan(
        paren_balanced=bal,
        max_paren_depth=md,
        boolean_clause_count=cl,
        has_injection_pattern=inj,
        unclosed_quote=uq,
        cost_score=cost,
        backend="python-fallback",
    )


def _filter_company_rows_python(
    row_bukrs: list[int],
    allowed_bukrs: list[int],
    top_limit: int,
    skip_offset: int,
) -> tuple[list[int], int]:
    allowed_set = set(allowed_bukrs)
    denied = 0
    matched_seen = 0
    selected: list[int] = []
    for idx, code in enumerate(row_bukrs):
        if code not in allowed_set:
            denied += 1
            continue
        if matched_seen >= skip_offset and len(selected) < top_limit:
            selected.append(idx)
        matched_seen += 1
    return selected, denied


def filter_company_rows(
    row_bukrs: list[int],
    allowed_bukrs: list[int],
    *,
    top_limit: int = 50,
    skip_offset: int = 0,
    use_native: bool = True,
) -> tuple[list[int], int]:
    """Filter row indices by authorized SAP `BUKRS` company codes + `$skip`/`$top` pagination."""
    if top_limit < 0 or skip_offset < 0:
        raise ValueError("top_limit and skip_offset must be non-negative")
    n = len(row_bukrs)
    if n == 0:
        return [], 0
    if use_native and _NATIVE_LIB is not None:
        rb = array.array("i", row_bukrs)
        ab = array.array("i", allowed_bukrs if allowed_bukrs else [0])
        out_sel = array.array("i", [0] * max(1, min(n, top_limit)))
        out_den = ctypes.c_int32(0)
        i32p = ctypes.POINTER(ctypes.c_int32)
        cnt = _NATIVE_LIB.odata_filter_company_rows(
            n,
            ctypes.cast(ctypes.c_void_p(rb.buffer_info()[0]), i32p),
            ctypes.cast(ctypes.c_void_p(ab.buffer_info()[0]), i32p),
            len(allowed_bukrs),
            top_limit,
            skip_offset,
            ctypes.cast(ctypes.c_void_p(out_sel.buffer_info()[0]), i32p),
            ctypes.byref(out_den),
        )
        if cnt >= 0:
            return out_sel[:cnt].tolist(), int(out_den.value)
    return _filter_company_rows_python(row_bukrs, allowed_bukrs, top_limit, skip_offset)


def step_audit_hash(prev_chain: int, payload_hash: int, *, use_native: bool = True) -> int:
    """Compute next 64-bit SplitMix64 audit chain digest."""
    p_u64 = prev_chain & _MASK64
    h_u64 = payload_hash & _MASK64
    if use_native and _NATIVE_LIB is not None:
        return int(_NATIVE_LIB.odata_step_audit_hash(p_u64, h_u64))
    return _splitmix64_py(p_u64 ^ h_u64)


def verify_audit_chain(
    payload_hashes: list[int],
    recorded_chain: list[int],
    *,
    use_native: bool = True,
) -> tuple[bool, int]:
    """Verify full SplitMix64 audit chain returning `(is_valid, first_tampered_index)`."""
    if len(payload_hashes) != len(recorded_chain):
        raise ValueError("payload_hashes and recorded_chain must have equal length")
    n = len(payload_hashes)
    if n == 0:
        return True, -1
    if use_native and _NATIVE_LIB is not None:
        ph = array.array("Q", [x & _MASK64 for x in payload_hashes])
        rc_arr = array.array("Q", [x & _MASK64 for x in recorded_chain])
        first_bad = ctypes.c_int32(-1)
        u64p = ctypes.POINTER(ctypes.c_uint64)
        ok = _NATIVE_LIB.odata_verify_audit_chain(
            n,
            ctypes.cast(ctypes.c_void_p(ph.buffer_info()[0]), u64p),
            ctypes.cast(ctypes.c_void_p(rc_arr.buffer_info()[0]), u64p),
            ctypes.byref(first_bad),
        )
        if ok >= 0:
            return bool(ok == 1), int(first_bad.value)

    prev = GENESIS_SEED
    for idx, h in enumerate(payload_hashes):
        exp = _splitmix64_py(prev ^ (h & _MASK64))
        if (recorded_chain[idx] & _MASK64) != exp:
            return False, idx
        prev = exp
    return True, -1


def benchmark_kernels(
    num_rows: int = 20000, audit_len: int = 25000
) -> dict[str, float | int | str]:
    """Benchmark C++20 OData `$filter` scan + BUKRS row RBAC + audit chain vs pure Python."""
    sample_filter = (
        "(CompanyCode eq '1000' or CompanyCode eq '2000') and GrossAmount ge 5000 "
        "and ReleaseStatus eq 'APPROVED' and Currency eq 'AED'"
    )
    raw_filter = sample_filter.encode("utf-8")
    row_bukrs = [1000 if (i % 3 == 0) else (2000 if i % 5 == 0 else 3000) for i in range(num_rows)]
    allowed = [1000, 2000]

    payloads = [(i * 0x517CC1B727220A95 + 17) & _MASK64 for i in range(audit_len)]
    chain: list[int] = []
    cur = GENESIS_SEED
    for p in payloads:
        cur = _splitmix64_py(cur ^ p)
        chain.append(cur)

    if _NATIVE_LIB is not None:
        rb = array.array("i", row_bukrs)
        ab = array.array("i", allowed)
        out_sel = array.array("i", [0] * 200)
        out_den = ctypes.c_int32(0)
        out_m = array.array("i", [0] * 6)
        ph = array.array("Q", payloads)
        rc_a = array.array("Q", chain)
        first_bad = ctypes.c_int32(-1)
        i32p = ctypes.POINTER(ctypes.c_int32)
        u64p = ctypes.POINTER(ctypes.c_uint64)

        rb_p = ctypes.cast(ctypes.c_void_p(rb.buffer_info()[0]), i32p)
        ab_p = ctypes.cast(ctypes.c_void_p(ab.buffer_info()[0]), i32p)
        sel_p = ctypes.cast(ctypes.c_void_p(out_sel.buffer_info()[0]), i32p)
        m_p = ctypes.cast(ctypes.c_void_p(out_m.buffer_info()[0]), i32p)
        ph_p = ctypes.cast(ctypes.c_void_p(ph.buffer_info()[0]), u64p)
        rc_p = ctypes.cast(ctypes.c_void_p(rc_a.buffer_info()[0]), u64p)

        t0 = time.perf_counter()
        for _ in range(30):
            _NATIVE_LIB.odata_scan_filter_security(raw_filter, len(raw_filter), m_p)
            _NATIVE_LIB.odata_filter_company_rows(
                num_rows, rb_p, ab_p, len(allowed), 200, 0, sel_p, ctypes.byref(out_den)
            )
            _NATIVE_LIB.odata_verify_audit_chain(audit_len, ph_p, rc_p, ctypes.byref(first_bad))
        native_ms = ((time.perf_counter() - t0) * 1000.0) / 30.0
    else:  # pragma: no cover
        native_ms = 0.0

    t1 = time.perf_counter()
    for _ in range(30):
        _scan_filter_python(raw_filter)
        _filter_company_rows_python(row_bukrs, allowed, 200, 0)
        prev = GENESIS_SEED
        for idx, p in enumerate(payloads):
            exp = _splitmix64_py(prev ^ p)
            if chain[idx] != exp:
                break
            prev = exp
    python_ms = ((time.perf_counter() - t1) * 1000.0) / 30.0

    return {
        "backend": _BACKEND_NAME,
        "num_rows": num_rows,
        "audit_records": audit_len,
        "native_ms": round(native_ms, 3),
        "python_ms": round(python_ms, 3),
        "speedup_x": round(python_ms / max(native_ms, 1e-6), 2),
    }
