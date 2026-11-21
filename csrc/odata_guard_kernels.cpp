// Native C++20 OData v4 $filter security scanner, BUKRS row-level RBAC filter & SplitMix64 audit verifier.
#include <cctype>
#include <cstdint>
#include <cstring>

namespace {

inline char to_lower_ascii(char c) noexcept {
    if (c >= 'A' && c <= 'Z') {
        return static_cast<char>(c - 'A' + 'a');
    }
    return c;
}

inline bool is_ident_char(char c) noexcept {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

inline uint64_t splitmix64(uint64_t x) noexcept {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30U)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27U)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31U);
}

}  // namespace

extern "C" {

// out_metrics[6]:
//   [0] paren_balanced (1 or 0)
//   [1] max_paren_depth
//   [2] boolean_clause_count
//   [3] has_injection_pattern (1 or 0)
//   [4] unclosed_quote (1 or 0)
//   [5] cost_score
int32_t odata_scan_filter_security(
    const char* filter_str,
    int32_t len,
    int32_t* out_metrics
) {
    if (filter_str == nullptr || out_metrics == nullptr || len < 0) {
        return -1;
    }

    int32_t depth = 0;
    int32_t max_depth = 0;
    bool balanced = true;
    bool in_quote = false;
    int32_t clauses = (len > 0) ? 1 : 0;
    bool injection = false;

    for (int32_t i = 0; i < len; ++i) {
        char c = filter_str[i];
        if (in_quote) {
            if (c == '\'') {
                // OData escapes single quote as doubled ''
                if (i + 1 < len && filter_str[i + 1] == '\'') {
                    ++i;
                } else {
                    in_quote = false;
                }
            }
            continue;
        }

        if (c == '\'') {
            in_quote = true;
            continue;
        }
        if (c == '(') {
            ++depth;
            if (depth > max_depth) {
                max_depth = depth;
            }
            continue;
        }
        if (c == ')') {
            --depth;
            if (depth < 0) {
                balanced = false;
            }
            continue;
        }

        // Smuggling / comment / batch-boundary markers outside string literals
        if (c == ';') {
            injection = true;
        }
        if (c == '-' && i + 1 < len && filter_str[i + 1] == '-') {
            injection = true;
        }
        if (c == '/' && i + 1 < len && filter_str[i + 1] == '*') {
            injection = true;
        }
        if (c == '_' && i + 1 < len && filter_str[i + 1] == '_') {
            injection = true;
        }
        if (c == '$' && i + 5 <= len) {
            if (to_lower_ascii(filter_str[i + 1]) == 'b' &&
                to_lower_ascii(filter_str[i + 2]) == 'a' &&
                to_lower_ascii(filter_str[i + 3]) == 't' &&
                to_lower_ascii(filter_str[i + 4]) == 'c' &&
                (i + 5 < len && to_lower_ascii(filter_str[i + 5]) == 'h')) {
                injection = true;
            }
        }
        // Classic numeric tautology: `1 eq 1` at word boundaries
        if (c == '1' && (i == 0 || !is_ident_char(filter_str[i - 1])) && i + 6 <= len) {
            if (filter_str[i + 1] == ' ' &&
                to_lower_ascii(filter_str[i + 2]) == 'e' &&
                to_lower_ascii(filter_str[i + 3]) == 'q' &&
                filter_str[i + 4] == ' ' &&
                filter_str[i + 5] == '1' &&
                (i + 6 == len || !is_ident_char(filter_str[i + 6]))) {
                injection = true;
            }
        }

        // Standalone logical `and` / `or` outside quotes
        bool prev_sep = (i == 0) || !is_ident_char(filter_str[i - 1]);
        if (prev_sep) {
            if (i + 3 <= len &&
                to_lower_ascii(filter_str[i]) == 'a' &&
                to_lower_ascii(filter_str[i + 1]) == 'n' &&
                to_lower_ascii(filter_str[i + 2]) == 'd' &&
                (i + 3 == len || !is_ident_char(filter_str[i + 3]))) {
                ++clauses;
            } else if (i + 2 <= len &&
                       to_lower_ascii(filter_str[i]) == 'o' &&
                       to_lower_ascii(filter_str[i + 1]) == 'r' &&
                       (i + 2 == len || !is_ident_char(filter_str[i + 2]))) {
                ++clauses;
            }
        }
    }

    if (depth != 0) {
        balanced = false;
    }

    out_metrics[0] = balanced ? 1 : 0;
    out_metrics[1] = max_depth;
    out_metrics[2] = clauses;
    out_metrics[3] = injection ? 1 : 0;
    out_metrics[4] = in_quote ? 1 : 0;
    out_metrics[5] = clauses * 10 + max_depth * 15 + (len / 16);
    return 0;
}

int32_t odata_filter_company_rows(
    int32_t num_rows,
    const int32_t* row_bukrs_codes,
    const int32_t* allowed_bukrs,
    int32_t num_allowed,
    int32_t top_limit,
    int32_t skip_offset,
    int32_t* out_selected_indices,
    int32_t* out_denied_count
) {
    if (num_rows < 0 || num_allowed < 0 || top_limit < 0 || skip_offset < 0 ||
        row_bukrs_codes == nullptr || allowed_bukrs == nullptr ||
        out_selected_indices == nullptr || out_denied_count == nullptr) {
        return -1;
    }

    int32_t denied = 0;
    int32_t matched_seen = 0;
    int32_t selected = 0;

    for (int32_t i = 0; i < num_rows; ++i) {
        int32_t code = row_bukrs_codes[i];
        bool ok = false;
        for (int32_t j = 0; j < num_allowed; ++j) {
            if (allowed_bukrs[j] == code) {
                ok = true;
                break;
            }
        }
        if (!ok) {
            ++denied;
            continue;
        }
        if (matched_seen >= skip_offset && selected < top_limit) {
            out_selected_indices[selected] = i;
            ++selected;
        }
        ++matched_seen;
    }

    *out_denied_count = denied;
    return selected;
}

int32_t odata_verify_audit_chain(
    int32_t num_records,
    const uint64_t* payload_hashes,
    const uint64_t* recorded_chain,
    int32_t* out_first_tampered
) {
    if (num_records < 0 || payload_hashes == nullptr ||
        recorded_chain == nullptr || out_first_tampered == nullptr) {
        return -1;
    }

    uint64_t prev = 0x4f444154414d4350ULL;  // "ODATAMCP" genesis seed
    for (int32_t i = 0; i < num_records; ++i) {
        uint64_t expected = splitmix64(prev ^ payload_hashes[i]);
        if (recorded_chain[i] != expected) {
            *out_first_tampered = i;
            return 0;
        }
        prev = expected;
    }
    *out_first_tampered = -1;
    return 1;
}

uint64_t odata_step_audit_hash(uint64_t prev_chain, uint64_t payload_hash) {
    return splitmix64(prev_chain ^ payload_hash);
}

}  // extern "C"
