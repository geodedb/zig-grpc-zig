//! RFC 7519 JSON Web Token (JWT) implementation for the gRPC-zig server.
//!
//! Closes A3 + M3:
//!   * A3 — replaces the placeholder dot-separated string format with the
//!     canonical RFC 7519 layout:
//!         base64url(json_header) "." base64url(json_payload) "." base64url(hmac_sha256)
//!     Header: {"alg":"HS256","typ":"JWT"}
//!     Payload: {"sub":"<subject>","exp":<unix_seconds>,"iat":<unix_seconds>,"nbf":<unix_seconds_optional>}
//!   * M3 — verify the HMAC with `std.crypto.timing_safe.eql` so signature
//!     comparison runs in constant time and resists timing oracles.
//!
//! All segments are base64url-encoded with NO padding (`std.base64.url_safe_no_pad`),
//! per RFC 7515 §3 and the JWT spec.
//!
//! Supported algorithms: HS256 only. Anything else returns `InvalidToken`.

const std = @import("std");
const crypto = std.crypto;
const compat = @import("../compat.zig");
const crypto_backend = @import("crypto_backend");

// fips-exempt: compile-time mac_length only; the HMAC computation goes through
// the seam (crypto_backend.Mac).
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const b64url = std.base64.url_safe_no_pad;

pub const AuthError = error{
    /// Generic invalid-token sentinel for cases that aren't covered by the
    /// more specific errors below (e.g. wrong `alg`/`typ`).
    InvalidToken,
    /// Token is structurally invalid: not three segments, segment is not
    /// valid base64url, or JSON parse failed.
    MalformedToken,
    /// HMAC signature does not match the recomputed value.
    InvalidSignature,
    /// `exp` claim is in the past.
    TokenExpired,
    /// `nbf` claim is in the future.
    TokenNotYetValid,
    /// Generic permission-denied sentinel for callers that combine the auth
    /// gate with their own authorization rules.
    Unauthorized,
};

/// Decoded JWT claims returned by `Auth.verifyToken`. The caller owns the
/// `sub` slice (allocated via the Auth's allocator) and must free it.
pub const Claims = struct {
    sub: []u8,
    iat: i64,
    exp: i64,
    nbf: ?i64 = null,
};

pub const Auth = struct {
    secret_key: []const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, secret_key: []const u8) Auth {
        return .{
            .allocator = allocator,
            .secret_key = secret_key,
        };
    }

    /// Generate an RFC 7519 HS256 JWT for `subject`. `expires_in` is
    /// seconds-from-now (negative values are allowed; they yield a
    /// pre-expired token, which is useful for tests).
    ///
    /// Returns a freshly-allocated UTF-8 token string. Caller must free
    /// with `self.allocator`.
    pub fn generateToken(self: *Auth, subject: []const u8, expires_in: i64) ![]u8 {
        const now = compat.timestamp();
        const exp = now + expires_in;

        // Header — fixed for HS256.
        const header_json =
            \\{"alg":"HS256","typ":"JWT"}
        ;
        const header_b64 = try b64Encode(self.allocator, header_json);
        defer self.allocator.free(header_b64);

        // Payload — JSON-stringify a typed struct so we get correct escaping
        // for any subject string the caller hands us.
        const Payload = struct {
            sub: []const u8,
            iat: i64,
            exp: i64,
        };
        const payload_json = try std.json.Stringify.valueAlloc(
            self.allocator,
            Payload{ .sub = subject, .iat = now, .exp = exp },
            .{},
        );
        defer self.allocator.free(payload_json);

        const payload_b64 = try b64Encode(self.allocator, payload_json);
        defer self.allocator.free(payload_b64);

        // Signing input: "<header_b64>.<payload_b64>".
        const signing_input = try std.fmt.allocPrint(
            self.allocator,
            "{s}.{s}",
            .{ header_b64, payload_b64 },
        );
        defer self.allocator.free(signing_input);

        var mac: [HmacSha256.mac_length]u8 = undefined;
        // FIPS-0007: HS256 JWT signature HMAC-SHA256 via the seam.
        _ = crypto_backend.Mac.hmac(.sha256, self.secret_key, signing_input, &mac) catch return AuthError.InvalidToken;

        const sig_b64 = try b64Encode(self.allocator, &mac);
        defer self.allocator.free(sig_b64);

        return try std.fmt.allocPrint(
            self.allocator,
            "{s}.{s}.{s}",
            .{ header_b64, payload_b64, sig_b64 },
        );
    }

    /// Verify an RFC 7519 HS256 JWT and return its claims.
    ///
    /// Validation order:
    ///   1. Token has exactly three segments separated by '.' (else MalformedToken).
    ///   2. Header decodes to {alg:"HS256", typ:"JWT"} (else InvalidToken).
    ///   3. Payload decodes successfully (else MalformedToken).
    ///   4. Signature recomputed over `<header_b64>.<payload_b64>` and
    ///      compared with `std.crypto.timing_safe.eql` (else InvalidSignature).
    ///      The comparison happens BEFORE the time-window checks so a
    ///      forged token with a valid-looking exp/nbf can't even reveal
    ///      "would have been accepted if signed."
    ///   5. `exp` not in the past (else TokenExpired).
    ///   6. `nbf` not in the future (else TokenNotYetValid).
    ///
    /// Caller owns the returned `Claims.sub`.
    pub fn verifyToken(self: *Auth, token: []const u8) AuthError!Claims {
        // (1) Three-segment structure.
        const first_dot = std.mem.indexOfScalar(u8, token, '.') orelse
            return AuthError.MalformedToken;
        const second_dot = std.mem.indexOfScalarPos(u8, token, first_dot + 1, '.') orelse
            return AuthError.MalformedToken;
        // Reject tokens with a *third* dot.
        if (std.mem.indexOfScalarPos(u8, token, second_dot + 1, '.')) |_| {
            return AuthError.MalformedToken;
        }

        const header_b64 = token[0..first_dot];
        const payload_b64 = token[first_dot + 1 .. second_dot];
        const sig_b64 = token[second_dot + 1 ..];
        if (header_b64.len == 0 or payload_b64.len == 0 or sig_b64.len == 0) {
            return AuthError.MalformedToken;
        }

        // (2) Decode + validate header.
        const header_bytes = b64Decode(self.allocator, header_b64) catch
            return AuthError.MalformedToken;
        defer self.allocator.free(header_bytes);

        const HeaderJson = struct {
            alg: []const u8,
            typ: []const u8 = "JWT",
        };
        const header_parsed = std.json.parseFromSlice(
            HeaderJson,
            self.allocator,
            header_bytes,
            .{ .ignore_unknown_fields = true },
        ) catch return AuthError.MalformedToken;
        defer header_parsed.deinit();

        if (!std.mem.eql(u8, header_parsed.value.alg, "HS256")) {
            return AuthError.InvalidToken;
        }
        if (!std.mem.eql(u8, header_parsed.value.typ, "JWT")) {
            return AuthError.InvalidToken;
        }

        // (4) Recompute and constant-time-compare HMAC.
        const signing_input_len = first_dot + 1 + (second_dot - first_dot - 1);
        const signing_input = token[0..signing_input_len]; // header_b64 . payload_b64

        var expected_mac: [HmacSha256.mac_length]u8 = undefined;
        // FIPS-0007: HS256 JWT verify HMAC-SHA256 via the seam.
        _ = crypto_backend.Mac.hmac(.sha256, self.secret_key, signing_input, &expected_mac) catch return AuthError.InvalidSignature;

        const provided_sig = b64Decode(self.allocator, sig_b64) catch
            return AuthError.MalformedToken;
        defer self.allocator.free(provided_sig);

        if (provided_sig.len != HmacSha256.mac_length) {
            return AuthError.InvalidSignature;
        }
        var provided_arr: [HmacSha256.mac_length]u8 = undefined;
        @memcpy(&provided_arr, provided_sig);
        // fips-exempt: non-security-algorithm — constant-time tag compare.
        if (!crypto.timing_safe.eql([HmacSha256.mac_length]u8, expected_mac, provided_arr)) {
            return AuthError.InvalidSignature;
        }

        // (3) Now (and only now) parse the payload claims. Doing this
        // after signature verification keeps an attacker from learning
        // anything about the parser through pre-signature errors.
        const payload_bytes = b64Decode(self.allocator, payload_b64) catch
            return AuthError.MalformedToken;
        defer self.allocator.free(payload_bytes);

        const PayloadJson = struct {
            sub: []const u8,
            iat: i64,
            exp: i64,
            nbf: ?i64 = null,
        };
        const payload_parsed = std.json.parseFromSlice(
            PayloadJson,
            self.allocator,
            payload_bytes,
            .{ .ignore_unknown_fields = true },
        ) catch return AuthError.MalformedToken;
        defer payload_parsed.deinit();

        // (5) (6) Time-window checks.
        const now = compat.timestamp();
        if (payload_parsed.value.exp <= now) return AuthError.TokenExpired;
        if (payload_parsed.value.nbf) |nbf| {
            if (nbf > now) return AuthError.TokenNotYetValid;
        }

        // Caller owns sub; the Parsed handle goes out of scope here so we
        // dupe it onto the auth allocator.
        const sub_owned = self.allocator.dupe(u8, payload_parsed.value.sub) catch
            return AuthError.MalformedToken;

        return .{
            .sub = sub_owned,
            .iat = payload_parsed.value.iat,
            .exp = payload_parsed.value.exp,
            .nbf = payload_parsed.value.nbf,
        };
    }
};

/// base64url-no-pad encode `data` into a freshly-allocated slice owned by
/// the caller.
fn b64Encode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const enc_len = b64url.Encoder.calcSize(data.len);
    const out = try allocator.alloc(u8, enc_len);
    errdefer allocator.free(out);
    _ = b64url.Encoder.encode(out, data);
    return out;
}

/// base64url-no-pad decode `data` into a freshly-allocated slice owned by
/// the caller. Returns `error.MalformedToken`-equivalent on bad input by
/// surfacing the underlying decode error to the caller.
fn b64Decode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const dec_len = try b64url.Decoder.calcSizeForSlice(data);
    const out = try allocator.alloc(u8, dec_len);
    errdefer allocator.free(out);
    try b64url.Decoder.decode(out, data);
    return out;
}
