## TEESimulator-RS v4.7: Operation & Attestation Fixes

Tested against [KeyDetector](https://github.com/XiaoTong6666/KeyDetector) and [Key Attestation](https://github.com/nickel-lang/nickel) on OnePlus (Android 16) and Xiaomi Redmi 14C (Android 14).

- **PADDING encoding** — Fixed ASN.1 encoding of PADDING tag in attestation extension from individual `[6] INTEGER` entries to `[6] SET OF INTEGER`, matching AOSP `attestation_record.h` schema. Broke all RSA key attestation since v4.6.
- **Operation error-path conformance** — Software operations now track finalized state and return `INVALID_OPERATION_HANDLE (-28)` on post-abort calls. Input length guard (32KB) returns `TOO_MUCH_DATA` matching AOSP `operation.rs`. Passes KeyDetector's OperationErrorPathChecker.
- **updateAad support** — Added `updateAad` to `SoftwareOperationBinder`, fixing `AbstractMethodError` on Android 16 where the runtime Stub declares it abstract.
- **Algorithm inference** — `createOperation` now infers algorithm from the stored key pair when operation params omit the ALGORITHM tag, matching AOSP behavior.

---

## TEESimulator-RS v4.6: Rebrand & Detection Fix

- **RTT normalization rework** — Replaced Gaussian sleep (mean=55ms) with a 15ms floor fence. The old approach triggered Chunqiu Native Check 2.8 timing analysis; the floor-only approach satisfies the minimum RTT threshold without creating a detectable delay pattern.
- **Cross-algorithm attestation** — Signing algorithm now derived from the attestation key's actual type, not the generated key's algorithm. Fixes BouncyCastle crash when signing RSA keys with EC attestation keys (Shizuku attestation flow).
- **Device ID attestation** — Serial/IMEI/MEID/secondImei tags now flow through to software cert gen instead of blanket rejection. Only DEVICE_UNIQUE_ATTESTATION is rejected, matching AOSP keystore2 policy.
- **Rebrand to TEESimulator-RS** — Distinguishes this fork from upstream. Version scheme simplified to v{major}.{minor}-{commitCount}.
- **CI streamlined** — Release pipeline uses Gradle-generated filenames directly, eliminating the rename step.

---

## TEESimulator v4.5: Detection Hardening

Tested against [KeyDetector](https://github.com/XiaoTong6666/KeyDetector) (23-check attestation validator). All keystore-level checks now pass.

- **Key deletion consistency** — After deleting a software-generated key, `getKeyEntry` now correctly returns `KEY_NOT_FOUND` instead of falling through to a stale live-patch fallback. Fixes binder consistency checks that detect ghost key responses.
- **generateKey timing normalization** — Software key generation RTT now matches real TEE latency profile (Gaussian distribution, mean=55ms, floor=15ms). Previously completed in ~4ms, which is an immediate timing side-channel.
- **Delete cleanup scope** — `deleteKey` now clears all cached state (patched chains, attestation keys) regardless of whether the key was software or hardware-generated.

---

## TEESimulator v4.4: AOSP Conformance

- **Binder error reply format** — Aligned EX_SERVICE_SPECIFIC wire layout with AOSP Status.cpp, including the remote stack trace header field.
- **Key enumeration** — Corrected list_past_alias pagination order to match AOSP database.rs semantics.
- **KeyMetadata fields** — Generated key responses now include modificationTimeMs, Tag.ORIGIN, and normalized KeyDescriptor fields per AOSP Keystore2.
- **Parcel handling** — hasException() preserves reply position for downstream consumers.

---

## TEESimulator v4.3: Performance & Reliability

- **Debug log gating** — `SystemLogger.debug()` now skipped entirely in release builds, eliminating unnecessary logcat syscalls on every intercepted transaction.
- **Supervisor backoff** — Exponential restart delay (500ms → 30s cap) prevents CPU spin if the daemon crashes repeatedly. Resets automatically once stable.
- **Process priority** — Daemon runs at nice=10, yielding CPU to foreground apps on constrained devices.
- **Map eviction** — Rate limiter and file lock maps now evict stale entries instead of growing unbounded.
- **CI pipeline** — Single-trigger build→release pipeline with proper changelog extraction and correctly sized artifacts.

---

## TEESimulator v4.2: Detection Evasion Hardening

Fixes 6 detection vectors flagged by attestation validator apps.

### Attestation Policy Enforcement

Replicate AOSP keystore2's `add_required_parameters()` validation that our software keygen path was bypassing:

- **CREATION_DATETIME** — Reject caller-provided input with `INVALID_ARGUMENT (20)`, matching `security_level.rs:424`. Our cert gen still adds its own timestamp, same as real keystore2.
- **Device ID attestation** — Reject ATTESTATION_ID_SERIAL, IMEI, MEID, SECOND_IMEI, and DEVICE_UNIQUE_ATTESTATION with `CANNOT_ATTEST_IDS (-66)`. No consumer app has READ_PRIVILEGED_PHONE_STATE.
- **Error reply format** — Fixed AIDL ServiceSpecificException parcel write order (was errorCode→message, now message→errorCode).

### Certificate Fix

Leaf certificate Subject CN corrected from "Android KeyStore Key" to "Android Keystore Key" (lowercase s), matching AOSP `KeyGenParameterSpec.java:282`. Both Kotlin and Rust paths.

### Binder Timing

Skip interception for system transaction codes (PING, INTERFACE, DUMP) above LAST_CALL_TRANSACTION. Eliminates the JNI round-trip that inflated binder ping ratio to 3.85x (detector threshold: 3.0x).

---

## TEESimulator v4.1: Boot Identity Persistence

Bugfix release. The vbmeta boot key digest was randomizing on every reboot, producing a different RootOfTrust in attestation certificates each boot.

On devices where the kernel doesn't set `ro.boot.vbmeta.public_key_digest`, the fallback chain hit random generation every boot because `resetprop` overrides for `ro.boot.*` props don't survive reboots. Added file-based persistence (`boot_hash.bin`, `boot_key.bin`) between the TEE cache and random fallback. Once determined, boot identity values persist across reboots.

Verified on Redmi 14C: second boot reads from persistent file instead of regenerating.

---

## TEESimulator v4.0: Native Rust Cert Generation

Major release. Certificate chain generation rebuilt from the ground up in Rust, replacing the BouncyCastle Java path for EC and RSA keys. Hardened against every known detector app.

### Native Cert Generation

The headline feature. `libcertgen.so` generates X.509 certificate chains using `ring` (EC-P256/P384) and `rsa` (RSA-2048/4096) with manual DER assembly. No more BouncyCastle quirks — issuer/subject DN bytes are injected directly from the keybox, ensuring byte-perfect chain linkage. BouncyCastle remains as fallback for unsupported curves (P-224, P-521, Curve25519).

### Anti-Detection Hardening

- **Challenge validation** — Oversized attestation challenges (>128 bytes) now return `INVALID_INPUT_LENGTH (-21)`, matching real KeyMint behavior. Previously accepted silently — DuckDetector exploited this.
- **Per-UID rate limiter** — 2 hardware keygens per 30s burst, 2 concurrent max. Overflow falls back to software certs. Blocks DuckDetector-style keygen flooding that starves GMS.
- **importKey eviction guard** — Retained patch chains prevent generate-then-import attacks that evict cached attestation data.
- **256KB native payload cap** — Oversized binder payloads bypass interception cleanly instead of stalling threads.
- **Alias size rejection** — Oversized key aliases rejected before they hit the binder buffer.

### Key Persistence

Generated keys now survive reboots. File-backed storage with file-level locking, preserved across keybox rotations. Banking and biometric apps that cache attestation keys no longer break after restart.

### Attestation Fixes

- Null out all-zero `verifiedBootHash` from TEE cache (fingerprinting vector)
- Correct `module_hash` field to match AOSP Keystore2 format
- Override pre-existing attest keys instead of skipping them
- Strip HTML comments from PEM blocks in keybox parsing
- Security patch consistency — `system=prop` forces boot/vendor to match

### Module Lifecycle

- Supervisor daemon keeps the interceptor alive
- KSU Action button clears persistent key cache
- Clean uninstall removes all traces (persistent keys, TEE status, daemon)

### Stability

- FileObserver NPE on config deletion fixed
- Global uncaught exception handler — daemon stays alive on unexpected errors
- PEM parsing hardened against malformed keybox files

### Tested Against

DuckDetector, Luna, Play Integrity, Key Attestation Demo — all passing on Redmi 14C (Android 14, Beanpod KeyMaster, KSU).
