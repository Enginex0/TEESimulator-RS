## TEESimulator-RS v5.1: Interception Architecture Rewrite

Major release. 27 files changed, 2300 lines rewritten. The entire Kotlin interception layer has been rebuilt with a clean architecture, proper AIDL alignment, and significantly lower binder overhead.

### Interception Layer Rewrite
- KeyMintSecurityLevelInterceptor completely restructured: GeneratedKeyInfo now carries full KeyMintAttestation instead of nullable stub, eliminating scattered null checks across every operation path
- SoftwareOperation rewritten with sealed CryptoPrimitive interface separating Signer, Verifier, Encryptor, and Decryptor into isolated implementations with proper JCA algorithm mapping
- KeystoreErrorCode centralized object replaces scattered magic numbers for all KeyMint and Keystore2 error codes
- listEntries moved from pre-transact parameter caching to post-transact injection, eliminating a race condition where cached params could go stale
- deleteKey now handles both APP domain (by alias) and KEY_ID domain (by nspace) resolution paths correctly
- AuthorizeCreate and AndroidPermissionUtils removed, authorization logic consolidated into the operation dispatch path
- DeviceAttestationService removed, attestation routing simplified into the main interceptor

### Software Crypto Operations
- GCM nonce returned in CreateOperationResponse.parameters for encrypt operations, matching real KeyMint HAL behavior
- updateAad correctly throws INVALID_TAG on non-AEAD operations instead of silently succeeding
- Cipher algorithm mapping cleaned up: dropped CTR block mode and RSA_PKCS1_1_5_SIGN padding that caused JCA provider mismatches
- All crypto exceptions wrapped as ServiceSpecificException with correct KeyMint error codes instead of raw exceptions

### Attestation & Certificate Generation
- CertificateGenerator rewritten with clean Kotlin Pair return type instead of Android's util.Pair
- AttestationBuilder field ordering aligned with AOSP KeyDescription ASN.1 schema
- Unique ID computation follows KeyMint HAL spec: HMAC-SHA256(temporal_counter || AAID || reset_flag, HBK) truncated to 128 bits
- Patch level logging removed from hot path to reduce logcat noise on every attestation

### Configuration & Device Properties
- ConfigurationManager target package parsing refactored: mode/package extraction deduplicated across GENERATE/PATCH/AUTO branches
- system=prop forced boot/vendor override removed, now respects explicit per-component patch level configuration
- FileObserver delete handler simplified with direct file access instead of defensive null-checks
- AndroidDeviceUtils expanded with additional device property accessors for attestation fields

### Binder Performance
- Safe parcel reads at 6 deserialization sites, replacing force-unwrap NPE paths with early-return on null. A single NPE generates a full stack trace that blocks the binder thread for ~2ms
- teeResponses cache populated on generateKey/importKey post-transact, reducing getKeyEntry from 2+ binder round-trips to 1
- pingBinder liveness check removed from pre-transact failure path, eliminating a synchronous IPC call on every failed transaction
- Native transaction code filtering at C++ level, skipping JNI entirely for PING/INTERFACE/DUMP

### Dynamic SecurityLevel Binder Registration
- Intercepts getSecurityLevel replies to register hooks on every new BBinder instance keystore2 returns, not just the initial one from setup
- Identity hash deduplication prevents double-hooking when keystore2 returns the same binder across multiple calls
- Resolves apps that call getSecurityLevel independently and receive a different binder than the one registered at startup

### Build & Packaging
- Rust native build task integrated into Gradle with cargo-ndk for aarch64/armv7/x86/x86_64
- Module ZIP includes all 4 native libraries (libTEESimulator, libsupervisor, libcertgen, libinject)
- customize.sh extraction restored for supervisor daemon and native cert gen library
- TeeLatencySimulator added as standalone utility for log-normal hardware latency emulation

---

## TEESimulator-RS v5.0: AOSP Compliance Overhaul

Major release integrating 30+ AOSP compliance improvements from upstream PR #157 analysis, layered on top of our StrongBox hardening and native cert gen architecture.

### Attestation Extension Alignment
- 17 enforcement tags added to KeyMintAttestation (ACTIVE_DATETIME, ORIGINATION_EXPIRE, USAGE_EXPIRE, USAGE_COUNT_LIMIT, CALLER_NONCE, UNLOCKED_DEVICE_REQUIRED, INCLUDE_UNIQUE_ID, ROLLBACK_RESISTANCE, EARLY_BOOT_ONLY, ALLOW_WHILE_ON_BODY, TRUSTED_USER_PRESENCE_REQUIRED, TRUSTED_CONFIRMATION_REQUIRED, NO_AUTH_REQUIRED, MAX_USES_PER_BOOT, MAX_BOOT_LEVEL, MIN_MAC_LENGTH, RSA_OAEP_MGF_DIGEST)
- BLOCK_MODE encoded as SET OF INTEGER per AOSP attestation_record.h
- Version-guarded tags (RSA_OAEP_MGF_DIGEST >=100, ROLLBACK_RESISTANCE >=3, EARLY_BOOT_ONLY >=4)
- INCLUDE_UNIQUE_ID computed via HMAC-SHA256 per KeyMint HAL spec using device HBK
- AAID gated on attestation challenge presence
- Certificate validity defaults aligned with AOSP (epoch notBefore, 9999-12-31 notAfter)

### Binder Infrastructure
- Native transaction code filtering at C++ level, skipping JNI for non-intercepted codes
- getNumberOfEntries includes software-generated key count
- deleteKey resolves KEY_ID domain via generatedKeys lookup
- patchAuthorizations for OS/VENDOR/BOOT patch levels in authorization arrays

### Software Operation AOSP Conformance
- updateAad on non-AEAD operations returns INVALID_TAG (-76), matching AOSP operation.rs
- All crypto exceptions wrapped as ServiceSpecificException with correct KeyMint error codes
- GCM IV returned in CreateOperationResponse.parameters for encrypt operations
- SoftwareOperationBinder methods @Synchronized, matching AOSP Mutex per operation
- authorize_create enforcement: PURPOSE validation, algorithm-purpose compatibility, temporal constraints, CALLER_NONCE prohibition, WRAP_KEY rejection

### Security and Configuration
- SELinux permission checks via /proc/pid/attr/current
- Per-UID permission verification through IPackageManager.checkPermission
- Imported key tracking prevents stale attest-key overrides in getKeyEntry
- nspace consistency fix in attest-key override path
- TeeLatencySimulator with log-normal distribution matching real hardware profiles
- Device-unique HBK seed generated on install (32 bytes from /dev/random)

### Preserved from v4.8
- StrongBox op limits (4 concurrent max, TOO_MANY_OPERATIONS rejection)
- LRU operation pruning per security level
- Hardware keygen rate limiting (2/30s sliding window, 2 concurrent cap)
- Native Rust cert generation with BouncyCastle fallback
- Key persistence across reboots

---

## TEESimulator-RS v4.8.1: StrongBox Op Rejection Fix

- **StrongBox op limit gate fix** — `trackAndEnforceOpLimit` was only called in the `Domain.KEY_ID` not-found path, so software-generated keys (found via `Domain.APP`) bypassed `STRONGBOX_MAX_CONCURRENT_OPS=4` entirely. DuckDetector's concurrent signing handles test created 24+ operations that all succeeded via LRU pruning instead of being rejected with `TOO_MANY_OPERATIONS (-29)`. Now enforced for all StrongBox createOperation paths.

---

## TEESimulator-RS v4.8: StrongBox Hardening & LRU Pruning

Tested against DuckDetector on OnePlus (Android 16, KSU). Tamper score dropped from 32 to 8.

- **LRU operation pruning** — Concurrent software operations capped at 15 per UID (TEE) and 4 per UID (StrongBox), with oldest-first eviction. Pruned operations return `INVALID_OPERATION_HANDLE (-28)`, matching AOSP keystore2 malus-based pruning.
- **StrongBox param guard** — Unsupported StrongBox params (RSA >2048-bit, non-P256 EC curves) forwarded to real HAL for proper rejection instead of generating in software.
- **StrongBox timing** — Key generation floors at 250ms, signing at 80ms on StrongBox security level to match real secure element latency.
- **StrongBox op limit** — Sliding-window enforcer caps concurrent StrongBox operations for both software and hardware key paths, returning `TOO_MANY_OPERATIONS (-29)` when exceeded.
- **ECDSA algorithm alias** — Accept "ECDSA" in addition to "EC" as JCA private key algorithm name. Fixes SIGSEGV crash on Android 10 devices where the provider reports EC keys as "ECDSA". Closes #4.
- **createOperation domain handling** — Software-generated keys now found via both `Domain.APP` (alias) and `Domain.KEY_ID` (nspace) lookup paths.
- **Permission guards** — Device ID attestation tags (IMEI, MEID, serial) require caller permission checks.

---

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
