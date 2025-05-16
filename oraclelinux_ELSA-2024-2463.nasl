#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-2463.
##

include('compat.inc');

if (description)
{
  script_id(195045);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id("CVE-2023-7008");

  script_name(english:"Oracle Linux 9 : systemd (ELSA-2024-2463)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2024-2463 advisory.

    [252-32.0.2]
    - Due to a new [Orabug: 36564551] filed on April 29 2024, reverting from back to
    - previous Tony Lam patch [Orabug: 25897792] until issue with [Orabug: 36564551] is resolved.
    - Re-Added 1001-Fix-missing-netdev-for-iscsi-entry-in-fstab.patch [Orabug: 25897792]
    - Removed the following, associated with [Orabug: 36269319]:
    - 1A) Remove 1001-systemd-fstab-generator-reload-targets.patch
    - 1B) Remove Fix local-fs and remote-fs targets during system boot [Orabug: 36269319]
    - 1C) Remove 'systemd-fstab-generator-reload-targets.service' file [Orabug: 36269319]
    - 1D) Remove required rpms for correct kickstart/systemd functionality within systemd.spec [Orabug:
    36269319]
    - 1E) Remove Important: Review 1001-systemd-fstab-generator-reload-targets.patch for important build
    details/steps [Orabug: 36269319]

    [252-32.0.1]
    - Backport upstream pstore dmesg fix [Orabug: 34868110]
    - Remove upstream references  [Orabug: 33995357]
    - Disable unprivileged BPF by default [Orabug: 32870980]
    - udev rules: fix memory hot add and remove [Orabug: 31310273]
    - set 'RemoveIPC=no' in logind.conf as default for OL7.2 [Orabug: 22224874]
    - allow dm remove ioctl to co-operate with UEK3 [Orabug: 18467469]
    - shutdown: get only active md arrays. [Orabug: 34467234]
    - Wait for an extra configurable time before udevd kills a worker [Orabug: 36017407]
    - Removed unneeded patches from the systemd.spec
    - 1001-Fix-missing-netdev-for-iscsi-entry-in-fstab.patch [Orabug: 25897792]
    - 1004-orabug34272490-0001-core-device-ignore-DEVICE_FOUND_UDEV-bit-on-switchin.patch [Orabug: 34272490]
    - 1005-orabug34272490-0002-core-device-drop-unnecessary-condition.patch [Orabug: 34272490]
    - 1007-orabug34868110-pstore-fixes-for-dmesg.txt-reconstruction.patch [Orabug: 34868110]

    [252-32]
    - rebase rhel-net-naming-sysattrs to v0.5

    [252-31]
    - bootctl: rework random seed logic to use open_mkdir_at() and openat() (RHEL-16952)
    - bootctl: properly sync fs before/after moving random seed file into place (RHEL-16952)
    - bootctl: when updating EFI random seed file, hash old seed with new one (RHEL-16952)
    - sha256: add helper than hashes a buffer *and* its size (RHEL-16952)
    - random-seed: don't refresh EFI random seed from random-seed.c anymore (RHEL-16952)
    - bootctl: downgrade graceful messages to LOG_NOTICE (RHEL-16952)
    - units: rename/rework systemd-boot-system-token.service -> systemd-boot-random-seed.service (RHEL-16952)
    - bootctl: split out setting of system token into function of its own (RHEL-16952)

    [252-30]
    - resolved: limit the number of signature validations in a transaction (RHEL-26643)
    - resolved: reduce the maximum nsec3 iterations to 100 (RHEL-26643)
    - efi: alignment of the PE file has to be at least 512 bytes (RHEL-26133)
    - units: change assert to condition to skip running in initrd/os (RHEL-16182)
    - ci: add configuration for regression sniffer GA (RHEL-1086)

    [252-29]
    - units: fix typo in Condition in systemd-boot-system-token (RHEL-16952)

    [252-28]
    - random-seed: shorten a bit may_credit() (RHEL-16952)
    - random-seed: make one more use of random_write_entropy() (RHEL-16952)
    - random-seed: use getopt() (RHEL-16952)
    - random-seed: make the logic to calculate the number of bytes read from the random seed file clearer
    (RHEL-16952)
    - random-seed: no need to pass 'mode' argument when opening /dev/urandom (RHEL-16952)
    - random-seed: split out run() (RHEL-16952)
    - random_seed: minor improvement in run() (RHEL-16952)
    - random-seed: downgrade some messages (RHEL-16952)
    - random-seed: clarify one comment (RHEL-16952)
    - random-seed: make sure to load machine id even if the seed file is missing (RHEL-16952)
    - chase-symlinks: add new flag for prohibiting any following of symlinks (RHEL-16952)
    - bootctl,bootspec: make use of CHASE_PROHIBIT_SYMLINKS whenever we access the ESP/XBOOTLDR (RHEL-16952)
    - boot: implement kernel EFI RNG seed protocol with proper hashing (RHEL-16952)
    - random-seed: refresh EFI boot seed when writing a new seed (RHEL-16952)
    - random-seed: handle post-merge review nits (RHEL-16952)
    - boot: do not truncate random seed file (RHEL-16952)
    - bootctl: install system token on virtualized systems (RHEL-16952)
    - boot: remove random-seed-mode (RHEL-16952)
    - stub: handle random seed like sd-boot does (RHEL-16952)
    - efi: add efi_guid_equal() helper (RHEL-16952)
    - efi: add common implementation for loop finding EFI configuration tables (RHEL-16952)
    - boot: Detect hypervisors using SMBIOS info (RHEL-16952)
    - boot: Skip soft-brick warning when in a VM (RHEL-16952)
    - boot: Replace UINTN with size_t (RHEL-16952)
    - boot: Use unsigned for beep counting (RHEL-16952)
    - boot: Use unicode literals (RHEL-16952)
    - macro: add generic IS_ALIGNED32() anf friends (RHEL-16952)
    - meson: use 0|1 for SD_BOOT (RHEL-16952)
    - boot: Add printf functions (RHEL-16952)
    - boot: Use printf for error logging (RHEL-16952)
    - boot: Introduce log_wait (RHEL-16952)
    - boot: Add log_trace debugging helper (RHEL-16952)
    - tree-wide: Use __func__ in asserts (RHEL-16952)
    - boot: Drop use of xpool_print/SPrint (RHEL-16952)
    - boot: Drop use of Print (RHEL-16952)
    - boot: Rework GUID handling (RHEL-16952)
    - efi-string: Fix strchr() null byte handling (RHEL-16952)
    - efi-string: Add startswith8() (RHEL-16952)
    - efi-string: Add efi_memchr() (RHEL-16952)
    - vmm: Add more const (RHEL-16952)
    - vmm: Add smbios_find_oem_string() (RHEL-16952)
    - stub: Read extra kernel command line items from SMBIOS (RHEL-16952)
    - vmm: Modernize get_smbios_table() (RHEL-16952)
    - stub: measure SMBIOS kernel-cmdline-extra in PCR12 (RHEL-16952)
    - efi: support passing empty cmdline to mangle_stub_cmdline() (RHEL-16952)
    - efi: set EFIVAR to stop Shim from uninstalling its protocol (RHEL-16952)
    - ukify: use empty stub for addons (RHEL-16952)
    - stub: allow loading and verifying cmdline addons (RHEL-16952)
    - TODO: remove fixed item (RHEL-16952)
    - fix: do not check/verify slice units if recursive errors are to be ignored (RHEL-1086)

    [252-27]
    - test: merge TEST-20-MAINPIDGAMES into TEST-07-PID1 (fixup) (RHEL-1086)
    - test: use the default nsec3-iterations value (RHEL-1086)
    - test: explicitly set nsec3-iterations to 0 (RHEL-1086)
    - core: mount namespaces: Remove auxiliary bind mounts directory after unit termination (RHEL-19483)
    - ci: deploy systemd man to GitHub Pages (RHEL-1086)
    - doc: add missing <listitem> to systemd.net-naming-scheme.xml (RHEL-7026)
    - man: reorder the list of supported naming schemes (RHEL-7026)
    - tree-wide: fix return value handling of base64mem() (RHEL-16182)
    - Consolidate various TAKE_* into TAKE_GENERIC(), add TAKE_STRUCT() (RHEL-16182)
    - pcrphase: add  env var for overriding stub check (RHEL-16182)
    - pcrphase: gracefully exit if TPM2 support is incomplete (RHEL-16182)
    - tpm2-util: split out code that derives 'good' TPM2 banks into an strv from pcrphase and generalize it in
    tpm2-util.c (RHEL-16182)
    - tpm2-util: split out code that extends a PCR from pcrphase (RHEL-16182)
    - tpm2-util: optionally do HMAC in tpm2_extend_bytes() in case we process sensitive data (RHEL-16182)
    - cryptsetup: add tpm2-measure-pcr= and tpm2-measure-bank= crypttab options (RHEL-16182)
    - man: document the new crypttab measurement options (RHEL-16182)
    - gpt-auto-generator: automatically measure root/var volume keys into PCR 15 (RHEL-16182)
    - blkid-util: define enum for blkid_do_safeprobe() return values (RHEL-16182)
    - pcrphase: make tool more generic, reuse for measuring machine id/fs uuids (RHEL-16182)
    - units: measure /etc/machine-id into PCR 15 during early boot (RHEL-16182)
    - generators: optionally, measure file systems at boot (RHEL-16182)
    - tpm2: add common helper for checking if we are running on UKI with TPM measurements (RHEL-16182)
    - man: document new machine-id/fs measurement options (RHEL-16182)
    - test: add simple integration test for checking PCR extension works as it should (RHEL-16182)
    - update TODO (RHEL-16182)
    - cryptsetup: retry TPM2 unseal operation if it fails with TPM2_RC_PCR_CHANGED (RHEL-16182)
    - boot: Simplify object erasure (RHEL-16182)
    - tree-wide: use CLEANUP_ERASE() at various places (RHEL-16182)
    - dlfcn: add new safe_dclose() helper (RHEL-16182)
    - tpm2: rename tpm2 alg id<->string functions (RHEL-16182)
    - tpm2: rename struct tpm2_context to Tpm2Context (RHEL-16182)
    - tpm2: use ref counter for Tpm2Context (RHEL-16182)
    - tpm2: use Tpm2Context* instead of ESYS_CONTEXT* (RHEL-16182)
    - tpm2: add Tpm2Handle with automatic cleanup (RHEL-16182)
    - tpm2: simplify tpm2_seal() blob creation (RHEL-16182)
    - tpm2: add salt to pin (RHEL-16182)
    - basic/macro: add macro to iterate variadic args (RHEL-16182)
    - test/test-macro: add tests for FOREACH_VA_ARGS() (RHEL-16182)
    - basic/bitfield: add bitfield operations (RHEL-16182)
    - test/test-bitfield: add tests for bitfield macros (RHEL-16182)
    - tpm2: add tpm2_get_policy_digest() (RHEL-16182)
    - tpm2: add TPM2_PCR_VALID() (RHEL-16182)
    - tpm2: add/rename functions to manage pcr selections (RHEL-16182)
    - test/test-tpm2: add tests for pcr selection functions (RHEL-16182)
    - tpm2: add tpm2_pcr_read() (RHEL-16182)
    - tpm2: move openssl-required ifdef code out of policy-building function (RHEL-16182)
    - tpm2: add tpm2_is_encryption_session() (RHEL-16182)
    - tpm2: move policy building out of policy session creation (RHEL-16182)
    - tpm2: add support for a trusted SRK (RHEL-16182)
    - tpm2: fix nits from PR #26185 (RHEL-16182)
    - tpm2: replace magic number (RHEL-16182)
    - tpm2: add tpm2_digest_*() functions (RHEL-16182)
    - tpm2: replace hash_pin() with tpm2_digest_*() functions (RHEL-16182)
    - tpm2: add tpm2_set_auth() (RHEL-16182)
    - tpm2: add tpm2_get_name() (RHEL-16182)
    - tpm2: rename pcr_values_size vars to n_pcr_values (RHEL-16182)
    - tpm2: add tpm2_policy_pcr() (RHEL-16182)
    - tpm2: add tpm2_policy_auth_value() (RHEL-16182)
    - tpm2: add tpm2_policy_authorize() (RHEL-16182)
    - tpm2: use tpm2_policy_authorize() (RHEL-16182)
    - tpm2: add tpm2_calculate_sealing_policy() (RHEL-16182)
    - tpm: remove external calls to dlopen_tpm2() (RHEL-16182)
    - tpm2: remove all extern tpm2-tss symbols (RHEL-16182)
    - tpm2: add tpm2_get_capability(), tpm2_cache_capabilities(), tpm2_capability_pcrs() (RHEL-16182)
    - tpm2: verify symmetric parms in tpm2_context_new() (RHEL-16182)
    - tpm2: replace _cleanup_tpm2_* macros with _cleanup_() (RHEL-16182)
    - tpm2-util: use compound initialization when allocating tpm2 objects (RHEL-16182)
    - tpm2: add tpm2_get_capability_handle(), tpm2_esys_handle_from_tpm_handle() (RHEL-16182)
    - tpm2: add tpm2_read_public() (RHEL-16182)
    - tpm2: add tpm2_get_legacy_template() and tpm2_get_srk_template() (RHEL-16182)
    - tpm2: add tpm2_load() (RHEL-16182)
    - tpm2: add tpm2_load_external() (RHEL-16182)
    - tpm2: move local vars in tpm2_seal() to point of use (RHEL-16182)
    - tpm2: replace magic number in hmac_sensitive initialization (RHEL-16182)
    - tpm2: add tpm2_create() (RHEL-16182)
    - tpm2: replace tpm2_capability_pcrs() macro with direct c->capaiblity_pcrs use (RHEL-16182)
    - basic/alloc-util: add greedy_realloc_append() (RHEL-16182)
    - tpm2: cache the TPM supported commands, add tpm2_supports_command() (RHEL-16182)
    - tpm2: cache TPM algorithms (RHEL-16182)
    - tpm2: add tpm2_persist_handle() (RHEL-16182)
    - tpm2: add tpm2_get_or_create_srk() (RHEL-16182)
    - tpm2: move local vars in tpm2_unseal() to point of use (RHEL-16182)
    - tpm2: remove tpm2_make_primary() (RHEL-16182)
    - tpm2: use CreatePrimary() to create primary keys instead of Create() (RHEL-16182)
    - cryptsetup: downgrade a bunch of log messages that to LOG_WARNING (RHEL-16182)
    - boot/measure: replace TPM PolicyPCR session with calculation (RHEL-16182)
    - core: imply DeviceAllow=/dev/tpmrm0 with LoadCredentialEncrypted (RHEL-16182)
    - added more test cases (RHEL-16182)
    - test: fixed negative checks in TEST-70-TPM2. Use in-line error handling rather than redirections. Follow
    up on #27020 (RHEL-16182)
    - systemd-cryptenroll: add string aliases for tpm2 PCRs Fixes #26697. RFE. (RHEL-16182)
    - cryptenroll: fix an assertion with weak passwords (RHEL-16182)
    - man/systemd-cryptenroll: update list of PCRs, link to uapi docs (RHEL-16182)
    - tpm2: add debug logging to functions converting hash or asym algs to/from strings or ids (RHEL-16182)
    - tpm2: add tpm2_hash_alg_to_size() (RHEL-16182)
    - tpm2: change tpm2_tpm*_pcr_selection_to_mask() to return mask (RHEL-16182)
    - tpm2: add more helper functions for managing TPML_PCR_SELECTION and TPMS_PCR_SELECTION (RHEL-16182)
    - tpm2: add Tpm2PCRValue struct and associated functions (RHEL-16182)
    - tpm2: move declared functions in header lower down (RHEL-16182)
    - tpm2: declare tpm2_log_debug_*() functions in tpm2_util.h (RHEL-16182)
    - tpm2: change tpm2_calculate_policy_pcr(), tpm2_calculate_sealing_policy() to use Tpm2PCRValue array
    (RHEL-16182)
    - tpm2: change tpm2_parse_pcr_argument() parameters to parse to Tpm2PCRValue array (RHEL-16182)
    - tpm2: add TPM2B_*_MAKE(), TPM2B_*_CHECK_SIZE() macros (RHEL-16182)
    - tpm2: add tpm2_pcr_read_missing_values() (RHEL-16182)
    - openssl: add openssl_pkey_from_pem() (RHEL-16182)
    - openssl: add rsa_pkey_new(), rsa_pkey_from_n_e(), rsa_pkey_to_n_e() (RHEL-16182)
    - openssl: add ecc_pkey_new(), ecc_pkey_from_curve_x_y(), ecc_pkey_to_curve_x_y() (RHEL-16182)
    - test: add DEFINE_HEX_PTR() helper function (RHEL-16182)
    - openssl: add test-openssl (RHEL-16182)
    - tpm2: add functions to convert TPM2B_PUBLIC to/from openssl pkey or PEM (RHEL-16182)
    - tpm2: move policy calculation out of tpm2_seal() (RHEL-16182)
    - man: update systemd-cryptenroll man page with details on --tpm2-pcrs format change (RHEL-16182)
    - tpm2: update TEST-70-TPM2 to test passing PCR value to systemd-cryptenroll (RHEL-16182)
    - tpm2: change *alg_to_* functions to use switch() (RHEL-16182)
    - tpm2: lowercase TPM2_PCR_VALUE[S]_VALID functions (RHEL-16182)
    - tpm2: move cast from lhs to rhs in uint16_t/int comparison (RHEL-16182)
    - tpm2: in validator functions, return false instead of assert failure (RHEL-16182)
    - tpm2: in tpm2_pcr_values_valid() use FOREACH_ARRAY() (RHEL-16182)
    - tpm2: use SIZE_MAX instead of strlen() for unhexmem() (RHEL-16182)
    - tpm2: put !isempty() check inside previous !isempty() check (RHEL-16182)
    - tpm2: simplify call to asprintf() (RHEL-16182)
    - tpm2: check pcr value hash != 0 before looking up hash algorithm name (RHEL-16182)
    - tpm2: use strempty() (RHEL-16182)
    - tpm2: split TPM2_PCR_VALUE_MAKE() over multiple lines (RHEL-16182)
    - tpm2: remove ret_ prefix from input/output params (RHEL-16182)
    - tpm2: use memcpy_safe() instead of memcpy() (RHEL-16182)
    - openssl: use new(char, size) instead of malloc(size) (RHEL-16182)
    - tpm2: use table for openssl<->tpm2 ecc curve id mappings (RHEL-16182)
    - tpm2: use switch() instead of if-else (RHEL-16182)
    - tpm2: make logging level consistent at debug for some functions (RHEL-16182)
    - tpm2: remove unnecessary void* cast (RHEL-16182)
    - tpm2: add tpm2_pcr_values_has_(any|all)_values() functions (RHEL-16182)
    - tpm2: wrap (7) in UINT32_C() (RHEL-16182)
    - cryptenroll: change man page example to remove leading 0x and lowercase hex (RHEL-16182)
    - openssl: add log_openssl_errors() (RHEL-16182)
    - openssl: add openssl_digest_size() (RHEL-16182)
    - openssl: add openssl_digest_many() (RHEL-16182)
    - openssl: replace openssl_hash() with openssl_digest() (RHEL-16182)
    - openssl: add openssl_hmac_many() (RHEL-16182)
    - openssl: add rsa_oaep_encrypt_bytes() (RHEL-16182)
    - openssl: add kdf_kb_hmac_derive() (RHEL-16182)
    - openssl: add openssl_cipher_many() (RHEL-16182)
    - openssl: add ecc_edch() (RHEL-16182)
    - openssl: add kdf_ss_derive() (RHEL-16182)
    - dlfcn-util: add static asserts ensuring our sym_xyz() func ptrs match the types from the official
    headers (RHEL-16182)
    - tpm2: add tpm2_marshal_blob() and tpm2_unmarshal_blob() (RHEL-16182)
    - tpm2: add tpm2_serialize() and tpm2_deserialize() (RHEL-16182)
    - tpm2: add tpm2_index_to_handle() and tpm2_index_from_handle() (RHEL-16182)
    - tpm2: fix build failure without openssl (RHEL-16182)
    - tpm2-util: look for tpm2-pcr-signature.json directly in /.extra/ (RHEL-16182)
    - tpm2: downgrade most log functions from error to debug (RHEL-16182)
    - tpm2: handle older tpm enrollments without a saved pcr bank (RHEL-16182)
    - tpm2: allow tpm2_make_encryption_session() without bind key (RHEL-16182)
    - tpm2: update tpm2 test for supported commands (RHEL-16182)
    - tpm2: use GREEDY_REALLOC_APPEND() in tpm2_get_capability_handles(), cap max value (RHEL-16182)
    - tpm2: change tpm2_unseal() to accept Tpm2Context instead of device string (RHEL-16182)
    - tpm2: cache TPM's supported ECC curves (RHEL-16182)
    - tpm2-util: make tpm2_marshal_blob()/tpm2_unmarshal_blob() static (RHEL-16182)
    - tpm2-util: make tpm2_read_public() static, as we use it only internally in tpm2-util.c (RHEL-16182)
    - cryptenroll: allow specifying handle index of key to use for sealing (RHEL-16182)
    - test: add tests for systemd-cryptenroll --tpm2-seal-key-handle (RHEL-16182)
    - tpm2: do not call Esys_TR_Close() (RHEL-16182)
    - tpm2: don't use GetCapability() to check transient handles (RHEL-16182)
    - tpm2-util: pick up a few new symbols from tpm2-tss (RHEL-16182)
    - tpm2: add tpm2_get_pin_auth() (RHEL-16182)
    - tpm2: instead of adjusting authValue trailing 0(s), trim them as required by tpm spec (RHEL-16182)
    - tpm2-util: rename tpm2_calculate_name() -> tpm2_calculate_pubkey_name() (RHEL-16182)
    - cryptenroll: do not implicitly verify with default tpm policy signature (RHEL-16182)
    - cryptenroll: drop deadcode (RHEL-16182)
    - tpm2: allow using tpm2_get_srk_template() without tpm (RHEL-16182)
    - tpm2: add test to verify srk templates (RHEL-16182)
    - tpm2: add tpm2_sym_alg_*_string() and tpm2_sym_mode_*_string() (RHEL-16182)
    - tpm2: add tpm2_calculate_seal() and helper functions (RHEL-16182)
    - tpm2: update test-tpm2 for tpm2_calculate_seal() (RHEL-16182)
    - cryptenroll: add support for calculated TPM2 enrollment (RHEL-16182)
    - test: update TEST-70 with systemd-cryptenroll calculated TPM2 enrollment (RHEL-16182)
    - openssl-util: avoid freeing invalid pointer (RHEL-16182)
    - creds-util: check for CAP_DAC_READ_SEARCH (RHEL-16182)
    - creds-util: do not try TPM2 if there is not support (RHEL-16182)
    - creds-util: merge the TPM2 detection for initrd (RHEL-16182)
    - cryptenroll: fix a memory leak (RHEL-16182)
    - sd-journal: introduce sd_journal_step_one() (RHEL-11591)
    - test: modernize test-journal-flush (RHEL-11591)
    - journal-file-util: do not fail when journal_file_set_offline() called more than once (RHEL-11591)
    - journal-file-util: Prefer punching holes instead of truncating (RHEL-11591)
    - test: add reproducer for SIGBUS issue caused by journal truncation (RHEL-11591)

    [252-26]
    - spec: update rhel-net-naming-sysattrs to v0.4 (RHEL-22278)

    [252-25]
    - spec: add new package with RHEL-specific network naming sysattrs (RHEL-22278)

    [252-24]
    - ci: use source-git-automation composite Action (RHEL-1086)
    - ci: increase the cron interval to 45 minutes (RHEL-1086)
    - ci: add all Z-Stream versions to array of allowed versions (RHEL-1086)
    - udev/net_id: introduce naming scheme for RHEL-9.4 (RHEL-22427)
    - basic/errno-util: add wrappers which only accept negative errno (RHEL-22443)
    - errno-util: allow ERRNO_IS_* to accept types wider than int (RHEL-22443)
    - udev: add new builtin net_driver (RHEL-22443)
    - udev/net_id: introduce naming scheme for RHEL-8.10 (RHEL-22427)

    [252-23]
    - logind: don't setup idle session watch for lock-screen and greeter (RHEL-20757)
    - logind: don't make idle action timer accuracy more coarse than timeout (RHEL-20757)
    - logind: do TTY idle logic only for sessions marked as 'tty' (RHEL-20757)
    - meson: Properly install 90-uki-copy.install (RHEL-16354)

    [252-22]
    - Revert 'man: mention System Administrator's Guide in systemctl manpage' (RHEL-19436)
    - man: mention RHEL documentation in systemctl's man page (RHEL-19436)
    - resolved: actually check authenticated flag of SOA transaction (RHEL-6216)
    - udev: allow/denylist for reading sysfs attributes when composing a NIC name (RHEL-1317)
    - man: environment value -> udev property (RHEL-1317)

    [252-21]
    - meson: fix installation of ukify (RHEL-13199)
    - sd-id128: introduce id128_hash_ops_free (RHEL-5988)
    - udevadm-trigger: allow to fallback without synthetic UUID only first time (RHEL-5988)
    - udevadm-trigger: settle with synthetic UUID if the kernel support it (RHEL-5988)
    - udevadm-trigger: also check with the original syspath if device is renamed (RHEL-5988)
    - test: use 'udevadm trigger --settle' even if device is renamed (RHEL-5988)
    - sd-event: don't mistake USEC_INFINITY passed in for overflow (RHEL-6090)
    - pid1: rework service_arm_timer() to optionally take a relative time value (RHEL-6090)
    - manager: add one more assert() (RHEL-6090)
    - pid1: add new Type=notify-reload service type (RHEL-6090)
    - man: document Type=notify-reload (RHEL-6090)
    - pid1: make sure we send our calling service manager RELOADING=1 when reloading (RHEL-6090)
    - networkd: implement Type=notify-reload protocol (RHEL-6090)
    - udevd: implement the full Type=notify-reload protocol (RHEL-6090)
    - logind: implement Type=notify-reload protocol properly (RHEL-6090)
    - notify: add --stopping + --reloading switches (RHEL-6090)
    - test: add Type=notify-reload testcase (RHEL-6090)
    - update TODO (RHEL-6090)
    - core: check for SERVICE_RELOAD_NOTIFY in manager_dbus_is_running (RHEL-6090)

    [252-20]
    - udev/net: allow new link name as an altname before renaming happens (RHEL-5988)
    - sd-netlink: do not swap old name and alternative name (RHEL-5988)
    - sd-netlink: restore altname on error in rtnl_set_link_name (RHEL-5988)
    - udev: attempt device rename even if interface is up (RHEL-5988)
    - sd-netlink: add a test for rtnl_set_link_name() (RHEL-5988)
    - test-network: add a test for renaming device to current altname (RHEL-5988)
    - udev: align table (RHEL-5988)
    - sd-device: make device_set_syspath() clear sysname and sysnum (RHEL-5988)
    - sd-device: do not directly access entry in sd-device object (RHEL-5988)
    - udev: move device_rename() from device-private.c (RHEL-5988)
    - udev: restore syspath and properties on failure (RHEL-5988)
    - sd-device: introduce device_get_property_int() (RHEL-5988)
    - core/device: downgrade log level for ignored errors (RHEL-5988)
    - core/device: ignore failed uevents (RHEL-5988)
    - test: add tests for failure in renaming network interface (RHEL-5988)
    - test: modernize test-netlink.c (RHEL-5988)
    - test-netlink: use dummy interface to test assigning new interface name (RHEL-5988)
    - udev: use SYNTHETIC_ERRNO() at one more place (RHEL-5988)
    - udev: make udev_builtin_run() take UdevEvent* (RHEL-5988)
    - udev/net: verify ID_NET_XYZ before trying to assign it as an alternative name (RHEL-5988)
    - udev/net: generate new network interface name only on add uevent (RHEL-5988)
    - sd-netlink: make rtnl_set_link_name() optionally append alternative names (RHEL-5988)
    - udev/net: assign alternative names only on add uevent (RHEL-5988)
    - test: add tests for renaming network interface (RHEL-5988)
    - Backport ukify from upstream (RHEL-13199)
    - bootctl: make --json output normal json (RHEL-13199)
    - test: replace readfp() with read_file() (RHEL-13199)
    - stub/measure: document and measure .uname UKI section (RHEL-13199)
    - boot: measure .sbat section (RHEL-13199)
    - Revert 'test_ukify: no stinky root needed for signing' (RHEL-13199)
    - ukify: move to /usr/bin and mark as non non-experimental (RHEL-13199)
    - kernel-install: Add uki layout (RHEL-16354)
    - kernel-install: remove math slang from man page (RHEL-16354)
    - kernel-install: handle uki installs automatically (RHEL-16354)
    - 90-uki-copy.install: create /EFI/Linux directory if needed (RHEL-16354)
    - kernel-install: Log location that uki is installed in (RHEL-16354)
    - bootctl: fix errno logging (RHEL-16354)
    - bootctl: add kernel-identity command (RHEL-16354)
    - bootctl: add kernel-inspect command (RHEL-16354)
    - bootctl: add kernel-inspect to --help text (RHEL-16354)
    - bootctl: drop full stop at end of --help texts (RHEL-16354)
    - bootctl: change section title for kernel image commands (RHEL-16354)
    - bootctl: remove space that should not be there (RHEL-16354)
    - bootctl: kernel-inspect: print os info (RHEL-16354)
    - bootctl-uki: several coding style fixlets (RHEL-16354)
    - tree-wide: unify how we pick OS pretty name to display (RHEL-16354)
    - bootctl-uki: several follow-ups for inspect_osrel() (RHEL-16354)
    - bootctl: Add missing %m (RHEL-16354)
    - bootctl: tweak DOS header magic check (RHEL-16354)

    [252-19]
    - ci: Extend source-git-automation (RHEL-1086)
    - netif-naming-scheme: let's also include rhel8 schemes (RHEL-7026)
    - systemd-analyze: Add table and JSON output implementation to plot (RHEL-5070)
    - systemd-analyze: Update man/systemd-analyze.xml with Plot JSON and table (RHEL-5070)
    - systemd-analyze: Add tab complete logic for plot (RHEL-5070)
    - systemd-analyze: Add --json=, --table and -no-legend tests for plot (RHEL-5070)
    - ci: enable source-git automation to validate reviews and ci results (RHEL-1086)
    - ci: remove Mergify config - replaced by Pull Request Validator (RHEL-1086)
    - ci: enable auto-merge GH Action (RHEL-1086)
    - ci: add missing permissions (RHEL-1086)
    - ci: permissions: write-all (RHEL-1086)
    - ci(lint): exclude .in files from ShellCheck lint (RHEL-1086)
    - udev: raise RLIMIT_NOFILE as high as we can (RHEL-11040)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-2463.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-7008");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:4:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9:4:baseos_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rhel-net-naming-sysattrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-boot-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-journal-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-oomd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:systemd-udev");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'rhel-net-naming-sysattrs-252-32.0.2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-252-32.0.2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-boot-unsigned-252-32.0.2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-252-32.0.2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-252-32.0.2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-252-32.0.2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-252-32.0.2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-oomd-252-32.0.2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-252-32.0.2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-resolved-252-32.0.2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-rpm-macros-252-32.0.2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-252-32.0.2.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-252-32.0.2.el9_4', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-boot-unsigned-252-32.0.2.el9_4', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-252-32.0.2.el9_4', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-252-32.0.2.el9_4', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-252-32.0.2.el9_4', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-252-32.0.2.el9_4', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-oomd-252-32.0.2.el9_4', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-252-32.0.2.el9_4', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-resolved-252-32.0.2.el9_4', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-rpm-macros-252-32.0.2.el9_4', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-252-32.0.2.el9_4', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-252-32.0.2.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-boot-unsigned-252-32.0.2.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-container-252-32.0.2.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-devel-252-32.0.2.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-journal-remote-252-32.0.2.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-libs-252-32.0.2.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-oomd-252-32.0.2.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-pam-252-32.0.2.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-resolved-252-32.0.2.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-rpm-macros-252-32.0.2.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'systemd-udev-252-32.0.2.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rhel-net-naming-sysattrs / systemd / systemd-boot-unsigned / etc');
}
