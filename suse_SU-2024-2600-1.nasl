#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2600-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(204741);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id("CVE-2023-5388");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2600-1");

  script_name(english:"SUSE SLES15 Security Update : mozilla-nss (SUSE-SU-2024:2600-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by a vulnerability as referenced
in the SUSE-SU-2024:2600-1 advisory.

    - FIPS: Added more safe memset (bsc#1222811).
    - FIPS: Adjusted AES GCM restrictions (bsc#1222830).
    - FIPS: Adjusted approved ciphers (bsc#1222813, bsc#1222814, bsc#1222821,
      bsc#1222822, bsc#1224118, bsc#1222807, bsc#1222828, bsc#1222834,
      bsc#1222804, bsc#1222826, bsc#1222833, bsc#1224113, bsc#1224115,
      bsc#1224116).

    Update to NSS 3.101.1:

    * GLOBALTRUST 2020: Set Distrust After for TLS and S/MIME.

    update to NSS 3.101:

    * add diagnostic assertions for SFTKObject refcount.
    * freeing the slot in DeleteCertAndKey if authentication failed
    * fix formatting issues.
    * Add Firmaprofesional CA Root-A Web to NSS.
    * remove invalid acvp fuzz test vectors.
    * pad short P-384 and P-521 signatures gtests.
    * remove unused FreeBL ECC code.
    * pad short P-384 and P-521 signatures.
    * be less strict about ECDSA private key length.
    * Integrate HACL* P-521.
    * Integrate HACL* P-384.
    * memory leak in create_objects_from_handles.
    * ensure all input is consumed in a few places in mozilla::pkix
    * SMIME/CMS and PKCS #12 do not integrate with modern NSS policy
    * clean up escape handling
    * Use lib::pkix as default validator instead of the old-one
    * Need to add high level support for PQ signing.
    * Certificate Compression: changing the allocation/freeing of buffer + Improving the documentation
    * SMIME/CMS and PKCS #12 do not integrate with modern NSS policy
    * Allow for non-full length ecdsa signature when using softoken
    * Modification of .taskcluster.yml due to mozlint indent defects
    * Implement support for PBMAC1 in PKCS#12
    * disable VLA warnings for fuzz builds.
    * remove redundant AllocItem implementation.
    * add PK11_ReadDistrustAfterAttribute.
    * - Clang-formatting of SEC_GetMgfTypeByOidTag update
    * Set SEC_ERROR_LIBRARY_FAILURE on self-test failure
    * sftk_getParameters(): Fix fallback to default variable after error with configfile.
    * Switch to the mozillareleases/image_builder image

    - switch from ec_field_GFp to ec_field_plain

    Update to NSS 3.100:

    * merge pk11_kyberSlotList into pk11_ecSlotList for faster Xyber operations.
    * remove ckcapi.
    * avoid a potential PK11GenericObject memory leak.
    * Remove incomplete ESDH code.
    * Decrypt RSA OAEP encrypted messages.
    * Fix certutil CRLDP URI code.
    * Don't set CKA_DERIVE for CKK_EC_EDWARDS private keys.
    * Add ability to encrypt and decrypt CMS messages using ECDH.
    * Correct Templates for key agreement in smime/cmsasn.c.
    * Moving the decodedCert allocation to NSS.
    * Allow developers to speed up repeated local execution of NSS tests that depend on certificates.

    Update to NSS 3.99:

    * Removing check for message len in ed25519 (bmo#1325335)
    * add ed25519 to SECU_ecName2params. (bmo#1884276)
    * add EdDSA wycheproof tests. (bmo#1325335)
    * nss/lib layer code for EDDSA. (bmo#1325335)
    * Adding EdDSA implementation. (bmo#1325335)
    * Exporting Certificate Compression types (bmo#1881027)
    * Updating ACVP docker to rust 1.74 (bmo#1880857)
    * Updating HACL* to 0f136f28935822579c244f287e1d2a1908a7e552 (bmo#1325335)
    * Add NSS_CMSRecipient_IsSupported. (bmo#1877730)

    Update to NSS 3.98:

    * (CVE-2023-5388) Timing attack against RSA decryption in TLS
    * Certificate Compression: enabling the check that the compression was advertised
    * Move Windows workers to nss-1/b-win2022-alpha
    * Remove Email trust bit from OISTE WISeKey Global Root GC CA
    * Replace `distutils.spawn.find_executable` with `shutil.which` within `mach` in `nss`
    * Certificate Compression: Updating nss_bogo_shim to support Certificate compression
    * TLS Certificate Compression (RFC 8879) Implementation
    * Add valgrind annotations to freebl kyber operations for constant-time execution tests
    * Set nssckbi version number to 2.66
    * Add Telekom Security roots
    * Add D-Trust 2022 S/MIME roots
    * Remove expired Security Communication RootCA1 root
    * move keys to a slot that supports concatenation in PK11_ConcatSymKeys
    * remove unmaintained tls-interop tests
    * bogo: add support for the -ipv6 and -shim-id shim flags
    * bogo: add support for the -curves shim flag and update Kyber expectations
    * bogo: adjust expectation for a key usage bit test
    * mozpkix: add option to ignore invalid subject alternative names
    * Fix selfserv not stripping `publicname:` from -X value
    * take ownership of ecckilla shims
    * add valgrind annotations to freebl/ec.c
    * PR_INADDR_ANY needs PR_htonl before assignment to inet.ip
    * Update zlib to 1.3.1

    Update to NSS 3.97:

    * make Xyber768d00 opt-in by policy
    * add libssl support for xyber768d00
    * add PK11_ConcatSymKeys
    * add Kyber and a PKCS#11 KEM interface to softoken
    * add a FreeBL API for Kyber
    * part 2: vendor github.com/pq-crystals/kyber/commit/e0d1c6ff
    * part 1: add a script for vendoring kyber from pq-crystals repo
    * Removing the calls to RSA Blind from loader.*
    * fix worker type for level3 mac tasks
    * RSA Blind implementation
    * Remove DSA selftests
    * read KWP testvectors from JSON
    * Backed out changeset dcb174139e4f
    * Fix CKM_PBE_SHA1_DES2_EDE_CBC derivation
    * Wrap CC shell commands in gyp expansions

    Update to NSS 3.96.1:

    * Use pypi dependencies for MacOS worker in ./build_gyp.sh
    * p7sign: add -a hash and -u certusage (also p7verify cleanups)
    * add a defensive check for large ssl_DefSend return values
    * Add dependency to the taskcluster script for Darwin
    * Upgrade version of the MacOS worker for the CI

    Update to NSS 3.95:

    * Bump builtins version number.
    * Remove Email trust bit from Autoridad de Certificacion Firmaprofesional CIF A62634068 root cert.
    * Remove 4 DigiCert (Symantec/Verisign) Root Certificates
    * Remove 3 TrustCor Root Certificates from NSS.
    * Remove Camerfirma root certificates from NSS.
    * Remove old Autoridad de Certificacion Firmaprofesional Certificate.
    * Add four Commscope root certificates to NSS.
    * Add TrustAsia Global Root CA G3 and G4 root certificates.
    * Include P-384 and P-521 Scalar Validation from HACL*
    * Include P-256 Scalar Validation from HACL*.
    * After the HACL 256 ECC patch, NSS incorrectly encodes 256 ECC without DER wrapping at the softoken level
    * Add means to provide library parameters to C_Initialize
    * add OSXSAVE and XCR0 tests to AVX2 detection.
    * Typo in ssl3_AppendHandshakeNumber
    * Introducing input check of ssl3_AppendHandshakeNumber
    * Fix Invalid casts in instance.c

    Update to NSS 3.94:

    * Updated code and commit ID for HACL*
    * update ACVP fuzzed test vector: refuzzed with current NSS
    * Softoken C_ calls should use system FIPS setting to select NSC_ or FC_ variants
    * NSS needs a database tool that can dump the low level representation of the database
    * declare string literals using char in pkixnames_tests.cpp
    * avoid implicit conversion for ByteString
    * update rust version for acvp docker
    * Moving the init function of the mpi_ints before clean-up in ec.c
    * P-256 ECDH and ECDSA from HACL*
    * Add ACVP test vectors to the repository
    * Stop relying on std::basic_string<uint8_t>
    * Transpose the PPC_ABI check from Makefile to gyp

    Update to NSS 3.93:

    * Update zlib in NSS to 1.3.
    * softoken: iterate hashUpdate calls for long inputs.
    * regenerate NameConstraints test certificates (bsc#1214980).

    Update to NSS 3.92:

    * Set nssckbi version number to 2.62
    * Add 4 Atos TrustedRoot Root CA certificates to NSS
    * Add 4 SSL.com Root CA certificates
    * Add Sectigo E46 and R46 Root CA certificates
    * Add LAWtrust Root CA2 (4096)
    * Remove E-Tugra Certification Authority root
    * Remove Camerfirma Chambers of Commerce Root.
    * Remove Hongkong Post Root CA 1
    * Remove E-Tugra Global Root CA ECC v3 and RSA v3
    * Avoid redefining BYTE_ORDER on hppa Linux

    Update to NSS 3.91:

    * Implementation of the HW support check for ADX instruction
    * Removing the support of Curve25519
    * Fix comment about the addition of ticketSupportsEarlyData
    * Adding args to enable-legacy-db build
    * dbtests.sh failure in 'certutil dump keys with explicit default trust flags'
    * Initialize flags in slot structures
    * Improve the length check of RSA input to avoid heap overflow
    * Followup Fixes
    * avoid processing unexpected inputs by checking for m_exptmod base sign
    * add a limit check on order_k to avoid infinite loop
    * Update HACL* to commit 5f6051d2
    * add SHA3 to cryptohi and softoken
    * HACL SHA3
    * Disabling ASM C25519 for A but X86_64

    Update to NSS 3.90.3:

    * GLOBALTRUST 2020: Set Distrust After for TLS and S/MIME.
    * clean up escape handling.
    * remove redundant AllocItem implementation.
    * Disable ASM support for Curve25519.
    * Disable ASM support for Curve25519 for all but X86_64.

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214980");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224118");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-July/019020.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1674046f");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5388");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5388");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP2/3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libfreebl3-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'libfreebl3-32bit-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'libsoftokn3-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'libsoftokn3-32bit-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'mozilla-nss-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'mozilla-nss-32bit-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'mozilla-nss-certs-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'mozilla-nss-certs-32bit-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'mozilla-nss-devel-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'mozilla-nss-sysinit-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'mozilla-nss-tools-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'libfreebl3-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libfreebl3-32bit-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libsoftokn3-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libsoftokn3-32bit-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'mozilla-nss-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'mozilla-nss-32bit-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'mozilla-nss-certs-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'mozilla-nss-certs-32bit-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'mozilla-nss-devel-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'mozilla-nss-sysinit-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'mozilla-nss-sysinit-32bit-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'mozilla-nss-tools-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libfreebl3-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libfreebl3-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libfreebl3-32bit-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'libsoftokn3-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libsoftokn3-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libsoftokn3-32bit-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'mozilla-nss-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'mozilla-nss-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'mozilla-nss-32bit-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'mozilla-nss-certs-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'mozilla-nss-certs-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'mozilla-nss-certs-32bit-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'mozilla-nss-devel-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'mozilla-nss-devel-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'mozilla-nss-sysinit-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'mozilla-nss-sysinit-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'mozilla-nss-tools-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'mozilla-nss-tools-3.101.1-150000.3.117.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libfreebl3-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libfreebl3-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libfreebl3-32bit-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'libsoftokn3-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libsoftokn3-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libsoftokn3-32bit-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'mozilla-nss-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'mozilla-nss-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'mozilla-nss-32bit-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'mozilla-nss-certs-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'mozilla-nss-certs-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'mozilla-nss-certs-32bit-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'mozilla-nss-devel-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'mozilla-nss-devel-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'mozilla-nss-sysinit-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'mozilla-nss-sysinit-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'mozilla-nss-sysinit-32bit-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'mozilla-nss-tools-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'mozilla-nss-tools-3.101.1-150000.3.117.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libfreebl3-3.101.1-150000.3.117.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'libsoftokn3-3.101.1-150000.3.117.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'mozilla-nss-3.101.1-150000.3.117.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'mozilla-nss-certs-3.101.1-150000.3.117.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'mozilla-nss-devel-3.101.1-150000.3.117.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'mozilla-nss-sysinit-3.101.1-150000.3.117.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'mozilla-nss-tools-3.101.1-150000.3.117.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'libfreebl3-3.101.1-150000.3.117.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'libsoftokn3-3.101.1-150000.3.117.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'mozilla-nss-3.101.1-150000.3.117.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'mozilla-nss-certs-3.101.1-150000.3.117.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'mozilla-nss-devel-3.101.1-150000.3.117.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'mozilla-nss-sysinit-3.101.1-150000.3.117.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'mozilla-nss-tools-3.101.1-150000.3.117.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libfreebl3 / libfreebl3-32bit / libsoftokn3 / libsoftokn3-32bit / etc');
}
