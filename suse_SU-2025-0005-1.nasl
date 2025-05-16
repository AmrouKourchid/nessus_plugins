#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0005-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(213486);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/04");

  script_cve_id("CVE-2024-36405", "CVE-2024-37305", "CVE-2024-54137");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0005-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : liboqs, oqs-provider (SUSE-SU-2025:0005-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2025:0005-1 advisory.

    This update supplies the new FIPS standardized ML-KEM, ML-DSA, SHL-DSA algorithms.

    This update liboqs to 0.12.0:

      - This release updates the ML-DSA implementation to the [final
        FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) version. This
        release still includes the NIST Round 3 version of Dilithium for
        interoperability purposes, but we plan to remove Dilithium Round 3 in
        a future release.
      - This will be the last release of liboqs to include Kyber (that is,
        the NIST Round 3 version of Kyber, prior to its standardization by NIST
        as ML-KEM in FIPS 203). Applications should switch to ML-KEM (FIPS 203).
      - The addition of ML-DSA FIPS 204 final version to liboqs has
        introduced a new signature API which includes a context string
        parameter. We are planning to remove the old version of the API
        without a context string in the next release to streamline the
        API and bring it in line with NIST specifications. Users who
        have an opinion on this removal are invited to provide input at
        https://github.com/open-quantum-safe/liboqs/issues/2001.

      Security issues:

      - CVE-2024-54137: Fixed bug in HQC decapsulation that leads to incorrect
        shared secret value during decapsulation when called with an invalid
        ciphertext. (bsc#1234292)
      - new library major version 7

    Updated to 0.11.0:

      * This release updates ML-KEM implementations to their final FIPS 203
        https://csrc.nist.gov/pubs/fips/203/final versions .
      * This release still includes the NIST Round 3 version of Kyber for
        interoperability purposes, but we plan to remove Kyber Round 3 in a
        future release.
      * Additionally, this release adds support for MAYO and CROSS
        digital signature schemes from [NIST Additional Signatures Round 1
        https://csrc.nist.gov/Projects/pqc-dig-sig/round-1-additional-signatures
        along with stateful hash-based signature schemes XMSS
        https://datatracker.ietf.org/doc/html/rfc8391 and LMS
        https://datatracker.ietf.org/doc/html/rfc8554.
      * Finally, this release provides formally verified
        implementations of Kyber-512 and Kyber-768 from libjade
        https://github.com/formosa-crypto/libjade/releases/tag/release%2F2023.05-2
      * LMS and XMSS are disabled by default due to the security risks associated with their use in software.
        See the note on stateful hash-based signatures in CONFIGURE.md
      * Key encapsulation mechanisms:
      - Kyber: Added formally-verified portable C and AVX2 implementations
        of Kyber-512 and Kyber-768 from libjade.
      - ML-KEM: Updated portable C and AVX2 implementations of ML-KEM-512,
        ML-KEM-768, and ML-KEM-1024 to FIP 203 version.
      - Kyber: Patched ARM64 implementations of Kyber-512, Kyber-768, and
        Kyber-1024 to work with AddressSanitizer.
      * Digital signature schemes:
      - LMS/XMSS: Added implementations of stateful hash-based signature
        schemes: XMSS and LMS
      - MAYO: Added portable C and AVX2 implementations of MAYO signature
        scheme from NIST Additional Signatures Round 1.
      - CROSS: Added portable C and AVX2 implementations of CROSS signature
        scheme from NIST Additional Signatures Round 1.
      * Other changes:
      - Added callback API to use custom implementations of AES, SHA2, and SHA3.
      - Refactor SHA3 implementation to use OpenSSL's EVP_DigestSqueeze() API.

      - new library major version 6

    Updated to 0.10.1:

    - This release is a security release which fixes potential
      non-constant-time behaviour in ML-KEM and Kyber. (bsc#1226162
      CVE-2024-36405)
      It also includes a fix for incorrectly named macros in the ML-DSA
      implementation.

    updated to 0.10.0:

      Key encapsulation mechanisms:

      - BIKE: Updated portable C implementation to include constant-time fixes from upstream.
      - HQC: Updated to NIST Round 4 version.
      - ML-KEM: Added portable C and AVX2 implementations of Initial Public Draft (IPD) versions of ML-
    KEM-512, ML-KEM-768, and ML-KEM-1024.

      Digital signature schemes:

      - Falcon: Updated portable C, AVX2, and AArch64 implementations to support fixed-length (PADDED-format)
    signatures. Fixed the maximum length of variable-length signatures to comply with the NIST Round 3
    specification.
      - ML-DSA: Added portable C and AVX2 implementations of Initial Public Draft (IPD) versions of ML-DSA-44,
    ML-DSA-65, and ML-DSA-87.


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234292");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-January/020060.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8cb7ef38");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36405");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37305");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-54137");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liboqs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liboqs7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:oqs-provider");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'liboqs-devel-0.12.0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'liboqs-devel-0.12.0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'liboqs7-0.12.0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'liboqs7-0.12.0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'oqs-provider-0.7.0-150600.3.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'oqs-provider-0.7.0-150600.3.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'liboqs-devel-0.12.0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'liboqs-devel-0.12.0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'liboqs7-0.12.0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'liboqs7-0.12.0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'oqs-provider-0.7.0-150600.3.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'oqs-provider-0.7.0-150600.3.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'liboqs-devel-0.12.0-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'liboqs-devel-32bit-0.12.0-150600.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'liboqs7-0.12.0-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'liboqs7-32bit-0.12.0-150600.3.3.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'oqs-provider-0.7.0-150600.3.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'liboqs-devel / liboqs-devel-32bit / liboqs7 / liboqs7-32bit / etc');
}
