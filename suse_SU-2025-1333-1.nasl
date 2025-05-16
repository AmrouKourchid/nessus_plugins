#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1333-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(234602);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id(
    "CVE-2024-6104",
    "CVE-2024-51744",
    "CVE-2025-22868",
    "CVE-2025-22869",
    "CVE-2025-22870",
    "CVE-2025-27144"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1333-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : cosign (SUSE-SU-2025:1333-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has a package installed that is
affected by multiple vulnerabilities as referenced in the SUSE-SU-2025:1333-1 advisory.

    - CVE-2024-6104: cosign: hashicorp/go-retryablehttp: Fixed sensitive information disclosure to log file
    (bsc#1227031)
    - CVE-2024-51744: cosign: github.com/golang-jwt/jwt/v4: Fixed bad documentation of error handling in
    ParseWithClaims leading to potentially dangerous situations (bsc#1232985)
    - CVE-2025-27144: cosign: github.com/go-jose/go-jose/v4,github.com/go-jose/go-jose/v3: Fixed denial of
    service in Go JOSE's Parsing (bsc#1237682)
    - CVE-2025-22870: cosign: golang.org/x/net/proxy: Fixed proxy bypass using IPv6 zone IDs (bsc#1238693)
    - CVE-2025-22868: cosign: golang.org/x/oauth2/jws: Fixed unexpected memory consumption during token
    parsing (bsc#1239204)
    - CVE-2025-22869: cosign: golang.org/x/crypto/ssh: Fixed denial of service in the Key Exchange
    (bsc#1239337)

    Other fixes:

    - Update to version 2.5.0 (jsc#SLE-23476):
      * Update sigstore-go to pick up bug fixes (#4150)
      * Update golangci-lint to v2, update golangci-lint-action (#4143)
      * Feat/non filename completions (#4115)
      * update builder to use go1.24.1 (#4116)
      * Add support for new bundle specification for attesting/verifying OCI image attestations (#3889)
      * Remove cert log line (#4113)
      * cmd/cosign/cli: fix typo in ignoreTLogMessage (#4111)
      * bump to latest scaffolding release for testing (#4099)
      * increase 2e2_test docker compose tiemout to 180s (#4091)
      * Fix replace with compliant image mediatype (#4077)
      * Add TSA certificate related flags and fields for cosign attest (#4079)

    - Update to version 2.4.3 (jsc#SLE-23476):
      * Enable fetching signatures without remote get. (#4047)
      * Bump sigstore/sigstore to support KMS plugins (#4073)
      * sort properly Go imports (#4071)
      * sync comment with parameter name in function signature (#4063)
      * fix go imports order to be alphabetical (#4062)
      * fix comment typo and imports order (#4061)
      * Feat/file flag completion improvements (#4028)
      * Udpate builder to use go1.23.6 (#4052)
      * Refactor verifyNewBundle into library function (#4013)
      * fix parsing error in --only for cosign copy (#4049)
      * Fix codeowners syntax, add dep-maintainers (#4046)

    - Update to version 2.4.2 (jsc#SLE-23476):
      - Updated open-policy-agent to 1.1.0 library (#4036)
         -  Note that only Rego v0 policies are supported at this time
      - Add UseSignedTimestamps to CheckOpts, refactor TSA options (#4006)
      - Add support for verifying root checksum in cosign initialize (#3953)
      - Detect if user supplied a valid protobuf bundle (#3931)
      - Add a log message if user doesn't provide --trusted-root (#3933)
      - Support mTLS towards container registry (#3922)
      - Add bundle create helper command (#3901)
      - Add trusted-root create helper command (#3876)
      Bug Fixes:
      - fix: set tls config while retaining other fields from default http transport (#4007)
      - policy fuzzer: ignore known panics (#3993)
      - Fix for multiple WithRemote options (#3982)
      - Add nightly conformance test workflow (#3979)
      - Fix copy --only for signatures + update/align docs (#3904)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239204");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239337");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/039052.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-51744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22869");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-27144");
  script_set_attribute(attribute:"solution", value:
"Update the affected cosign package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6104");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-27144");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cosign");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4/5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4/5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'cosign-2.5.0-150400.3.27.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cosign');
}
