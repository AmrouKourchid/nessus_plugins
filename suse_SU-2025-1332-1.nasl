#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1332-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(234607);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/18");

  script_cve_id(
    "CVE-2023-45288",
    "CVE-2024-6104",
    "CVE-2025-22868",
    "CVE-2025-22869",
    "CVE-2025-27144",
    "CVE-2025-30204"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1332-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : rekor (SUSE-SU-2025:1332-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has a package installed that is
affected by multiple vulnerabilities as referenced in the SUSE-SU-2025:1332-1 advisory.

    - CVE-2023-45288: rekor: golang.org/x/net/http2: Fixed close connections when receiving too many headers
    (bsc#1236519)
    - CVE-2024-6104: rekor: hashicorp/go-retryablehttp: Fixed sensitive information disclosure inside log file
    (bsc#1227053)
    - CVE-2025-22868: rekor: golang.org/x/oauth2/jws: Fixed unexpected memory consumption during token parsing
    (bsc#1239191)
    - CVE-2025-22869: rekor: golang.org/x/crypto/ssh: Fixed denial of service in the Key Exchange
    (bsc#1239327)
    - CVE-2025-27144: rekor: gopkg.in/go-jose/go-jose.v2,github.com/go-jose/go-jose/v4,github.com/go-jose/go-
    jose/v3: Fixed denial of service in Go JOSE's parsing (bsc#1237638)
    - CVE-2025-30204: rekor: github.com/golang-jwt/jwt/v5: Fixed jwt-go allowing excessive memory allocation
    during header parsing (bsc#1240468)

    Other fixes:

    - Update to version 1.3.10:
      * Features
        - Added --client-signing-algorithms flag (#1974)
      * Fixes / Misc
        - emit unpopulated values when marshalling (#2438)
        - pkg/api: better logs when algorithm registry rejects a key
          (#2429)
        - chore: improve mysql readiness checks (#2397)
        - Added --client-signing-algorithms flag (#1974)

    - Update to version 1.3.9 (jsc#SLE-23476):
      * Cache checkpoint for inactive shards (#2332)
      * Support per-shard signing keys (#2330)

    - Update to version 1.3.8:
      * Bug Fixes
        - fix zizmor issues (#2298)
        - remove unneeded value in log message (#2282)
      * Quality Enhancements
        - chore: relax go directive to permit 1.22.x
        - fetch minisign from homebrew instead of custom ppa (#2329)
        - fix(ci): simplify GOVERSION extraction
        - chore(deps): bump actions pins to latest
        - Updates go and golangci-lint (#2302)
        - update builder to use go1.23.4 (#2301)
        - clean up spaces
        - log request body on 500 error to aid debugging (#2283)

    - Update to version 1.3.7:
      * New Features
        - log request body on 500 error to aid debugging (#2283)
        - Add support for signing with Tink keyset (#2228)
        - Add public key hash check in Signed Note verification (#2214)
        - update Trillian TLS configuration (#2202)
        - Add TLS support for Trillian server (#2164)
        - Replace docker-compose with plugin if available (#2153)
        - Add flags to backfill script (#2146)
        - Unset DisableKeepalive for backfill HTTP client (#2137)
        - Add script to delete indexes from Redis (#2120)
        - Run CREATE statement in backfill script (#2109)
        - Add MySQL support to backfill script (#2081)
        - Run e2e tests on mysql and redis index backends (#2079)
      * Bug Fixes
        - remove unneeded value in log message (#2282)
        - Add error message when computing consistency proof (#2278)
        - fix validation error handling on API (#2217)
        - fix error in pretty-printed inclusion proof from verify
          subcommand (#2210)
        - Fix index scripts (#2203)
        - fix failing sharding test
        - Better error handling in backfill script (#2148)
        - Batch entries in cleanup script (#2158)
        - Add missing workflow for index cleanup test (#2121)
        - hashedrekord: fix schema $id (#2092)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240468");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/039053.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22869");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-27144");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-30204");
  script_set_attribute(attribute:"solution", value:
"Update the affected rekor package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6104");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-30204");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rekor");
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
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'rekor-1.3.10-150400.4.25.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rekor');
}
