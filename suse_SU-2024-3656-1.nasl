#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3656-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(209193);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id(
    "CVE-2018-16873",
    "CVE-2018-16874",
    "CVE-2018-16875",
    "CVE-2018-16886",
    "CVE-2020-15106",
    "CVE-2020-15112",
    "CVE-2021-28235",
    "CVE-2022-41723",
    "CVE-2023-29406",
    "CVE-2023-47108",
    "CVE-2023-48795"
  );
  script_xref(name:"IAVA", value:"2024-A-0236");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3656-1");

  script_name(english:"openSUSE 15 Security Update : etcd (SUSE-SU-2024:3656-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
SUSE-SU-2024:3656-1 advisory.

    Update to version 3.5.12:

    Security fixes:

    - CVE-2018-16873: Fixed remote command execution in cmd/go (bsc#1118897)
    - CVE-2018-16874: Fixed directory traversal in cmd/go (bsc#1118898)
    - CVE-2018-16875: Fixed CPU denial of service in crypto/x509 (bsc#1118899)
    - CVE-2018-16886: Fixed improper authentication issue when RBAC and client-cert-auth is enabled
    (bsc#1121850)
    - CVE-2020-15106: Fixed panic in decodeRecord method (bsc#1174951)
    - CVE-2020-15112: Fixed improper checks in entry index (bsc#1174951)
    - CVE-2021-28235: Fixed information discosure via debug function (bsc#1210138)
    - CVE-2022-41723: Fixed quadratic complexity in HPACK decoding in net/http (bsc#1208270, bsc#1208297)
    - CVE-2023-29406: Fixed insufficient sanitization of Host header in go net/http (bsc#1213229)
    - CVE-2023-47108: Fixed DoS vulnerability in otelgrpc (bsc#1217070)
    - CVE-2023-48795: Fixed prefix truncation breaking ssh channel integrity (aka Terrapin Attack) in
    crypto/ssh (bsc#1217950, bsc#1218150)

    Other changes:

    - Added hardening to systemd service(s) (bsc#1181400)
    - Fixed static /tmp file issue (bsc#1199031)
    - Fixed systemd service not starting (bsc#1183703)

    Full changelog:

    https://github.com/etcd-io/etcd/compare/v3.3.1...v3.5.12

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1095184");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1118897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1118898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1118899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1121850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218150");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-October/037265.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15106");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15112");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28235");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-41723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-29406");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47108");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-48795");
  script_set_attribute(attribute:"solution", value:
"Update the affected etcd and / or etcdctl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16886");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-28235");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-48795");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (isnull(os_release) || os_release !~ "^SUSE") audit(AUDIT_OS_NOT, "openSUSE");
var os_ver = pregmatch(pattern: "^(SUSE[\d.]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SUSE15\.5|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'openSUSE 15', 'openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE (' + os_ver + ')', cpu);

var pkgs = [
    {'reference':'etcd-3.5.12-150000.7.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'etcdctl-3.5.12-150000.7.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'etcd-3.5.12-150000.7.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'etcdctl-3.5.12-150000.7.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'etcd / etcdctl');
}
