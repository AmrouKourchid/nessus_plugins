#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:4351-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(168492);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/14");

  script_cve_id("CVE-2019-3681", "CVE-2019-3685");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:4351-1");

  script_name(english:"SUSE SLES12 Security Update : osc (SUSE-SU-2022:4351-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has a package installed that is affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:4351-1 advisory.

  - A External Control of File Name or Path vulnerability in osc of SUSE Linux Enterprise Module for
    Development Tools 15, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise
    Software Development Kit 12-SP4; openSUSE Leap 15.1, openSUSE Factory allowed remote attackers that can
    change downloaded packages to overwrite arbitrary files. This issue affects: SUSE Linux Enterprise Module
    for Development Tools 15 osc versions prior to 0.169.1-3.20.1. SUSE Linux Enterprise Software Development
    Kit 12-SP5 osc versions prior to 0.162.1-15.9.1. SUSE Linux Enterprise Software Development Kit 12-SP4 osc
    versions prior to 0.162.1-15.9.1. openSUSE Leap 15.1 osc versions prior to 0.169.1-lp151.2.15.1. openSUSE
    Factory osc versions prior to 0.169.0 . (CVE-2019-3681)

  - Open Build Service before version 0.165.4 diddn't validate TLS certificates for HTTPS connections with the
    osc client binary (CVE-2019-3685)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1089025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1097996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1122675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1125243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1126055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1126058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1127932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1129757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1129889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1131512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1136584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1137477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1138165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1138977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1140697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1142518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1142662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1144211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1155953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1166537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-3685");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-December/013202.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dd78780");
  script_set_attribute(attribute:"solution", value:
"Update the affected osc package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3685");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-3681");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:osc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'osc-0.182.0-15.12.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'osc-0.182.0-15.12.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'osc');
}
