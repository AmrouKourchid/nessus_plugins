#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2346-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(176618);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/14");

  script_cve_id("CVE-2023-32324");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2346-1");

  script_name(english:"SUSE SLES12 Security Update : cups (SUSE-SU-2023:2346-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by a vulnerability as referenced
in the SUSE-SU-2023:2346-1 advisory.

  - OpenPrinting CUPS is an open source printing system. In versions 2.4.2 and prior, a heap buffer overflow
    vulnerability would allow a remote attacker to launch a denial of service (DoS) attack. A buffer overflow
    vulnerability in the function `format_log_line` could allow remote attackers to cause a DoS on the
    affected system. Exploitation of the vulnerability can be triggered when the configuration file
    `cupsd.conf` sets the value of `loglevel `to `DEBUG`. No known patches or workarounds exist at time of
    publication. (CVE-2023-32324)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211643");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-June/029665.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-32324");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32324");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-ddk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP2/4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cups-1.7.5-20.39.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'cups-client-1.7.5-20.39.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'cups-libs-1.7.5-20.39.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'cups-libs-32bit-1.7.5-20.39.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'cups-1.7.5-20.39.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'cups-client-1.7.5-20.39.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'cups-ddk-1.7.5-20.39.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'cups-devel-1.7.5-20.39.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'cups-libs-1.7.5-20.39.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'cups-libs-32bit-1.7.5-20.39.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'cups-ddk-1.7.5-20.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'cups-devel-1.7.5-20.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'cups-1.7.5-20.39.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'cups-client-1.7.5-20.39.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'cups-libs-1.7.5-20.39.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'cups-libs-32bit-1.7.5-20.39.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'cups-1.7.5-20.39.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'cups-client-1.7.5-20.39.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'cups-libs-1.7.5-20.39.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'cups-libs-32bit-1.7.5-20.39.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']},
    {'reference':'cups-1.7.5-20.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'cups-client-1.7.5-20.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'cups-libs-1.7.5-20.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'cups-libs-32bit-1.7.5-20.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'cups-1.7.5-20.39.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-4']},
    {'reference':'cups-1.7.5-20.39.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-4']},
    {'reference':'cups-client-1.7.5-20.39.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-4']},
    {'reference':'cups-client-1.7.5-20.39.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-4']},
    {'reference':'cups-libs-1.7.5-20.39.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-4']},
    {'reference':'cups-libs-1.7.5-20.39.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-4']},
    {'reference':'cups-libs-32bit-1.7.5-20.39.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cups / cups-client / cups-ddk / cups-devel / cups-libs / etc');
}
