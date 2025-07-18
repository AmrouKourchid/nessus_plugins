#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:1884-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150397);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/13");

  script_cve_id("CVE-2021-29951", "CVE-2021-29964", "CVE-2021-29967");
  script_xref(name:"IAVA", value:"2021-A-0214-S");
  script_xref(name:"IAVA", value:"2021-A-0264-S");
  script_xref(name:"SuSE", value:"SUSE-SU-2021:1884-1");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : MozillaFirefox (SUSE-SU-2021:1884-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2021:1884-1 advisory.

  - The Mozilla Maintenance Service granted SERVICE_START access to BUILTIN|Users which, in a domain network,
    grants normal remote users access to start or stop the service. This could be used to prevent the browser
    update service from operating (if an attacker spammed the 'Stop' command); but also exposed attack surface
    in the maintenance service. *Note: This issue only affected Windows operating systems older than Win 10
    build 1709. Other operating systems are unaffected.*. This vulnerability affects Thunderbird < 78.10.1,
    Firefox < 87, and Firefox ESR < 78.10.1. (CVE-2021-29951)

  - A locally-installed hostile program could send `WM_COPYDATA` messages that Firefox would process
    incorrectly, leading to an out-of-bounds read. *This bug only affects Firefox on Windows. Other operating
    systems are unaffected.*. This vulnerability affects Thunderbird < 78.11, Firefox < 89, and Firefox ESR <
    78.11. (CVE-2021-29964)

  - Mozilla developers reported memory safety bugs present in Firefox 88 and Firefox ESR 78.11. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Thunderbird < 78.11, Firefox < 89, and
    Firefox ESR < 78.11. (CVE-2021-29967)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29967");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-June/008948.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85523227");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaFirefox, MozillaFirefox-devel, MozillaFirefox-translations-common and / or MozillaFirefox-
translations-other packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29967");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP2/3", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaFirefox-78.11.0-8.43', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.2']},
    {'reference':'MozillaFirefox-78.11.0-8.43', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.2']},
    {'reference':'MozillaFirefox-devel-78.11.0-8.43', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.2']},
    {'reference':'MozillaFirefox-devel-78.11.0-8.43', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.2']},
    {'reference':'MozillaFirefox-translations-common-78.11.0-8.43', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.2']},
    {'reference':'MozillaFirefox-translations-common-78.11.0-8.43', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.2']},
    {'reference':'MozillaFirefox-translations-other-78.11.0-8.43', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.2']},
    {'reference':'MozillaFirefox-translations-other-78.11.0-8.43', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.2']},
    {'reference':'MozillaFirefox-78.11.0-8.43', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.3']},
    {'reference':'MozillaFirefox-78.11.0-8.43', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.3']},
    {'reference':'MozillaFirefox-devel-78.11.0-8.43', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.3']},
    {'reference':'MozillaFirefox-devel-78.11.0-8.43', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.3']},
    {'reference':'MozillaFirefox-devel-78.11.0-8.43', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.3']},
    {'reference':'MozillaFirefox-devel-78.11.0-8.43', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.3']},
    {'reference':'MozillaFirefox-translations-common-78.11.0-8.43', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.3']},
    {'reference':'MozillaFirefox-translations-common-78.11.0-8.43', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.3']},
    {'reference':'MozillaFirefox-translations-other-78.11.0-8.43', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.3']},
    {'reference':'MozillaFirefox-translations-other-78.11.0-8.43', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['sle-module-desktop-applications-release-15.3']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaFirefox / MozillaFirefox-devel / etc');
}
