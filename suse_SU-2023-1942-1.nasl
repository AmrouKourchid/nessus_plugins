#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:1942-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(174672);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/14");

  script_cve_id("CVE-2022-25881");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:1942-1");

  script_name(english:"SUSE SLES12 Security Update : nodejs16 (SUSE-SU-2023:1942-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by a vulnerability as referenced
in the SUSE-SU-2023:1942-1 advisory.

  - This affects versions of the package http-cache-semantics before 4.1.1. The issue can be exploited via
    malicious request header values sent to a server, when that server reads the cache policy from the request
    using this library. (CVE-2022-25881)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-25881");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-April/014543.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3814ac23");
  script_set_attribute(attribute:"solution", value:
"Update the affected nodejs16, nodejs16-devel, nodejs16-docs and / or npm16 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-25881");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs16-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs16-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:npm16");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(0|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP0/3/4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(0|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP0/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'nodejs16-16.20.0-8.27.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'nodejs16-16.20.0-8.27.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'nodejs16-16.20.0-8.27.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'nodejs16-16.20.0-8.27.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'nodejs16-devel-16.20.0-8.27.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'nodejs16-devel-16.20.0-8.27.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'nodejs16-devel-16.20.0-8.27.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'nodejs16-devel-16.20.0-8.27.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'nodejs16-docs-16.20.0-8.27.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'nodejs16-docs-16.20.0-8.27.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'nodejs16-docs-16.20.0-8.27.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'nodejs16-docs-16.20.0-8.27.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'npm16-16.20.0-8.27.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'npm16-16.20.0-8.27.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'npm16-16.20.0-8.27.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'npm16-16.20.0-8.27.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'nodejs16-16.20.0-8.27.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'nodejs16-16.20.0-8.27.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'nodejs16-16.20.0-8.27.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'nodejs16-16.20.0-8.27.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'nodejs16-devel-16.20.0-8.27.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'nodejs16-devel-16.20.0-8.27.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'nodejs16-devel-16.20.0-8.27.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'nodejs16-devel-16.20.0-8.27.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'nodejs16-docs-16.20.0-8.27.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'nodejs16-docs-16.20.0-8.27.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'nodejs16-docs-16.20.0-8.27.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'nodejs16-docs-16.20.0-8.27.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'npm16-16.20.0-8.27.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'npm16-16.20.0-8.27.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'npm16-16.20.0-8.27.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'npm16-16.20.0-8.27.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs16 / nodejs16-devel / nodejs16-docs / npm16');
}
