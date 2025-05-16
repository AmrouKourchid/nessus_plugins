#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4011-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212527);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id("CVE-2023-3978");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4011-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : SUSE Manager Client Tools (SUSE-SU-2024:4011-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by a vulnerability as
referenced in the SUSE-SU-2024:4011-1 advisory.

    golang-github-lusitaniae-apache_exporter:

    - Security issues fixed:

      * CVE-2023-3978: Fixed security bug in x/net dependency (bsc#1213933)


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231206");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-November/019833.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?956f60e5");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3978");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang-github-lusitaniae-apache_exporter, golang-github-prometheus-promu, spacecmd and / or wire
packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3978");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-lusitaniae-apache_exporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:golang-github-prometheus-promu");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.5|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4/5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'golang-github-lusitaniae-apache_exporter-1.0.8-150000.1.23.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'golang-github-lusitaniae-apache_exporter-1.0.8-150000.1.23.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'golang-github-prometheus-promu-0.16.0-150000.3.21.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'spacecmd-5.0.10-150000.3.127.3', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'wire-0.6.0-150000.1.17.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'golang-github-lusitaniae-apache_exporter-1.0.8-150000.1.23.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'golang-github-prometheus-promu-0.16.0-150000.3.21.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'spacecmd-5.0.10-150000.3.127.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'wire-0.6.0-150000.1.17.4', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'golang-github-prometheus-promu-0.16.0-150000.3.21.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'golang-github-prometheus-promu-0.16.0-150000.3.21.4', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-github-lusitaniae-apache_exporter / etc');
}
