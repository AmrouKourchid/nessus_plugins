#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4007-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212528);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id("CVE-2024-47533", "CVE-2024-49502", "CVE-2024-49503");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4007-1");

  script_name(english:"SUSE SLES15 Security Update : SUSE Manager Server 4.3 (SUSE-SU-2024:4007-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:4007-1 advisory.

    release-notes-susemanager:

    - Update to SUSE Manager 4.3.14
      * Ubuntu 24.04 support as client
      * Product migration from RHEL and Clones to SUSE Liberty Linux
      * POS image templates now produce compressed images
      * Date format for API endpoints has been changed to ISO-8601 format
      * Security issues fixed:
        CVE-2024-47533, CVE-2024-49502, CVE-2024-49503
      * Bugs mentioned:
        bsc#1146701, bsc#1211899, bsc#1212985, bsc#1217003, bsc#1217338
        bsc#1217978, bsc#1218090, bsc#1219450, bsc#1219645, bsc#1219887
        bsc#1221435, bsc#1221505, bsc#1223312, bsc#1223988, bsc#1224108
        bsc#1224209, bsc#1225603, bsc#1225619, bsc#1225960, bsc#1226090
        bsc#1226439, bsc#1226461, bsc#1226478, bsc#1226687, bsc#1226917
        bsc#1227133, bsc#1227334, bsc#1227406, bsc#1227526, bsc#1227543
        bsc#1227599, bsc#1227606, bsc#1227746, bsc#1228036, bsc#1228101
        bsc#1228130, bsc#1228147, bsc#1228286, bsc#1228326, bsc#1228345
        bsc#1228412, bsc#1228545, bsc#1228638, bsc#1228851, bsc#1228945
        bsc#1229079, bsc#1229178, bsc#1229260, bsc#1229339, bsc#1231332
        bsc#1231852, bsc#1231922, bsc#1231900

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1146701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225603");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231922");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-November/019836.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a77d7d2");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47533");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49503");
  script_set_attribute(attribute:"solution", value:
"Update the affected release-notes-susemanager package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47533");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-49503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:release-notes-susemanager");
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
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'release-notes-susemanager-4.3.14-150400.3.122.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'release-notes-susemanager');
}
