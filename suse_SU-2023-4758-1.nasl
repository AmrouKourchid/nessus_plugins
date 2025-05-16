#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:4758-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(186857);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/14");

  script_cve_id("CVE-2023-22644");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:4758-1");

  script_name(english:"SUSE SLES15 Security Update : SUSE Manager Proxy and Retail Branch Server 4.3 (SUSE-SU-2023:4758-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2023:4758-1 advisory.

  - An Innsertion of Sensitive Information into Log File vulnerability in SUSE SUSE Manager Server Module 4.2
    spacewalk-java, SUSE SUSE Manager Server Module 4.3 spacewalk-java causes sensitive information to be
    logged. This issue affects SUSE Manager Server Module 4.2: before 4.2.50-150300.3.66.5; SUSE Manager
    Server Module 4.3: before 4.3.58-150400.3.46.4. (CVE-2023-22644)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217224");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-December/017309.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71f50133");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22644");
  script_set_attribute(attribute:"solution", value:
"Update the affected release-notes-susemanager and / or release-notes-susemanager-proxy packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22644");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:release-notes-susemanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:release-notes-susemanager-proxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
    {'reference':'release-notes-susemanager-proxy-4.3.10-150400.3.72.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'release-notes-susemanager-4.3.10-150400.3.93.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'release-notes-susemanager / release-notes-susemanager-proxy');
}
