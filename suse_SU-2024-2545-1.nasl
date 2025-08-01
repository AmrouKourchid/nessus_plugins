#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2545-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(202588);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/20");

  script_cve_id(
    "CVE-2023-23969",
    "CVE-2024-38875",
    "CVE-2024-39329",
    "CVE-2024-39330",
    "CVE-2024-39614"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2545-1");

  script_name(english:"openSUSE 15 Security Update : python-Django (SUSE-SU-2024:2545-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as referenced in the
SUSE-SU-2024:2545-1 advisory.

    - CVE-2024-38875: Fixed potential denial-of-service attack via certain inputs with a very large number of
    brackets (bsc#1227590)
    - CVE-2024-39329: Fixed username enumeration through timing difference for users with unusable passwords
    (bsc#1227593)
    - CVE-2024-39330: Fixed potential directory traversal in django.core.files.storage.Storage.save()
    (bsc#1227594)
    - CVE-2024-39614: Fixed potential denial-of-service through
    django.utils.translation.get_supported_language_variant() (bsc#1227595)
    - CVE-2023-23969: Fixed potential denial-of-service via Accept-Language headers (bsc#1207565)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227595");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-July/018995.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2bb7f556");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39329");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39330");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39614");
  script_set_attribute(attribute:"solution", value:
"Update the affected python3-Django package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23969");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
if (isnull(os_release) || os_release !~ "^SUSE") audit(AUDIT_OS_NOT, "openSUSE");
var os_ver = pregmatch(pattern: "^(SUSE[\d.]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'openSUSE 15', 'openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE (' + os_ver + ')', cpu);

var pkgs = [
    {'reference':'python3-Django-2.0.7-150000.1.20.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-Django');
}
