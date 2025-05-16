#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1673-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(197551);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/21");

  script_cve_id(
    "CVE-2020-35654",
    "CVE-2021-23437",
    "CVE-2021-25289",
    "CVE-2021-25290",
    "CVE-2021-25292",
    "CVE-2021-25293",
    "CVE-2021-27921",
    "CVE-2021-27922",
    "CVE-2021-27923",
    "CVE-2021-34552",
    "CVE-2022-22815",
    "CVE-2022-22816"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1673-1");

  script_name(english:"openSUSE 15 Security Update : python-Pillow (SUSE-SU-2024:1673-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
SUSE-SU-2024:1673-1 advisory.

  - In Pillow before 8.1.0, TiffDecode has a heap-based buffer overflow when decoding crafted YCbCr files
    because of certain interpretation conflicts with LibTIFF in RGBA mode. (CVE-2020-35654)

  - The package pillow 5.2.0 and before 8.3.2 are vulnerable to Regular Expression Denial of Service (ReDoS)
    via the getrgb function. (CVE-2021-23437)

  - An issue was discovered in Pillow before 8.1.1. TiffDecode has a heap-based buffer overflow when decoding
    crafted YCbCr files because of certain interpretation conflicts with LibTIFF in RGBA mode. NOTE: this
    issue exists because of an incomplete fix for CVE-2020-35654. (CVE-2021-25289)

  - An issue was discovered in Pillow before 8.1.1. In TiffDecode.c, there is a negative-offset memcpy with an
    invalid size. (CVE-2021-25290)

  - An issue was discovered in Pillow before 8.1.1. The PDF parser allows a regular expression DoS (ReDoS)
    attack via a crafted PDF file because of a catastrophic backtracking regex. (CVE-2021-25292)

  - An issue was discovered in Pillow before 8.1.1. There is an out-of-bounds read in SGIRleDecode.c.
    (CVE-2021-25293)

  - Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the
    reported size of a contained image is not properly checked for a BLP container, and thus an attempted
    memory allocation can be very large. (CVE-2021-27921)

  - Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the
    reported size of a contained image is not properly checked for an ICNS container, and thus an attempted
    memory allocation can be very large. (CVE-2021-27922)

  - Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the
    reported size of a contained image is not properly checked for an ICO container, and thus an attempted
    memory allocation can be very large. (CVE-2021-27923)

  - Pillow through 8.2.0 and PIL (aka Python Imaging Library) through 1.1.7 allow an attacker to pass
    controlled parameters directly into a convert function to trigger a buffer overflow in Convert.c.
    (CVE-2021-34552)

  - path_getbbox in path.c in Pillow before 9.0.0 improperly initializes ImagePath.Path. (CVE-2022-22815)

  - path_getbbox in path.c in Pillow before 9.0.0 has a buffer over-read during initialization of
    ImagePath.Path. (CVE-2022-22816)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183102");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183110");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194551");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194552");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-May/018541.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0aff4692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35654");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23437");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25293");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-34552");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-22816");
  script_set_attribute(attribute:"solution", value:
"Update the affected python3-Pillow and / or python3-Pillow-tk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34552");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/21");

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
    {'reference':'python3-Pillow-7.2.0-150300.3.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python3-Pillow-tk-7.2.0-150300.3.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-Pillow / python3-Pillow-tk');
}
