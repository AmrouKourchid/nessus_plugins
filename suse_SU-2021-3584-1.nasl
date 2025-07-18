#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3584-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154744);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/13");

  script_cve_id(
    "CVE-2020-21529",
    "CVE-2020-21530",
    "CVE-2020-21531",
    "CVE-2020-21532",
    "CVE-2020-21533",
    "CVE-2020-21534",
    "CVE-2020-21535",
    "CVE-2020-21680",
    "CVE-2020-21681",
    "CVE-2020-21682",
    "CVE-2020-21683",
    "CVE-2021-32280"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3584-1");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : transfig (SUSE-SU-2021:3584-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 host has a package installed that is affected by multiple vulnerabilities as
referenced in the SUSE-SU-2021:3584-1 advisory.

  - fig2dev 3.2.7b contains a stack buffer overflow in the bezier_spline function in genepic.c.
    (CVE-2020-21529)

  - fig2dev 3.2.7b contains a segmentation fault in the read_objects function in read.c. (CVE-2020-21530)

  - fig2dev 3.2.7b contains a global buffer overflow in the conv_pattern_index function in gencgm.c.
    (CVE-2020-21531)

  - fig2dev 3.2.7b contains a global buffer overflow in the setfigfont function in genepic.c. (CVE-2020-21532)

  - fig2dev 3.2.7b contains a stack buffer overflow in the read_textobject function in read.c.
    (CVE-2020-21533)

  - fig2dev 3.2.7b contains a global buffer overflow in the get_line function in read.c. (CVE-2020-21534)

  - fig2dev 3.2.7b contains a segmentation fault in the gencgm_start function in gencgm.c. (CVE-2020-21535)

  - A stack-based buffer overflow in the put_arrow() component in genpict2e.c of fig2dev 3.2.7b allows
    attackers to cause a denial of service (DOS) via converting a xfig file into pict2e format.
    (CVE-2020-21680)

  - A global buffer overflow in the set_color component in genge.c of fig2dev 3.2.7b allows attackers to cause
    a denial of service (DOS) via converting a xfig file into ge format. (CVE-2020-21681)

  - A global buffer overflow in the set_fill component in genge.c of fig2dev 3.2.7b allows attackers to cause
    a denial of service (DOS) via converting a xfig file into ge format. (CVE-2020-21682)

  - A global buffer overflow in the shade_or_tint_name_after_declare_color in genpstricks.c of fig2dev 3.2.7b
    allows attackers to cause a denial of service (DOS) via converting a xfig file into pstricks format.
    (CVE-2020-21683)

  - An issue was discovered in fig2dev before 3.2.8.. A NULL pointer dereference exists in the function
    compute_closed_spline() located in trans_spline.c. It allows an attacker to cause Denial of Service. The
    fixed version of fig2dev is 3.2.8. (CVE-2021-32280)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189325");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21529");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21530");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21533");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21534");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21682");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-21683");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32280");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-October/009682.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4497296");
  script_set_attribute(attribute:"solution", value:
"Update the affected transfig package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32280");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:transfig");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'reference':'transfig-3.2.8b-4.15.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.2']},
    {'reference':'transfig-3.2.8b-4.15.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.2']},
    {'reference':'transfig-3.2.8b-4.15.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.3']},
    {'reference':'transfig-3.2.8b-4.15.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.3']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'transfig');
}
