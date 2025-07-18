#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4042-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212587);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2024-10389",
    "CVE-2024-10975",
    "CVE-2024-45794",
    "CVE-2024-48057",
    "CVE-2024-51735",
    "CVE-2024-51744",
    "CVE-2024-51746"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4042-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : govulncheck-vulndb (SUSE-SU-2024:4042-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:4042-1 advisory.

    - Update to version 0.0.20241112T145010 2024-11-12T14:50:10Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2024-3250 CVE-2024-51744 GHSA-29wx-vh33-7x7r

    - Update to version 0.0.20241108T172500 2024-11-08T17:25:00Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2024-3260 CVE-2024-45794 GHSA-q78v-cv36-8fxj
      * GO-2024-3262 CVE-2024-10975 GHSA-2w5v-x29g-jw7j

    - Update to version 0.0.20241106T172143 2024-11-06T17:21:43Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2024-3251 CVE-2024-10389 GHSA-q3rp-vvm7-j8jg
      * GO-2024-3252 CVE-2024-51746 GHSA-8pmp-678w-c8xx
      * GO-2024-3253 CVE-2024-48057 GHSA-ghx4-cgxw-7h9p
      * GO-2024-3254 CVE-2024-51735 GHSA-wvv7-wm5v-w2gv

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-November/019840.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6c46171");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-10389");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-10975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45794");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-48057");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-51735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-51744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-51746");
  script_set_attribute(attribute:"solution", value:
"Update the affected govulncheck-vulndb package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45794");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-51735");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:govulncheck-vulndb");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'govulncheck-vulndb-0.0.20241112T145010-150000.1.17.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'govulncheck-vulndb-0.0.20241112T145010-150000.1.17.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'govulncheck-vulndb-0.0.20241112T145010-150000.1.17.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'govulncheck-vulndb-0.0.20241112T145010-150000.1.17.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'govulncheck-vulndb');
}
