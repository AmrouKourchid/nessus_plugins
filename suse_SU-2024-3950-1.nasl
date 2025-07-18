#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3950-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(210710);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/27");

  script_cve_id(
    "CVE-2024-0132",
    "CVE-2024-0133",
    "CVE-2024-8185",
    "CVE-2024-10005",
    "CVE-2024-10006",
    "CVE-2024-10086",
    "CVE-2024-10452",
    "CVE-2024-39720",
    "CVE-2024-46872",
    "CVE-2024-47401",
    "CVE-2024-50052",
    "CVE-2024-50354"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3950-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : govulncheck-vulndb (SUSE-SU-2024:3950-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:3950-1 advisory.

    - Update to version 0.0.20241104T154416 2024-11-04T15:44:16Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2024-3233 CVE-2024-46872 GHSA-762g-9p7f-mrww
      * GO-2024-3234 CVE-2024-47401 GHSA-762v-rq7q-ff97
      * GO-2024-3235 CVE-2024-50052 GHSA-g376-m3h3-mj4r
      * GO-2024-3237 CVE-2024-0133 GHSA-f748-7hpg-88ch
      * GO-2024-3239 CVE-2024-0132 GHSA-mjjw-553x-87pq
      * GO-2024-3240 CVE-2024-10452 GHSA-66c4-2g2v-54qw
      * GO-2024-3241 CVE-2024-10006 GHSA-5c4w-8hhh-3c3h
      * GO-2024-3242 CVE-2024-10086 GHSA-99wr-c2px-grmh
      * GO-2024-3243 CVE-2024-10005 GHSA-chgm-7r52-whjj

    - Update to version 0.0.20241101T215616 2024-11-01T21:56:16Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2024-3244 CVE-2024-50354 GHSA-cph5-3pgr-c82g
      * GO-2024-3245 CVE-2024-39720
      * GO-2024-3246 CVE-2024-8185 GHSA-g233-2p4r-3q7v

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-November/019795.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89883214");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0132");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0133");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-10005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-10006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-10086");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-10452");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47401");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50052");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50354");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8185");
  script_set_attribute(attribute:"solution", value:
"Update the affected govulncheck-vulndb package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0132");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:govulncheck-vulndb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'govulncheck-vulndb-0.0.20241104T154416-150000.1.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'govulncheck-vulndb-0.0.20241104T154416-150000.1.12.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'govulncheck-vulndb-0.0.20241104T154416-150000.1.12.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'govulncheck-vulndb-0.0.20241104T154416-150000.1.12.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']}
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
