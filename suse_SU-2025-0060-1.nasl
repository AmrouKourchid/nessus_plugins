#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0060-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(213966);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id(
    "CVE-2024-9779",
    "CVE-2024-12678",
    "CVE-2024-25131",
    "CVE-2024-25133",
    "CVE-2024-28892",
    "CVE-2024-43803",
    "CVE-2024-45338",
    "CVE-2024-45387",
    "CVE-2024-54148",
    "CVE-2024-55196",
    "CVE-2024-55947",
    "CVE-2024-56362",
    "CVE-2024-56513",
    "CVE-2024-56514",
    "CVE-2025-21609",
    "CVE-2025-21613",
    "CVE-2025-21614",
    "CVE-2025-22130"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0060-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : govulncheck-vulndb (SUSE-SU-2025:0060-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as
referenced in the SUSE-SU-2025:0060-1 advisory.

    - Update to version 0.0.20250108T191942 2025-01-08T19:19:42Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2025-3371 GHSA-2r2v-9pf8-6342
      * GO-2025-3374 CVE-2025-22130 GHSA-j4jw-m6xr-fv6c

    - Update to version 0.0.20250107T160406 2025-01-07T16:04:06Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2025-3363 GO-2025-3364 GO-2025-3367 GO-2025-3368
      * GO-2024-3355 CVE-2024-54148 GHSA-r7j8-5h9c-f6fx
      * GO-2024-3356 CVE-2024-55947 GHSA-qf5v-rp47-55gg
      * GO-2024-3357 CVE-2024-56362 GHSA-xwx7-p63r-2rj8
      * GO-2024-3358 CVE-2024-45387 GHSA-vq94-9pfv-ccqr
      * GO-2024-3359 CVE-2024-28892 GHSA-5qww-56gc-f66c
      * GO-2024-3360 CVE-2024-25133 GHSA-wgqq-9qh8-wvqv
      * GO-2025-3361 CVE-2024-55196 GHSA-rv83-h68q-c4wq
      * GO-2025-3362 CVE-2025-21609 GHSA-8fx8-pffw-w498
      * GO-2025-3363 CVE-2024-56514 GHSA-cwrh-575j-8vr3
      * GO-2025-3364 CVE-2024-56513 GHSA-mg7w-c9x2-xh7r
      * GO-2025-3367 CVE-2025-21614 GHSA-r9px-m959-cxf4
      * GO-2025-3368 CVE-2025-21613 GHSA-v725-9546-7q7m

    - Update to version 0.0.20241220T214820 2024-12-20T21:48:20Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2024-3101 GHSA-75qh-gg76-p2w4
      * GO-2024-3339 GHSA-8wcc-m6j2-qxvm

    - Update to version 0.0.20241220T203729 2024-12-20T20:37:29Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2024-3101 GHSA-75qh-gg76-p2w4
      * GO-2024-3109 CVE-2024-43803 GHSA-pqfh-xh7w-7h3p
      * GO-2024-3333 CVE-2024-45338 GHSA-w32m-9786-jp63
      * GO-2024-3342 GHSA-hxr6-2p24-hf98
      * GO-2024-3343 CVE-2024-9779 GHSA-jhh6-6fhp-q2xp
      * GO-2024-3344 GHSA-32gq-x56h-299c
      * GO-2024-3349 CVE-2024-25131 GHSA-77c2-c35q-254w
      * GO-2024-3350 GHSA-5pf6-cq2v-23ww
      * GO-2024-3354 CVE-2024-12678 GHSA-hr68-hvgv-xxqf

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-January/020087.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?179aa6b1");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-12678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-25131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-25133");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-28892");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45338");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45387");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-54148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-55196");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-55947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56362");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56513");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56514");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9779");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21613");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22130");
  script_set_attribute(attribute:"solution", value:
"Update the affected govulncheck-vulndb package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/U:Clear");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-55947");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-21613");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:govulncheck-vulndb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'govulncheck-vulndb-0.0.20250108T191942-150000.1.26.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'govulncheck-vulndb-0.0.20250108T191942-150000.1.26.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']}
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
