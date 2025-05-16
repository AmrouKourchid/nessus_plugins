#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0429-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(216199);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id(
    "CVE-2022-47930",
    "CVE-2024-3727",
    "CVE-2024-9312",
    "CVE-2024-9313",
    "CVE-2024-10846",
    "CVE-2024-11741",
    "CVE-2024-13484",
    "CVE-2024-35177",
    "CVE-2024-45336",
    "CVE-2024-45339",
    "CVE-2024-45340",
    "CVE-2024-45341",
    "CVE-2024-47770",
    "CVE-2024-50354",
    "CVE-2025-0750",
    "CVE-2025-22865",
    "CVE-2025-22866",
    "CVE-2025-22867",
    "CVE-2025-23216",
    "CVE-2025-24366",
    "CVE-2025-24369",
    "CVE-2025-24371",
    "CVE-2025-24376",
    "CVE-2025-24784",
    "CVE-2025-24786",
    "CVE-2025-24787",
    "CVE-2025-24883",
    "CVE-2025-24884"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0429-1");
  script_xref(name:"IAVB", value:"2025-B-0024-S");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : govulncheck-vulndb (SUSE-SU-2025:0429-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as
referenced in the SUSE-SU-2025:0429-1 advisory.

    - Update to version 0.0.20250207T224745 2025-02-07T22:47:45Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2025-3456 CVE-2025-24786 GHSA-9r4c-jwx3-3j76
      * GO-2025-3457 CVE-2025-24787 GHSA-c7w4-9wv8-7x7c
      * GO-2025-3458 CVE-2025-24366 GHSA-vj7w-3m8c-6vpx

    - Update to version 0.0.20250206T175003 2025-02-06T17:50:03Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2023-1867 CVE-2022-47930 GHSA-c58h-qv6g-fw74
      * GO-2024-3244 CVE-2024-50354 GHSA-cph5-3pgr-c82g

    - Update to version 0.0.20250206T165438 2025-02-06T16:54:38Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2025-3428 CVE-2025-22867
      * GO-2025-3447 CVE-2025-22866

    - Update to version 0.0.20250205T232745 2025-02-05T23:27:45Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2025-3408
      * GO-2025-3448 GHSA-23qp-3c2m-xx6w
      * GO-2025-3449 GHSA-mx2j-7cmv-353c
      * GO-2025-3450 GHSA-w7wm-2425-7p2h
      * GO-2025-3454 GHSA-mj4v-hp69-27x5
      * GO-2025-3455 GHSA-vqv5-385r-2hf8

    - Update to version 0.0.20250205T003520 2025-02-05T00:35:20Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2025-3451

    - Update to version 0.0.20250204T220613 2025-02-04T22:06:13Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2025-3431 CVE-2025-24884 GHSA-hcr5-wv4p-h2g2
      * GO-2025-3433 CVE-2025-23216 GHSA-47g2-qmh2-749v
      * GO-2025-3434 CVE-2025-24376 GHSA-fc89-jghx-8pvg
      * GO-2025-3435 CVE-2025-24784 GHSA-756x-m4mj-q96c
      * GO-2025-3436 CVE-2025-24883 GHSA-q26p-9cq4-7fc2
      * GO-2025-3437 GHSA-274v-mgcv-cm8j
      * GO-2025-3438 CVE-2024-11741 GHSA-wxcc-2f3q-4h58
      * GO-2025-3442 CVE-2025-24371 GHSA-22qq-3xwm-r5x4
      * GO-2025-3443 GHSA-r3r4-g7hq-pq4f
      * GO-2025-3444 CVE-2024-35177
      * GO-2025-3445 CVE-2024-47770

    - Use standard RPM macros to unpack the source and populate a
      working directory. Fixes build with RPM 4.20.

    - Update to version 0.0.20250130T185858 2025-01-30T18:58:58Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2024-2842 CVE-2024-3727 GHSA-6wvf-f2vw-3425
      * GO-2024-3181 CVE-2024-9313 GHSA-x5q3-c8rm-w787
      * GO-2024-3188 CVE-2024-9312 GHSA-4gfw-wf7c-w6g2
      * GO-2025-3372 CVE-2024-45339 GHSA-6wxm-mpqj-6jpf
      * GO-2025-3373 CVE-2024-45341
      * GO-2025-3383 CVE-2024-45340
      * GO-2025-3408
      * GO-2025-3412 CVE-2024-10846 GHSA-36gq-35j3-p9r9
      * GO-2025-3420 CVE-2024-45336
      * GO-2025-3421 CVE-2025-22865
      * GO-2025-3424 CVE-2025-24369
      * GO-2025-3426 CVE-2025-0750 GHSA-hp5j-2585-qx6g
      * GO-2025-3427 CVE-2024-13484 GHSA-58fx-7v9q-3g56

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-February/020315.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a9afd6ca");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-47930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-10846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-11741");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-13484");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35177");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3727");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45336");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45339");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45340");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45341");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47770");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50354");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9313");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0750");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-23216");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24366");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24369");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24371");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24376");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24787");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24884");
  script_set_attribute(attribute:"solution", value:
"Update the affected govulncheck-vulndb package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-47930");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2025-24883");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:govulncheck-vulndb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'reference':'govulncheck-vulndb-0.0.20250207T224745-150000.1.32.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'govulncheck-vulndb-0.0.20250207T224745-150000.1.32.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'govulncheck-vulndb');
}
