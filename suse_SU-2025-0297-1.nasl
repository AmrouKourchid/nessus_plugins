#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0297-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(214906);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2024-11218",
    "CVE-2024-36402",
    "CVE-2024-36403",
    "CVE-2024-45336",
    "CVE-2024-45339",
    "CVE-2024-45340",
    "CVE-2024-45341",
    "CVE-2024-51491",
    "CVE-2024-52281",
    "CVE-2024-52594",
    "CVE-2024-52602",
    "CVE-2024-52791",
    "CVE-2024-53263",
    "CVE-2024-56138",
    "CVE-2024-56323",
    "CVE-2024-56515",
    "CVE-2025-0377",
    "CVE-2025-20033",
    "CVE-2025-20086",
    "CVE-2025-20088",
    "CVE-2025-20621",
    "CVE-2025-21088",
    "CVE-2025-22149",
    "CVE-2025-22445",
    "CVE-2025-22449",
    "CVE-2025-22865",
    "CVE-2025-23028",
    "CVE-2025-23047",
    "CVE-2025-23208",
    "CVE-2025-24030",
    "CVE-2025-24337",
    "CVE-2025-24354",
    "CVE-2025-24355"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0297-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : govulncheck-vulndb (SUSE-SU-2025:0297-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as
referenced in the SUSE-SU-2025:0297-1 advisory.

    - Update to version 0.0.20250128T150132 2025-01-28T15:01:32Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2025-3409 CVE-2025-23208 GHSA-c9p4-xwr9-rfhx
      * GO-2025-3410 CVE-2025-24337 GHSA-3qc3-mx6x-267h
      * GO-2025-3413 CVE-2025-0377 GHSA-wpfp-cm49-9m9q
      * GO-2025-3414 CVE-2024-11218 GHSA-5vpc-35f4-r8w6
      * GO-2025-3415 CVE-2025-23028 GHSA-9m5p-c77c-f9j7
      * GO-2025-3416 CVE-2025-23047 GHSA-h78m-j95m-5356
      * GO-2025-3418 CVE-2025-24030 GHSA-j777-63hf-hx76
      * GO-2025-3419 CVE-2025-24355 GHSA-v34r-vj4r-38j6
      * GO-2025-3422 CVE-2025-24354

    - Update to version 0.0.20250128T004730 2025-01-28T00:47:30Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2025-3372 CVE-2024-45339
      * GO-2025-3373 CVE-2024-45341
      * GO-2025-3383 CVE-2024-45340
      * GO-2025-3420 CVE-2024-45336
      * GO-2025-3421 CVE-2025-22865

    - Update to version 0.0.20250117T214834 2025-01-17T21:48:34Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2025-3392 CVE-2025-20086 GHSA-5m7j-6gc4-ff5g
      * GO-2025-3393 CVE-2025-21088 GHSA-8j3q-gc9x-7972
      * GO-2025-3394 CVE-2025-20088 GHSA-45v9-w9fh-33j6
      * GO-2025-3396 CVE-2024-52594
      * GO-2025-3397 CVE-2024-36402 GHSA-8vmr-h7h5-cqhg
      * GO-2025-3398 CVE-2024-52791 GHSA-gp86-q8hg-fpxj
      * GO-2025-3399 CVE-2024-52602 GHSA-r6jg-jfv6-2fjv
      * GO-2025-3400 CVE-2024-56515 GHSA-rcxc-wjgw-579r
      * GO-2025-3401 CVE-2024-36403 GHSA-vc2m-hw89-qjxf
      * GO-2025-3407 CVE-2025-20621 GHSA-w6xh-c82w-h997

    - Update to version 0.0.20250115T172141 2025-01-15T17:21:41Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2025-3381 CVE-2024-56138 GHSA-45v3-38pc-874v
      * GO-2025-3382 CVE-2024-51491 GHSA-qjh3-4j3h-vmwp
      * GO-2025-3384 CVE-2024-56323 GHSA-32q6-rr98-cjqv
      * GO-2025-3390 CVE-2024-53263 GHSA-q6r2-x2cc-vrp7
      * GO-2025-3391 CVE-2024-52281 GHSA-2v2w-8v8c-wcm9

    - Update to version 0.0.20250109T194159 2025-01-09T19:41:59Z.
      Refs jsc#PED-11136
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2025-3376 CVE-2025-22149 GHSA-675f-rq2r-jw82
      * GO-2025-3377 CVE-2025-22449 GHSA-q8fg-cp3q-5jwm
      * GO-2025-3379 CVE-2025-20033 GHSA-2549-xh72-qrpm
      * GO-2025-3380 CVE-2025-22445 GHSA-7rgp-4j56-fm79

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-January/020248.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?138a5b87");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-11218");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36403");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45336");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45339");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45340");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45341");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-51491");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-52281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-52594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-52602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-52791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53263");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56323");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56515");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-0377");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-20033");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-20086");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-20088");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-20621");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21088");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22149");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22445");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22449");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-23028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-23047");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-23208");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24030");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24337");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24354");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-24355");
  script_set_attribute(attribute:"solution", value:
"Update the affected govulncheck-vulndb package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11218");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-52281");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-53263");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/03");

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
    {'reference':'govulncheck-vulndb-0.0.20250128T150132-150000.1.29.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'govulncheck-vulndb-0.0.20250128T150132-150000.1.29.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']}
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
