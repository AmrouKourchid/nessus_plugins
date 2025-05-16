#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4433-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(213461);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/02");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4433-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : govulncheck-vulndb (SUSE-SU-2024:4433-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has a package installed that is affected by a vulnerability as
referenced in the SUSE-SU-2024:4433-1 advisory.

    - Update to version 0.0.20241218T202206 2024-12-18T20:22:06Z. (jsc#PED-11136)
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2024-3333

    - Update to version 0.0.20241218T163557 2024-12-18T16:35:57Z. (jsc#PED-11136)
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2024-3331 GHSA-9j3m-fr7q-jxfw
      * GO-2024-3334 GHSA-qqc8-rv37-79q5
      * GO-2024-3335 GHSA-xx83-cxmq-x89m
      * GO-2024-3336 GHSA-cwq8-g58r-32hg
      * GO-2024-3337 GHSA-69pr-78gv-7c6h
      * GO-2024-3338 GHSA-826h-p4c3-477p
      * GO-2024-3339 GHSA-8wcc-m6j2-qxvm
      * GO-2024-3340 GHSA-v647-h8jj-fw5r

    - Update to version 0.0.20241213T205935 2024-12-13T20:59:35Z. (jsc#PED-11136)
      Go CVE Numbering Authority IDs added or updated with aliases:
      * GO-2022-0635 GHSA-7f33-f4f5-xwgw
      * GO-2022-0646 GHSA-f5pg-7wfw-84q9
      * GO-2022-0828 GHSA-fx8w-mjvm-hvpc
      * GO-2023-2170 GHSA-q78c-gwqw-jcmc
      * GO-2023-2330 GHSA-7fxm-f474-hf8w
      * GO-2024-2901 GHSA-8hqg-whrw-pv92
      * GO-2024-3104 GHSA-846m-99qv-67mg
      * GO-2024-3122 GHSA-q3hw-3gm4-w5cr
      * GO-2024-3140 GHSA-xxxw-3j6h-q7h6
      * GO-2024-3169 GHSA-fhqq-8f65-5xfc
      * GO-2024-3186 GHSA-586p-749j-fhwp
      * GO-2024-3205 GHSA-xhr3-wf7j-h255
      * GO-2024-3218 GHSA-mqr9-hjr8-2m9w
      * GO-2024-3245 GHSA-95j2-w8x7-hm88
      * GO-2024-3248 GHSA-p26r-gfgc-c47h
      * GO-2024-3259 GHSA-p7mv-53f2-4cwj
      * GO-2024-3265 GHSA-gppm-hq3p-h4rp
      * GO-2024-3268 GHSA-r864-28pw-8682
      * GO-2024-3279 GHSA-7225-m954-23v7
      * GO-2024-3282 GHSA-r4pg-vg54-wxx4
      * GO-2024-3286 GHSA-27wf-5967-98gx
      * GO-2024-3293
      * GO-2024-3295 GHSA-55v3-xh23-96gh
      * GO-2024-3302 GHSA-px8v-pp82-rcvr
      * GO-2024-3306 GHSA-7mwh-q3xm-qh6p
      * GO-2024-3312 GHSA-4c49-9fpc-hc3v
      * GO-2024-3313 GHSA-jpmc-7p9c-4rxf
      * GO-2024-3314 GHSA-c2xf-9v2r-r2rx
      * GO-2024-3315
      * GO-2024-3319 GHSA-vmg2-r3xv-r3xf
      * GO-2024-3321 GHSA-v778-237x-gjrc
      * GO-2024-3323 GHSA-25w9-wqfq-gwqx
      * GO-2024-3324 GHSA-4pjc-pwgq-q9jp
      * GO-2024-3325 GHSA-c7xh-gjv4-4jgv
      * GO-2024-3326 GHSA-fqj6-whhx-47p7
      * GO-2024-3327 GHSA-xx68-37v4-4596
      * GO-2024-3330 GHSA-7prj-hgx4-2xc3

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-December/020055.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3010126");
  script_set_attribute(attribute:"solution", value:
"Update the affected govulncheck-vulndb package.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/02");

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
if (! preg(pattern:"^(SLES15|SUSE15\.5|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'govulncheck-vulndb-0.0.20241218T202206-150000.1.23.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'govulncheck-vulndb-0.0.20241218T202206-150000.1.23.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'govulncheck-vulndb-0.0.20241218T202206-150000.1.23.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'govulncheck-vulndb-0.0.20241218T202206-150000.1.23.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']}
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
