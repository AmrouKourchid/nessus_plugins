#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:3961. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234660);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/21");

  script_cve_id("CVE-2022-49541");
  script_xref(name:"RHSA", value:"2025:3961");

  script_name(english:"RHEL 9 : kpatch-patch-5_14_0-70_112_1, kpatch-patch-5_14_0-70_121_1, kpatch-patch-5_14_0-70_124_1, and kpatch-patch-5_14_0-70_85_1 (RHSA-2025:3961)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for kpatch-patch-5_14_0-70_112_1 / kpatch-patch-5_14_0-70_121_1 /
kpatch-patch-5_14_0-70_124_1 / kpatch-patch-5_14_0-70_85_1.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2025:3961 advisory.

    This is a kernel live patch module which can be loaded by the kpatch command line utility to modify the
    code of a running kernel.  This patch module is targeted for kernel-5.14.0-70.85.1.el9_0.

    Security Fix(es):

    * kernel: cifs: fix potential double free during failed mount (CVE-2022-49541)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2348119");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_3961.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d22bfbdd");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:3961");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kpatch-patch-5_14_0-70_112_1 / kpatch-patch-5_14_0-70_121_1 / kpatch-patch-5_14_0-70_124_1 / kpatch-
patch-5_14_0-70_85_1 packages based on the guidance in RHSA-2025:3961.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-49541");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(415);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-5_14_0-70_112_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-5_14_0-70_121_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-5_14_0-70_124_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpatch-patch-5_14_0-70_85_1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '9.0')) audit(AUDIT_OS_NOT, 'Red Hat 9.0', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var uname_r = get_kb_item("Host/uname-r");
if (empty_or_null(uname_r)) audit(AUDIT_UNKNOWN_APP_VER, "kernel");
if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2022-49541');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2025:3961');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}


var kernel_live_checks = [
  {
    'repo_relative_urls': [
      'content/e4s/rhel9/9.0/ppc64le/baseos/debug',
      'content/e4s/rhel9/9.0/ppc64le/baseos/os',
      'content/e4s/rhel9/9.0/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/baseos/debug',
      'content/e4s/rhel9/9.0/x86_64/baseos/os',
      'content/e4s/rhel9/9.0/x86_64/baseos/source/SRPMS'
    ],
    'kernels': {
      '5.14.0-70.112.1.el9_0.ppc64le': {
        'pkgs': [
          {'reference':'kpatch-patch-5_14_0-70_112_1-1-5.el9_0', 'sp':'0', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '5.14.0-70.112.1.el9_0.x86_64': {
        'pkgs': [
          {'reference':'kpatch-patch-5_14_0-70_112_1-1-5.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '5.14.0-70.121.1.el9_0.ppc64le': {
        'pkgs': [
          {'reference':'kpatch-patch-5_14_0-70_121_1-1-4.el9_0', 'sp':'0', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '5.14.0-70.121.1.el9_0.x86_64': {
        'pkgs': [
          {'reference':'kpatch-patch-5_14_0-70_121_1-1-4.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '5.14.0-70.124.1.el9_0.ppc64le': {
        'pkgs': [
          {'reference':'kpatch-patch-5_14_0-70_124_1-1-2.el9_0', 'sp':'0', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '5.14.0-70.124.1.el9_0.x86_64': {
        'pkgs': [
          {'reference':'kpatch-patch-5_14_0-70_124_1-1-2.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '5.14.0-70.85.1.el9_0.ppc64le': {
        'pkgs': [
          {'reference':'kpatch-patch-5_14_0-70_85_1-1-9.el9_0', 'sp':'0', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        ]
      },
      '5.14.0-70.85.1.el9_0.x86_64': {
        'pkgs': [
          {'reference':'kpatch-patch-5_14_0-70_85_1-1-9.el9_0', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
        ]
      }
    }
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:kernel_live_checks);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
var kernel_affected = FALSE;
foreach var kernel_array ( kernel_live_checks ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(kernel_array['repo_relative_urls'])) repo_relative_urls = kernel_array['repo_relative_urls'];
  var kpatch_details = kernel_array['kernels'][uname_r];
  if (empty_or_null(kpatch_details)) continue;
  kernel_affected = TRUE;
  foreach var pkg ( kpatch_details['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    var cves = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}
# No kpatch details found for the running kernel version
if (!kernel_affected) audit(AUDIT_INST_VER_NOT_VULN, 'kernel', uname_r);

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Update Services for SAP Solutions repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kpatch-patch-5_14_0-70_112_1 / kpatch-patch-5_14_0-70_121_1 / etc');
}
