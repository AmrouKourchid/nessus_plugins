#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:9921. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211758);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/24");

  script_cve_id("CVE-2024-38796");
  script_xref(name:"RHSA", value:"2024:9921");

  script_name(english:"RHEL 9 : edk2 (RHSA-2024:9921)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for edk2.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2024:9921 advisory.

    EDK (Embedded Development Kit) is a project to enable UEFI support for Virtual Machines. This package
    contains a sample 64-bit UEFI firmware for QEMU and KVM.

    Security Fix(es):

    * edk2: Integer overflows in PeCoffLoaderRelocateImage (CVE-2024-38796)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2315390");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_9921.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa1d7bf3");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:9921");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL edk2 package based on the guidance in RHSA-2024:9921.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:S/C:P/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38796");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:edk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:edk2-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:edk2-ovmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:edk2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:edk2-tools-doc");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '9.4')) audit(AUDIT_OS_NOT, 'Red Hat 9.4', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel9/9.4/x86_64/appstream/debug',
      'content/aus/rhel9/9.4/x86_64/appstream/os',
      'content/aus/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.4/aarch64/appstream/debug',
      'content/e4s/rhel9/9.4/aarch64/appstream/os',
      'content/e4s/rhel9/9.4/aarch64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.4/x86_64/appstream/debug',
      'content/e4s/rhel9/9.4/x86_64/appstream/os',
      'content/e4s/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/eus/rhel9/9.4/aarch64/appstream/debug',
      'content/eus/rhel9/9.4/aarch64/appstream/os',
      'content/eus/rhel9/9.4/aarch64/appstream/source/SRPMS',
      'content/eus/rhel9/9.4/aarch64/codeready-builder/debug',
      'content/eus/rhel9/9.4/aarch64/codeready-builder/os',
      'content/eus/rhel9/9.4/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.4/x86_64/appstream/debug',
      'content/eus/rhel9/9.4/x86_64/appstream/os',
      'content/eus/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/eus/rhel9/9.4/x86_64/codeready-builder/debug',
      'content/eus/rhel9/9.4/x86_64/codeready-builder/os',
      'content/eus/rhel9/9.4/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'edk2-aarch64-20231122-6.el9_4.6', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'edk2-ovmf-20231122-6.el9_4.6', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'edk2-tools-20231122-6.el9_4.6', 'sp':'4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'edk2-tools-20231122-6.el9_4.6', 'sp':'4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'edk2-tools-doc-20231122-6.el9_4.6', 'sp':'4', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
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

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support repository.\n' +
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'edk2-aarch64 / edk2-ovmf / edk2-tools / edk2-tools-doc');
}
