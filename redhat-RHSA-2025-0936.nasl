#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:0936. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214929);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/04");

  script_cve_id("CVE-2024-52533");
  script_xref(name:"RHSA", value:"2025:0936");

  script_name(english:"RHEL 9 : mingw-glib2 (RHSA-2025:0936)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for mingw-glib2.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2025:0936 advisory.

    GLib provides the core application building blocks for libraries and applications written in C. It
    provides the core object system used in GNOME, the main loop implementation, and a large set of utility
    functions for strings and common data structures.

    Security Fix(es):

    * glib: buffer overflow in set_connect_msg() (CVE-2024-52533)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2325340");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_0936.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?19070dc3");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:0936");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL mingw-glib2 package based on the guidance in RHSA-2025:0936.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52533");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(193);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mingw-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mingw32-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mingw32-glib2-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mingw64-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mingw64-glib2-static");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel9/9.1/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.1/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.1/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.1/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.1/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.1/s390x/codeready-builder/os',
      'content/dist/rhel9/9.1/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.2/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.2/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.2/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.2/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.2/s390x/codeready-builder/os',
      'content/dist/rhel9/9.2/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.3/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.3/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.3/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.3/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.3/s390x/codeready-builder/os',
      'content/dist/rhel9/9.3/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.4/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.4/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.4/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.4/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.4/s390x/codeready-builder/os',
      'content/dist/rhel9/9.4/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.5/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.5/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.5/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.5/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.5/s390x/codeready-builder/os',
      'content/dist/rhel9/9.5/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.6/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.6/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.6/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.6/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.6/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.6/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.6/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.6/s390x/codeready-builder/os',
      'content/dist/rhel9/9.6/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.6/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.6/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.6/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9/aarch64/codeready-builder/os',
      'content/dist/rhel9/9/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/s390x/codeready-builder/debug',
      'content/dist/rhel9/9/s390x/codeready-builder/os',
      'content/dist/rhel9/9/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9/x86_64/codeready-builder/os',
      'content/dist/rhel9/9/x86_64/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/aarch64/codeready-builder/debug',
      'content/public/ubi/dist/ubi9/9/aarch64/codeready-builder/os',
      'content/public/ubi/dist/ubi9/9/aarch64/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/ppc64le/codeready-builder/debug',
      'content/public/ubi/dist/ubi9/9/ppc64le/codeready-builder/os',
      'content/public/ubi/dist/ubi9/9/ppc64le/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/s390x/codeready-builder/debug',
      'content/public/ubi/dist/ubi9/9/s390x/codeready-builder/os',
      'content/public/ubi/dist/ubi9/9/s390x/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/x86_64/codeready-builder/debug',
      'content/public/ubi/dist/ubi9/9/x86_64/codeready-builder/os',
      'content/public/ubi/dist/ubi9/9/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'mingw32-glib2-2.78.6-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mingw32-glib2-static-2.78.6-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mingw64-glib2-2.78.6-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'mingw64-glib2-static-2.78.6-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mingw32-glib2 / mingw32-glib2-static / mingw64-glib2 / etc');
}
