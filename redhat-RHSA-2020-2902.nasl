##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2902. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(138451);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2020-12861", "CVE-2020-12865");
  script_xref(name:"RHSA", value:"2020:2902");

  script_name(english:"RHEL 8 : sane-backends (RHSA-2020:2902)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for sane-backends.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:2902 advisory.

    Scanner Access Now Easy (SANE) is a universal scanner interface. The SANE application programming
    interface (API) provides standardized access to any raster image scanner hardware (for example, flatbed
    scanners, hand-held scanners, video and still cameras, and frame-grabbers).

    Security Fix(es):

    * sane-backends: Heap buffer overflow in epsonds_net_read in epsonds-net.c (CVE-2020-12861)

    * sane-backends: Heap buffer overflow in esci2_img (CVE-2020-12865)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_2902.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?601659f8");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:2902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1850556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1850598");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL sane-backends package based on the guidance in RHSA-2020:2902.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12861");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(122, 190);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sane-backends");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sane-backends-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sane-backends-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sane-backends-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sane-backends-drivers-cameras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sane-backends-drivers-scanners");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sane-backends-libs");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','8.2'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.2/x86_64/appstream/debug',
      'content/aus/rhel8/8.2/x86_64/appstream/os',
      'content/aus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.2/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.2/ppc64le/appstream/os',
      'content/e4s/rhel8/8.2/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.2/x86_64/appstream/debug',
      'content/e4s/rhel8/8.2/x86_64/appstream/os',
      'content/e4s/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/aarch64/appstream/debug',
      'content/eus/rhel8/8.2/aarch64/appstream/os',
      'content/eus/rhel8/8.2/aarch64/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/ppc64le/appstream/debug',
      'content/eus/rhel8/8.2/ppc64le/appstream/os',
      'content/eus/rhel8/8.2/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/s390x/appstream/debug',
      'content/eus/rhel8/8.2/s390x/appstream/os',
      'content/eus/rhel8/8.2/s390x/appstream/source/SRPMS',
      'content/eus/rhel8/8.2/x86_64/appstream/debug',
      'content/eus/rhel8/8.2/x86_64/appstream/os',
      'content/eus/rhel8/8.2/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.2/x86_64/appstream/debug',
      'content/tus/rhel8/8.2/x86_64/appstream/os',
      'content/tus/rhel8/8.2/x86_64/appstream/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'sane-backends-1.0.27-19.el8_2.1', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sane-backends-daemon-1.0.27-19.el8_2.1', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sane-backends-devel-1.0.27-19.el8_2.1', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sane-backends-doc-1.0.27-19.el8_2.1', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sane-backends-drivers-cameras-1.0.27-19.el8_2.1', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sane-backends-drivers-scanners-1.0.27-19.el8_2.1', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sane-backends-libs-1.0.27-19.el8_2.1', 'sp':'2', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8.10/aarch64/appstream/debug',
      'content/dist/rhel8/8.10/aarch64/appstream/os',
      'content/dist/rhel8/8.10/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.10/ppc64le/appstream/debug',
      'content/dist/rhel8/8.10/ppc64le/appstream/os',
      'content/dist/rhel8/8.10/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.10/s390x/appstream/debug',
      'content/dist/rhel8/8.10/s390x/appstream/os',
      'content/dist/rhel8/8.10/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/appstream/debug',
      'content/dist/rhel8/8.10/x86_64/appstream/os',
      'content/dist/rhel8/8.10/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/aarch64/appstream/debug',
      'content/dist/rhel8/8.6/aarch64/appstream/os',
      'content/dist/rhel8/8.6/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/appstream/debug',
      'content/dist/rhel8/8.6/ppc64le/appstream/os',
      'content/dist/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/s390x/appstream/debug',
      'content/dist/rhel8/8.6/s390x/appstream/os',
      'content/dist/rhel8/8.6/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/appstream/debug',
      'content/dist/rhel8/8.6/x86_64/appstream/os',
      'content/dist/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/aarch64/appstream/debug',
      'content/dist/rhel8/8.8/aarch64/appstream/os',
      'content/dist/rhel8/8.8/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/appstream/debug',
      'content/dist/rhel8/8.8/ppc64le/appstream/os',
      'content/dist/rhel8/8.8/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/s390x/appstream/debug',
      'content/dist/rhel8/8.8/s390x/appstream/os',
      'content/dist/rhel8/8.8/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/appstream/debug',
      'content/dist/rhel8/8.8/x86_64/appstream/os',
      'content/dist/rhel8/8.8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/aarch64/appstream/debug',
      'content/dist/rhel8/8.9/aarch64/appstream/os',
      'content/dist/rhel8/8.9/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/appstream/debug',
      'content/dist/rhel8/8.9/ppc64le/appstream/os',
      'content/dist/rhel8/8.9/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/s390x/appstream/debug',
      'content/dist/rhel8/8.9/s390x/appstream/os',
      'content/dist/rhel8/8.9/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/appstream/debug',
      'content/dist/rhel8/8.9/x86_64/appstream/os',
      'content/dist/rhel8/8.9/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8/aarch64/appstream/debug',
      'content/dist/rhel8/8/aarch64/appstream/os',
      'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/appstream/debug',
      'content/dist/rhel8/8/ppc64le/appstream/os',
      'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8/s390x/appstream/debug',
      'content/dist/rhel8/8/s390x/appstream/os',
      'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8/x86_64/appstream/debug',
      'content/dist/rhel8/8/x86_64/appstream/os',
      'content/dist/rhel8/8/x86_64/appstream/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'sane-backends-1.0.27-19.el8_2.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sane-backends-daemon-1.0.27-19.el8_2.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sane-backends-devel-1.0.27-19.el8_2.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sane-backends-doc-1.0.27-19.el8_2.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sane-backends-drivers-cameras-1.0.27-19.el8_2.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sane-backends-drivers-scanners-1.0.27-19.el8_2.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sane-backends-libs-1.0.27-19.el8_2.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'sane-backends / sane-backends-daemon / sane-backends-devel / etc');
}
