#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1279. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125446);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id("CVE-2018-16877", "CVE-2018-16878", "CVE-2019-3885");
  script_xref(name:"RHSA", value:"2019:1279");

  script_name(english:"RHEL 8 : pacemaker (RHSA-2019:1279)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for pacemaker.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2019:1279 advisory.

    The Pacemaker cluster resource manager is a collection of technologies working together to maintain data
    integrity and application availability in the event of failures.

    Security Fix(es):

    * pacemaker: Insufficient local IPC client-server authentication on the client's side can lead to local
    privesc (CVE-2018-16877)

    * pacemaker: Insufficient verification inflicted preference of uncontrolled processes can lead to DoS
    (CVE-2018-16878)

    * pacemaker: Information disclosure through use-after-free (CVE-2019-3885)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * Interrupted live migration will get full start rather than completed migration (BZ#1695247)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_1279.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?532dee74");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:1279");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1652646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1657962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1694554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1695247");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL pacemaker package based on the guidance in RHSA-2019:1279.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3885");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-16877");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(287, 400, 416);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cluster-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-nagios-plugins-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-schemas");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redhat_repos.nasl", "ssh_get_info.nasl");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8.10/ppc64le/appstream/debug',
      'content/dist/rhel8/8.10/ppc64le/appstream/os',
      'content/dist/rhel8/8.10/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.10/ppc64le/highavailability/debug',
      'content/dist/rhel8/8.10/ppc64le/highavailability/os',
      'content/dist/rhel8/8.10/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel8/8.10/ppc64le/resilientstorage/debug',
      'content/dist/rhel8/8.10/ppc64le/resilientstorage/os',
      'content/dist/rhel8/8.10/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8.10/s390x/appstream/debug',
      'content/dist/rhel8/8.10/s390x/appstream/os',
      'content/dist/rhel8/8.10/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8.10/s390x/highavailability/debug',
      'content/dist/rhel8/8.10/s390x/highavailability/os',
      'content/dist/rhel8/8.10/s390x/highavailability/source/SRPMS',
      'content/dist/rhel8/8.10/s390x/resilientstorage/debug',
      'content/dist/rhel8/8.10/s390x/resilientstorage/os',
      'content/dist/rhel8/8.10/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/appstream/debug',
      'content/dist/rhel8/8.10/x86_64/appstream/os',
      'content/dist/rhel8/8.10/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/highavailability/debug',
      'content/dist/rhel8/8.10/x86_64/highavailability/os',
      'content/dist/rhel8/8.10/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/resilientstorage/debug',
      'content/dist/rhel8/8.10/x86_64/resilientstorage/os',
      'content/dist/rhel8/8.10/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/appstream/debug',
      'content/dist/rhel8/8.6/ppc64le/appstream/os',
      'content/dist/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/highavailability/debug',
      'content/dist/rhel8/8.6/ppc64le/highavailability/os',
      'content/dist/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/resilientstorage/debug',
      'content/dist/rhel8/8.6/ppc64le/resilientstorage/os',
      'content/dist/rhel8/8.6/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8.6/s390x/appstream/debug',
      'content/dist/rhel8/8.6/s390x/appstream/os',
      'content/dist/rhel8/8.6/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/s390x/highavailability/debug',
      'content/dist/rhel8/8.6/s390x/highavailability/os',
      'content/dist/rhel8/8.6/s390x/highavailability/source/SRPMS',
      'content/dist/rhel8/8.6/s390x/resilientstorage/debug',
      'content/dist/rhel8/8.6/s390x/resilientstorage/os',
      'content/dist/rhel8/8.6/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/appstream/debug',
      'content/dist/rhel8/8.6/x86_64/appstream/os',
      'content/dist/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/highavailability/debug',
      'content/dist/rhel8/8.6/x86_64/highavailability/os',
      'content/dist/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/resilientstorage/debug',
      'content/dist/rhel8/8.6/x86_64/resilientstorage/os',
      'content/dist/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/appstream/debug',
      'content/dist/rhel8/8.8/ppc64le/appstream/os',
      'content/dist/rhel8/8.8/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/highavailability/debug',
      'content/dist/rhel8/8.8/ppc64le/highavailability/os',
      'content/dist/rhel8/8.8/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/resilientstorage/debug',
      'content/dist/rhel8/8.8/ppc64le/resilientstorage/os',
      'content/dist/rhel8/8.8/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8.8/s390x/appstream/debug',
      'content/dist/rhel8/8.8/s390x/appstream/os',
      'content/dist/rhel8/8.8/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/s390x/highavailability/debug',
      'content/dist/rhel8/8.8/s390x/highavailability/os',
      'content/dist/rhel8/8.8/s390x/highavailability/source/SRPMS',
      'content/dist/rhel8/8.8/s390x/resilientstorage/debug',
      'content/dist/rhel8/8.8/s390x/resilientstorage/os',
      'content/dist/rhel8/8.8/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/appstream/debug',
      'content/dist/rhel8/8.8/x86_64/appstream/os',
      'content/dist/rhel8/8.8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/highavailability/debug',
      'content/dist/rhel8/8.8/x86_64/highavailability/os',
      'content/dist/rhel8/8.8/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/resilientstorage/debug',
      'content/dist/rhel8/8.8/x86_64/resilientstorage/os',
      'content/dist/rhel8/8.8/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/appstream/debug',
      'content/dist/rhel8/8.9/ppc64le/appstream/os',
      'content/dist/rhel8/8.9/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/highavailability/debug',
      'content/dist/rhel8/8.9/ppc64le/highavailability/os',
      'content/dist/rhel8/8.9/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/resilientstorage/debug',
      'content/dist/rhel8/8.9/ppc64le/resilientstorage/os',
      'content/dist/rhel8/8.9/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8.9/s390x/appstream/debug',
      'content/dist/rhel8/8.9/s390x/appstream/os',
      'content/dist/rhel8/8.9/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/s390x/highavailability/debug',
      'content/dist/rhel8/8.9/s390x/highavailability/os',
      'content/dist/rhel8/8.9/s390x/highavailability/source/SRPMS',
      'content/dist/rhel8/8.9/s390x/resilientstorage/debug',
      'content/dist/rhel8/8.9/s390x/resilientstorage/os',
      'content/dist/rhel8/8.9/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/appstream/debug',
      'content/dist/rhel8/8.9/x86_64/appstream/os',
      'content/dist/rhel8/8.9/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/highavailability/debug',
      'content/dist/rhel8/8.9/x86_64/highavailability/os',
      'content/dist/rhel8/8.9/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/resilientstorage/debug',
      'content/dist/rhel8/8.9/x86_64/resilientstorage/os',
      'content/dist/rhel8/8.9/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/appstream/debug',
      'content/dist/rhel8/8/ppc64le/appstream/os',
      'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/highavailability/debug',
      'content/dist/rhel8/8/ppc64le/highavailability/os',
      'content/dist/rhel8/8/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/resilientstorage/debug',
      'content/dist/rhel8/8/ppc64le/resilientstorage/os',
      'content/dist/rhel8/8/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/s390x/appstream/debug',
      'content/dist/rhel8/8/s390x/appstream/os',
      'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8/s390x/highavailability/debug',
      'content/dist/rhel8/8/s390x/highavailability/os',
      'content/dist/rhel8/8/s390x/highavailability/source/SRPMS',
      'content/dist/rhel8/8/s390x/resilientstorage/debug',
      'content/dist/rhel8/8/s390x/resilientstorage/os',
      'content/dist/rhel8/8/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/x86_64/appstream/debug',
      'content/dist/rhel8/8/x86_64/appstream/os',
      'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8/x86_64/highavailability/debug',
      'content/dist/rhel8/8/x86_64/highavailability/os',
      'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel8/8/x86_64/resilientstorage/debug',
      'content/dist/rhel8/8/x86_64/resilientstorage/os',
      'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'pacemaker-2.0.1-4.el8_0.3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-2.0.1-4.el8_0.3', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-2.0.1-4.el8_0.3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-cli-2.0.1-4.el8_0.3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-cli-2.0.1-4.el8_0.3', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-cli-2.0.1-4.el8_0.3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-cluster-libs-2.0.1-4.el8_0.3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-cts-2.0.1-4.el8_0.3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-doc-2.0.1-4.el8_0.3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-libs-2.0.1-4.el8_0.3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-libs-devel-2.0.1-4.el8_0.3', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-libs-devel-2.0.1-4.el8_0.3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-libs-devel-2.0.1-4.el8_0.3', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-libs-devel-2.0.1-4.el8_0.3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-nagios-plugins-metadata-2.0.1-4.el8_0.3', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-remote-2.0.1-4.el8_0.3', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-remote-2.0.1-4.el8_0.3', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-remote-2.0.1-4.el8_0.3', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'pacemaker-schemas-2.0.1-4.el8_0.3', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pacemaker / pacemaker-cli / pacemaker-cluster-libs / pacemaker-cts / etc');
}
