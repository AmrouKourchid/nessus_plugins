#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:0999. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159196);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2021-3654");
  script_xref(name:"RHSA", value:"2022:0999");

  script_name(english:"RHEL 8 : Red Hat OpenStack Platform 16.2 (openstack-nova) (RHSA-2022:0999)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for Red Hat OpenStack Platform 16.2 (openstack-nova).");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2022:0999 advisory.

    OpenStack Compute (codename Nova) is open source software designed
    to provision and manage large networks of virtual machines,creating a
    redundant and scalable cloud computing platform. It gives you the software,
    control panels, and APIs required to orchestrate a cloud, including running
    instances, managing networks, and controlling access through users and
    projects.OpenStack Compute strives to be both hardware and hypervisor
    agnostic, currently supporting a variety of standard hardware
    configurations and seven major hypervisors.

    Security Fix(es):

    * novnc allows open redirection (CVE-2021-3654)

    For more details about the security issue(s), including the impact, a CVSS
    score, acknowledgments, and other related information, refer to the CVE
    page listed in the References section.

    Bug Fix(es):

    * Red Hat OpenStack Platform (RHOSP) does not support the use of a fully qualified domain name (FQDN) as
    the instance display name in a boot server request. The instance display name is passed from the boot
    server request to the `instance.hostname` field. Some customers use this unsupported naming in their
    workflows.

    A recent update [1] now sanitizes the `instance.hostname` field. The sanitization steps include replacing
    periods with dashes, a replacement that makes it impossible to continue using the unsupported FQDN
    instance display names.

    This update provides a temporary workaround for customers who use a fully qualified domain name (FQDN) as
    the instance display name in a boot server request. It limits the scope of the sanitization to cases where
    the instance display name ends with a period followed by one or more numeric digits.

    If you use FQDN as the instance display name in a boot server request, modify your workflow before
    upgrading to RHOSP 17. (BZ#2036652)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_0999.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92583ee2");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:0999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1729485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1908405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1915096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1961439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1968735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1972706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1987225");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1992863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1998556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1999583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2036652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2036690");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat OpenStack Platform 16.2 (openstack-nova) package based on the guidance in RHSA-2022:0999.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3654");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(601);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-conductor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-novncproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-serialproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-spicehtml5proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-nova");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/ppc64le/openstack-cinderlib/16.2/debug',
      'content/dist/layered/rhel8/ppc64le/openstack-cinderlib/16.2/os',
      'content/dist/layered/rhel8/ppc64le/openstack-cinderlib/16.2/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/openstack-deployment-tools/16.2/debug',
      'content/dist/layered/rhel8/ppc64le/openstack-deployment-tools/16.2/os',
      'content/dist/layered/rhel8/ppc64le/openstack-deployment-tools/16.2/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/openstack/16.2/debug',
      'content/dist/layered/rhel8/ppc64le/openstack/16.2/os',
      'content/dist/layered/rhel8/ppc64le/openstack/16.2/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/openstack-cinderlib/16.2/debug',
      'content/dist/layered/rhel8/x86_64/openstack-cinderlib/16.2/os',
      'content/dist/layered/rhel8/x86_64/openstack-cinderlib/16.2/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/openstack-deployment-tools/16.2/debug',
      'content/dist/layered/rhel8/x86_64/openstack-deployment-tools/16.2/os',
      'content/dist/layered/rhel8/x86_64/openstack-deployment-tools/16.2/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/openstack-tools/16/debug',
      'content/dist/layered/rhel8/x86_64/openstack-tools/16/os',
      'content/dist/layered/rhel8/x86_64/openstack-tools/16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/openstack/16.2/debug',
      'content/dist/layered/rhel8/x86_64/openstack/16.2/os',
      'content/dist/layered/rhel8/x86_64/openstack/16.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openstack-nova-20.6.2-2.20220112164912.8906554.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-api-20.6.2-2.20220112164912.8906554.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-common-20.6.2-2.20220112164912.8906554.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-compute-20.6.2-2.20220112164912.8906554.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-conductor-20.6.2-2.20220112164912.8906554.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-console-20.6.2-2.20220112164912.8906554.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-migration-20.6.2-2.20220112164912.8906554.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-novncproxy-20.6.2-2.20220112164912.8906554.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-scheduler-20.6.2-2.20220112164912.8906554.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-serialproxy-20.6.2-2.20220112164912.8906554.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-spicehtml5proxy-20.6.2-2.20220112164912.8906554.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'python3-nova-20.6.2-2.20220112164912.8906554.el8ost', 'release':'8', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openstack-nova / openstack-nova-api / openstack-nova-common / etc');
}
