#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:2622. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194102);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id("CVE-2019-14433");
  script_xref(name:"RHSA", value:"2019:2622");

  script_name(english:"RHEL 7 : openstack-nova (RHSA-2019:2622)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for openstack-nova.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2019:2622 advisory.

    OpenStack Compute (nova) launches and schedules large networks of virtual machines, creating a redundant
    and scalable cloud computing platform. Compute provides the software, control panels, and APIs required to
    orchestrate a cloud, including running virtual machine instances and controlling access through users and
    projects.

    Security Fix(es):

    * openstack-nova: Nova server resource faults leak external exception details (CVE-2019-14433)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * Previously, the heal info cache periodic task used the network info cache to heal the network info
    cache. If the cache was corrupted or missing, the heal info cache task could not heal the network info
    cache.

    With this update, the heal info cache uses VM data from Neutron when healing the network info cache.
    (BZ#1703225)

    * Previously, evacuation, migration, and resize operations took unnecessarily long to process on
    destination hosts with a large number of network interfaces. This was due to the my_ip configuration
    printing a warning when it did not find any of the host interfaces.

    With this update, the my_ip configuration occurs only once during host initialization. This reduces the
    time it takes to process migrations, evacuations, and resize operations. (BZ#1732879)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1721433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1735522");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_2622.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d48c96b4");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:2622");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL openstack-nova package based on the guidance in RHSA-2019:2622.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14433");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(209);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-cells");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-conductor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-novncproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-placement-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-serialproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-nova-spicehtml5proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-nova");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-nova-tests");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/13/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/13/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/13/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/13/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/13/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-octavia/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-octavia/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-octavia/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/13/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/13/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/13/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/13/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/source/SRPMS',
      'content/els/rhel/client/7/7Client/x86_64/openstack-tools/13/debug',
      'content/els/rhel/client/7/7Client/x86_64/openstack-tools/13/os',
      'content/els/rhel/client/7/7Client/x86_64/openstack-tools/13/source/SRPMS',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-deployment-tools/13/source/SRPMS',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack-devtools/13/source/SRPMS',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack/13/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack/13/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/openstack/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack-deployment-tools/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack-devtools/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack-devtools/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack-devtools/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack-octavia/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack-octavia/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack-octavia/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack-tools/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack-tools/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack-tools/13/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/openstack/13/debug',
      'content/els/rhel/server/7/7Server/x86_64/openstack/13/os',
      'content/els/rhel/server/7/7Server/x86_64/openstack/13/source/SRPMS',
      'content/els/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/debug',
      'content/els/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/os',
      'content/els/rhel/workstation/7/7Workstation/x86_64/openstack-tools/13/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/openstack-octavia/13/debug',
      'content/eus/rhel/server/7/7.6/x86_64/openstack-octavia/13/os',
      'content/eus/rhel/server/7/7.6/x86_64/openstack-octavia/13/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/openstack/13/debug',
      'content/eus/rhel/server/7/7.6/x86_64/openstack/13/os',
      'content/eus/rhel/server/7/7.6/x86_64/openstack/13/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openstack-nova-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-api-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-cells-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-common-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-compute-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-conductor-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-console-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-migration-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-network-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-novncproxy-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-placement-api-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-scheduler-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-serialproxy-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'openstack-nova-spicehtml5proxy-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'python-nova-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'},
      {'reference':'python-nova-tests-17.0.10-6.el7ost', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openstack-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openstack-nova / openstack-nova-api / openstack-nova-cells / etc');
}
