##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:2298. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(136913);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2020-10722", "CVE-2020-10723");
  script_xref(name:"RHSA", value:"2020:2298");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"RHEL 7 : openvswitch (RHSA-2020:2298)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:2298 advisory.

    Open vSwitch provides standard network bridging functions and support for the OpenFlow protocol for remote
    per-flow control of traffic.

    Security Fix(es):

    * dpdk: librte_vhost Interger overflow in vhost_user_set_log_base() (CVE-2020-10722)

    * dpdk: librte_vhost Integer truncation in vhost_user_check_and_alloc_queue_pair() (CVE-2020-10723)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * OVS causing high pings and latency inside guest VM when an active DPDK port fails (BZ#1822198)

    * SEGV after recirculation in batch processing in vswitchd 2.9.0 (BZ#1826886)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_2298.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0726cd54");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:2298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1822198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1826886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1828867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1828874");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10723");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(190);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-ovn-central");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-ovn-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-ovn-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-ovn-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-openvswitch");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/fast-datapath/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/fast-datapath/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/fast-datapath/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhv-mgmt-agent/4/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhv-mgmt-agent/4/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhv-mgmt-agent/4/source/SRPMS',
      'content/dist/rhel/power-le/7/7.3/ppc64le/rhev-mgmt-agent/3/debug',
      'content/dist/rhel/power-le/7/7.3/ppc64le/rhev-mgmt-agent/3/os',
      'content/dist/rhel/power-le/7/7.3/ppc64le/rhev-mgmt-agent/3/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/fast-datapath/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/fast-datapath/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/fast-datapath/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhev-mgmt-agent/3/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhev-mgmt-agent/3/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhev-mgmt-agent/3/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhev-tools/3/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhev-tools/3/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhev-tools/3/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhv-mgmt-agent/4/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhv-mgmt-agent/4/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhv-mgmt-agent/4/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhv-tools/4/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhv-tools/4/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhv-tools/4/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/rhev-tools/3/debug',
      'content/dist/rhel/power/7/7Server/ppc64/rhev-tools/3/os',
      'content/dist/rhel/power/7/7Server/ppc64/rhev-tools/3/source/SRPMS',
      'content/dist/rhel/server/7/7.3/x86_64/rhev-mgmt-agent/3/debug',
      'content/dist/rhel/server/7/7.3/x86_64/rhev-mgmt-agent/3/os',
      'content/dist/rhel/server/7/7.3/x86_64/rhev-mgmt-agent/3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/fast-datapath/debug',
      'content/dist/rhel/server/7/7Server/x86_64/fast-datapath/os',
      'content/dist/rhel/server/7/7Server/x86_64/fast-datapath/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhev-mgmt-agent/3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhev-mgmt-agent/3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhev-mgmt-agent/3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhevh/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhevh/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhevh/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager-tools/4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager-tools/4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-manager-tools/4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-mgmt-agent/4.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-mgmt-agent/4.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-mgmt-agent/4.3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-mgmt-agent/4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-mgmt-agent/4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-mgmt-agent/4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-tools/4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-tools/4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhv-tools/4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh-build/4.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh-build/4.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh-build/4.3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh-build/4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh-build/4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh-build/4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh/4.3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh/4.3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh/4.3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh/4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh/4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhvh/4/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/fast-datapath/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/fast-datapath/os',
      'content/dist/rhel/system-z/7/7Server/s390x/fast-datapath/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openvswitch-2.9.0-130.el7fdp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-2.9.0-130.el7fdp', 'cpu':'s390x', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-2.9.0-130.el7fdp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-devel-2.9.0-130.el7fdp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-devel-2.9.0-130.el7fdp', 'cpu':'s390x', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-devel-2.9.0-130.el7fdp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-ovn-central-2.9.0-130.el7fdp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-ovn-central-2.9.0-130.el7fdp', 'cpu':'s390x', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-ovn-central-2.9.0-130.el7fdp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-ovn-common-2.9.0-130.el7fdp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-ovn-common-2.9.0-130.el7fdp', 'cpu':'s390x', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-ovn-common-2.9.0-130.el7fdp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-ovn-host-2.9.0-130.el7fdp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-ovn-host-2.9.0-130.el7fdp', 'cpu':'s390x', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-ovn-host-2.9.0-130.el7fdp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-ovn-vtep-2.9.0-130.el7fdp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-ovn-vtep-2.9.0-130.el7fdp', 'cpu':'s390x', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-ovn-vtep-2.9.0-130.el7fdp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'openvswitch-test-2.9.0-130.el7fdp', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'python-openvswitch-2.9.0-130.el7fdp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'python-openvswitch-2.9.0-130.el7fdp', 'cpu':'s390x', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'},
      {'reference':'python-openvswitch-2.9.0-130.el7fdp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7fdp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openvswitch'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openvswitch / openvswitch-devel / openvswitch-ovn-central / etc');
}
