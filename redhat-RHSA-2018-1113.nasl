#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2018:1113. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233296);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/24");

  script_cve_id(
    "CVE-2017-13672",
    "CVE-2017-13673",
    "CVE-2017-13711",
    "CVE-2017-15118",
    "CVE-2017-15119",
    "CVE-2017-15124",
    "CVE-2017-15268",
    "CVE-2018-5683"
  );
  script_xref(name:"RHSA", value:"2018:1113");

  script_name(english:"RHEL 7 : qemu-kvm-rhev (RHSA-2018:1113)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for qemu-kvm-rhev.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2018:1113 advisory.

    KVM (Kernel-based Virtual Machine) is a full virtualization solution for Linux on a variety of
    architectures. The qemu-kvm-rhev packages provide the user-space component for running virtual machines
    that use KVM in environments managed by Red Hat products.

    Security Fix(es):

    * The Network Block Device (NBD) server in Quick Emulator (QEMU), is vulnerable to a denial of service
    issue. It could occur if a client sent large option requests, making the server waste CPU time on reading
    up to 4GB per request. A client could use this flaw to keep the NBD server from serving other requests,
    resulting in DoS. (CVE-2017-15119)

    * Qemu: vga: OOB read access during display update (CVE-2017-13672)

    * Qemu: vga: reachable assert failure during display update (CVE-2017-13673)

    * Qemu: Slirp: use-after-free when sending response (CVE-2017-13711)

    * VNC server implementation in Quick Emulator (QEMU) was found to be vulnerable to an unbounded memory
    allocation issue, as it did not throttle the framebuffer updates sent to its client. If the client did not
    consume these updates, VNC server allocates growing memory to hold onto this data. A malicious remote VNC
    client could use this flaw to cause DoS to the server host. (CVE-2017-15124)

    For more details about the security issue(s), including the impact, a CVSS score, and other related
    information, refer to the CVE page(s) listed in the References section.

    Red Hat would like to thank David Buchanan for reporting CVE-2017-13672 and CVE-2017-13673 and Wjjzhang
    (Tencent.com) for reporting CVE-2017-13711. The CVE-2017-15119 issue was discovered by Eric Blake (Red
    Hat) and the CVE-2017-15124 issue was discovered by Daniel Berrange (Red Hat).

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1486400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1486560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1486588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1516925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1525195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1549860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1553107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1557010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1557011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1562826");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2018/rhsa-2018_1113.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e9b54df");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:1113");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL qemu-kvm-rhev package based on the guidance in RHSA-2018:1113.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15118");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(121, 125, 400, 416, 617, 770);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-common-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-tools-rhev");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/10/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/10/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/10/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/11/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/11/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/11/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/12/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/12/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/12/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/8/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/8/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/8/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/9/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/9/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/9/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/12/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/12/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack-devtools/12/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/12/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/12/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/openstack/12/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/10/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/10/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/10/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/11/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/11/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/11/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/12/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/12/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/12/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/10/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/10/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/10/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/11/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/11/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/11/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/12/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/12/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/12/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/8/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/8/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/8/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/9/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/9/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/9/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/10/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/10/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/10/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/11/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/11/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/11/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/12/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/12/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/12/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/8/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/8/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/8/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/9/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/9/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/9/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/10/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/10/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/10/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/11/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/11/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/11/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/12/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/12/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/12/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/8/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/8/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/8/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/9/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/9/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/9/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'qemu-img-rhev-2.10.0-21.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'},
      {'reference':'qemu-img-rhev-2.10.0-21.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'},
      {'reference':'qemu-kvm-common-rhev-2.10.0-21.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'},
      {'reference':'qemu-kvm-common-rhev-2.10.0-21.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'},
      {'reference':'qemu-kvm-rhev-2.10.0-21.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'},
      {'reference':'qemu-kvm-rhev-2.10.0-21.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'},
      {'reference':'qemu-kvm-tools-rhev-2.10.0-21.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'},
      {'reference':'qemu-kvm-tools-rhev-2.10.0-21.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu-img-rhev / qemu-kvm-common-rhev / qemu-kvm-rhev / etc');
}
