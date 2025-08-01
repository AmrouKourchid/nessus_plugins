#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:3471. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194038);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/03");

  script_cve_id(
    "CVE-2017-7539",
    "CVE-2017-10664",
    "CVE-2017-11334",
    "CVE-2017-14167",
    "CVE-2017-15289"
  );
  script_xref(name:"RHSA", value:"2017:3471");

  script_name(english:"RHEL 7 : qemu-kvm-rhev (RHSA-2017:3471)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for qemu-kvm-rhev.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2017:3471 advisory.

    KVM (Kernel-based Virtual Machine) is a full virtualization solution for Linux on a variety of
    architectures. The qemu-kvm-rhev packages provide the user-space component for running virtual machines
    that use KVM in environments managed by Red Hat products.

    Security Fix(es):

    * An assertion-failure flaw was found in the Network Block Device (NBD) server's initial connection
    negotiation, where the I/O coroutine was undefined. This could crash the qemu-nbd server if a client sent
    unexpected data during connection negotiation. A remote user or process could use this flaw to crash the
    qemu-nbd server resulting in denial of service. (CVE-2017-7539)

    * Quick Emulator (QEMU) built with the Network Block Device (NBD) Server support is vulnerable to a crash
    via a SIGPIPE signal. The crash can occur if a client aborts a connection due to any failure during
    negotiation or read operation. A remote user/process could use this flaw to crash the qemu-nbd server
    resulting in a Denial of Service (DoS). (CVE-2017-10664)

    * Quick Emulator (QEMU), compiled with qemu_map_ram_ptr to access guests' RAM block area, is vulnerable to
    an OOB r/w access issue. The crash can occur if a privileged user inside a guest conducts certain DMA
    operations, resulting in a DoS. (CVE-2017-11334)

    * Quick Emulator (QEMU), compiled with the PC System Emulator with multiboot feature support, is
    vulnerable to an OOB r/w memory access issue. The issue could occur due to an integer overflow while
    loading a kernel image during a guest boot. A user or process could use this flaw to potentially achieve
    arbitrary code execution on a host. (CVE-2017-14167)

    * Quick emulator (QEMU), compiled with the Cirrus CLGD 54xx VGA Emulator support, is vulnerable to an OOB
    write access issue. The issue could occur while writing to VGA memory via mode4and5 write functions. A
    privileged user inside guest could use this flaw to crash the QEMU process resulting in Denial of Serivce
    (DoS). (CVE-2017-15289)

    Red Hat would like to thank Alex for reporting CVE-2017-11334; Thomas Garnier (Google.com) for reporting
    CVE-2017-14167; and Guoxiang Niu (Huawei.com) for reporting CVE-2017-15289.

    Bug Fix(es):

    * Hot-unplugging Virtual Function I/O (VFIO) devices previously failed when performed after hot-unplugging
    a vhost network device. This update fixes the underlying code, and the VFIO device is unplugged correctly
    in the described circumstances. (BZ#1498141)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1466190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1471638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1472484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1473622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1489375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1498141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1501290");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2017/rhsa-2017_3471.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a79e7a1");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:3471");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL qemu-kvm-rhev package based on the guidance in RHSA-2017:3471.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14167");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(190, 248, 617, 787);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/27");

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
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/8/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/8/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/8/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/8/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/8/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/8/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/8/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/8/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/8/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/8/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/8/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/8/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'qemu-img-rhev-2.9.0-16.el7_4.11', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'},
      {'reference':'qemu-kvm-common-rhev-2.9.0-16.el7_4.11', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'},
      {'reference':'qemu-kvm-rhev-2.9.0-16.el7_4.11', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'},
      {'reference':'qemu-kvm-tools-rhev-2.9.0-16.el7_4.11', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_4', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'}
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
