##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1216. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(135033);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2019-12155", "CVE-2019-14378", "CVE-2020-1711");
  script_bugtraq_id(108429);
  script_xref(name:"RHSA", value:"2020:1216");

  script_name(english:"RHEL 7 : qemu-kvm-rhev (RHSA-2020:1216)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1216 advisory.

    KVM (Kernel-based Virtual Machine) is a full virtualization solution for Linux on a variety of
    architectures. The qemu-kvm-rhev packages provide the user-space component for running virtual machines
    that use KVM in environments managed by Red Hat products.

    Security Fix(es):

    * QEMU: slirp: heap buffer overflow during packet reassembly (CVE-2019-14378)

    * QEMU: block: iscsi: OOB heap access via an unexpected response of iSCSI Server (CVE-2020-1711)

    * QEMU: qxl: null pointer dereference while releasing spice resources (CVE-2019-12155)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * After host update, older windows clients have large time drift (BZ#1639098)

    * [v2v] Migration performance regression (BZ#1648622)

    * Live storage migration fails with: TimeoutError: Timed out during operation: cannot acquire state change
    lock (held by monitor=remoteDispatchConnectGetAllDomainStats) and the VM becomes 'Not Responding'
    (BZ#1665256)

    * QEMU gets stuck on resume/cont call from libvirt (BZ#1673546)

    * [Intel 7.8 Bug] [KVM][CLX] CPUID_7_0_EDX_ARCH_CAPABILITIES is not enabled in VM qemu-kvm-rhev
    (BZ#1709972)

    * qemu aborts in blockCommit: qemu-kvm: block.c:3486: bdrv_replace_node: Assertion `!({
    _Static_assert(!(sizeof(*&from->in_flight) > 8), not expecting:  sizeof(*&from->in_flight) >
    ATOMIC_REG_SIZE); __atomic_load_n(&from->in_flight, 0); })' failed. (BZ#1711643)

    * ccid: Fix incorrect dwProtocol advertisement of T=0 (BZ#1721522)

    * Fail to migrate a rhel6.10-mt7.6 guest with dimm device (BZ#1724048)

    * qemu-kvm: backport cpuidle-haltpoll support (BZ#1734502)

    * qemu, qemu-img fail to detect alignment with XFS and Gluster/XFS on 4k block device (BZ#1743365)

    * ISST-LTE:RHV4.3 on RHEL7.6 kvm host:Power8:Tuleta-L:lotg7: call traces dumped on guest while performing
    guest migration (qemu-kvm-rhev) (BZ#1743508)

    * qemu coredump: qemu-kvm: block/create.c:68: qmp_blockdev_create: Assertion `drv' failed (BZ#1746224)

    * [Data plane]virtio_scsi_ctx_check: Assertion `blk_get_aio_context(d->conf.blk) == s->ctx' failed when
    unplug a device that running block stream on it (BZ#1764120)

    * qemu-kvm crashes when Windows VM is migrated with multiqueue (BZ#1775251)

    Enhancement(s):

    * [Intel 7.8 FEAT] MDS_NO exposure to guest - qemu-kvm-rhev (BZ#1716726)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_1216.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?823daff3");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1648622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1665256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1711643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1712670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1721522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1724048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1734502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1734745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1743365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1746224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1764120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1775251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1794290");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14378");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(122, 476);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/31");

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
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhv-mgmt-agent/4/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhv-mgmt-agent/4/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhv-mgmt-agent/4/source/SRPMS',
      'content/dist/rhel/power-le/7/7.3/ppc64le/rhev-mgmt-agent/3/debug',
      'content/dist/rhel/power-le/7/7.3/ppc64le/rhev-mgmt-agent/3/os',
      'content/dist/rhel/power-le/7/7.3/ppc64le/rhev-mgmt-agent/3/source/SRPMS',
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
      'content/dist/rhel/server/7/7Server/x86_64/rhvh/4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'qemu-img-rhev-2.12.0-44.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'ovirt-'},
      {'reference':'qemu-img-rhev-2.12.0-44.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'ovirt-'},
      {'reference':'qemu-kvm-common-rhev-2.12.0-44.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'ovirt-'},
      {'reference':'qemu-kvm-common-rhev-2.12.0-44.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'ovirt-'},
      {'reference':'qemu-kvm-rhev-2.12.0-44.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'ovirt-'},
      {'reference':'qemu-kvm-rhev-2.12.0-44.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'ovirt-'},
      {'reference':'qemu-kvm-tools-rhev-2.12.0-44.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'ovirt-'},
      {'reference':'qemu-kvm-tools-rhev-2.12.0-44.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'ovirt-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu-img-rhev / qemu-kvm-common-rhev / qemu-kvm-rhev / etc');
}
