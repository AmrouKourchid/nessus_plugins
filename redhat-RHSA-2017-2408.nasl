#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:2408. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210314);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id(
    "CVE-2016-4020",
    "CVE-2016-6888",
    "CVE-2016-7422",
    "CVE-2016-7466",
    "CVE-2016-8576",
    "CVE-2016-8669",
    "CVE-2016-8909",
    "CVE-2016-8910",
    "CVE-2016-9907",
    "CVE-2016-9911",
    "CVE-2016-9921",
    "CVE-2016-9922",
    "CVE-2016-10155",
    "CVE-2017-5579",
    "CVE-2017-5973",
    "CVE-2017-6414",
    "CVE-2017-8309",
    "CVE-2017-8379",
    "CVE-2017-9310",
    "CVE-2017-9373",
    "CVE-2017-9374",
    "CVE-2017-9375",
    "CVE-2017-9524"
  );
  script_xref(name:"RHSA", value:"2017:2408");

  script_name(english:"RHEL 7 : qemu-kvm-rhev (RHSA-2017:2408)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for qemu-kvm-rhev.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2017:2408 advisory.

    KVM (Kernel-based Virtual Machine) is a full virtualization solution for Linux on a variety of
    architectures. The qemu-kvm-rhev packages provide the user-space component for running virtual machines
    that use KVM in environments managed by Red Hat products.

    Security Fix(es):

    * Quick Emulator (QEMU) built with Network Block Device (NBD) Server support was vulnerable to a null-
    pointer dereference issue. The flaw could occur when releasing a client that was not initialized due to
    failed negotiation. A remote user or process could exploit this flaw to crash the qemu-nbd server (denial
    of service). (CVE-2017-9524)

    * An information-exposure flaw was found in Quick Emulator (QEMU) in Task Priority Register (TPR)
    optimizations for 32-bit Windows guests. The flaw could occur while accessing TPR. A privileged user
    inside a guest could use this issue to read portions of the host memory. (CVE-2016-4020)

    * A memory-leak flaw was found in the Quick Emulator (QEMU) built with USB xHCI controller emulation
    support. The flaw could occur while doing a USB-device unplug operation. Unplugging the device repeatedly
    resulted in leaking host memory, which affected other services on the host. A privileged user inside the
    guest could exploit this flaw to cause a denial of service on the host or potentially crash the host's
    QEMU process instance. (CVE-2016-7466)

    * Multiple CVEs were fixed as a result of rebase to QEMU 2.9.0. (CVE-2016-6888, CVE-2016-7422,
    CVE-2016-8576, CVE-2016-8669, CVE-2016-8909, CVE-2016-8910, CVE-2016-9907, CVE-2016-9911, CVE-2016-9921,
    CVE-2016-9922, CVE-2016-10155, CVE-2017-5579, CVE-2017-5973, CVE-2017-6414, CVE-2017-8309, CVE-2017-8379,
    CVE-2017-9310, CVE-2017-9373, CVE-2017-9374, CVE-2017-9375)

    Red Hat would like to thank Donghai Zdh (Alibaba Inc.) for reporting CVE-2016-4020; Li Qiang (Qihoo 360
    Inc.) for reporting CVE-2016-6888; Qinghao Tang (Marvel Team 360.cn Inc.) and Zhenhao Hong (Marvel Team
    360.cn Inc.) for reporting CVE-2016-7422; Li Qiang (360.cn Inc.) for reporting CVE-2016-7466,
    CVE-2016-10155, CVE-2017-5579, CVE-2017-5973, and CVE-2017-6414; PSIRT (Huawei Inc.) for reporting
    CVE-2016-8669; Andrew Henderson (Intelligent Automation Inc.) for reporting CVE-2016-8910; Qinghao Tang
    (Qihoo 360), Li Qiang (Qihoo 360), and Jiangxin (Huawei Inc.) for reporting CVE-2016-9921 and
    CVE-2016-9922; Jiang Xin (PSIRT, Huawei Inc.) for reporting CVE-2017-8309 and CVE-2017-8379; and Li Qiang
    (Qihoo 360 Gear Team) for reporting CVE-2017-9310, CVE-2017-9373, CVE-2017-9374, and CVE-2017-9375.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1313686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1333425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1334398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1369031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1376755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1377837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1384909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1388046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1388052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1402265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1402272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1415199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1416157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1421626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1427833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1446517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1446547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1452620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1458270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1458744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1459132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1459661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1459663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1459664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1459666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1459667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1459668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1460170");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2017/rhsa-2017_2408.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d6dbdb2");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:2408");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL qemu-kvm-rhev package based on the guidance in RHSA-2017:2408.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4020");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 200, 244, 369, 476, 772, 835);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/05");

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
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/10/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/10/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/10/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/11/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/11/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/11/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/7.0/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/7.0/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/7.0/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/8/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/8/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/8/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/9/debug',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/9/os',
      'content/dist/rhel/client/7/7Client/x86_64/openstack-tools/9/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/10/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/10/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/10/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/11/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/11/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-devtools/11/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/10/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/10/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/10/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/11/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/11/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/11/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/7.0/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/7.0/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack-tools/7.0/source/SRPMS',
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
      'content/dist/rhel/server/7/7Server/x86_64/openstack/6.0/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/6.0/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/6.0/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/7.0/debug',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/7.0/os',
      'content/dist/rhel/server/7/7Server/x86_64/openstack/7.0/source/SRPMS',
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
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/7.0/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/7.0/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/7.0/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/8/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/8/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/8/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/9/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/9/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/openstack-tools/9/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'qemu-img-rhev-2.9.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'},
      {'reference':'qemu-kvm-common-rhev-2.9.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'},
      {'reference':'qemu-kvm-rhev-2.9.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'},
      {'reference':'qemu-kvm-tools-rhev-2.9.0-10.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'10', 'exists_check':'openstack-'}
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
      severity   : SECURITY_NOTE,
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
