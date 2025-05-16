#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1233. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78932);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2012-3515");
  script_bugtraq_id(55413);
  script_xref(name:"RHSA", value:"2012:1233");

  script_name(english:"RHEL 6 : qemu-kvm-rhev (RHSA-2012:1233)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for qemu-kvm-rhev.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2012:1233 advisory.

    KVM (Kernel-based Virtual Machine) is a full virtualization solution for
    Linux on AMD64 and Intel 64 systems. The qemu-kvm-rhev packages form the
    user-space component for running virtual machines using KVM.

    A flaw was found in the way QEMU handled VT100 terminal escape sequences
    when emulating certain character devices. A guest user with privileges to
    write to a character device that is emulated on the host using a virtual
    console back-end could use this flaw to crash the qemu-kvm process on the
    host or, possibly, escalate their privileges on the host. (CVE-2012-3515)

    When using qemu-kvm-rhev on a Red Hat Enterprise Linux 6 host not managed
    by Red Hat Enterprise Virtualization:

    * This flaw did not affect the default use of KVM. Affected configurations
    were:

    - When guests were started from the command line (/usr/libexec/qemu-kvm)
    without the -nodefaults option, and also without specifying a
    serial or parallel device, or a virtio-console device, that specifically
    does not use a virtual console (vc) back-end. (Note that Red Hat does not
    support invoking qemu-kvm from the command line without -nodefaults on
    Red Hat Enterprise Linux 6.)

    - Guests that were managed via libvirt, such as when using Virtual Machine
    Manager (virt-manager), but that have a serial or parallel device, or a
    virtio-console device, that uses a virtual console back-end. By default,
    guests managed via libvirt will not use a virtual console back-end for such
    devices.

    When using qemu-kvm-rhev on a Red Hat Enterprise Virtualization managed Red
    Hat Enterprise Linux 6 host:

    * This flaw did not affect the default use of a Red Hat Enterprise
    Virtualization host: it is not possible to add a device that uses a virtual
    console back-end via Red Hat Enterprise Virtualization Manager.

    To specify a virtual console back-end for a device and therefore be
    vulnerable to this issue, the device would have to be created another way,
    for example, by using a VDSM hook.

    Red Hat would like to thank the Xen project for reporting this issue.

    This update also fixes the following bugs:

    * Previously, the KVM modules were not loaded by the postinstall scriptlet
    of RPM scripts. This bug caused various issues and required the system to
    be rebooted to resolve them. With this update, the modules are loaded
    properly by the scriptlet and no unnecessary reboots are now required.
    (BZ#839897)

    * Previously, when a guest was started up with two serial devices, qemu-kvm
    returned an error message and terminated the boot because IRQ 4 for the ISA
    bus was being used by both devices. This update fixes the qemu-kvm code,
    which allows IRQ 4 to be used by more than one device on the ISA bus, and
    the boot now succeeds in the described scenario. (BZ#840054)

    All users of qemu-kvm-rhev are advised to upgrade to these updated
    packages, which fix these issues. After installing this update, shut down
    all running virtual machines. Once all virtual machines have shut down,
    start them again for this update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2012/rhsa-2012_1233.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5ba3d85");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2012:1233");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=851252");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL qemu-kvm-rhev package based on the guidance in RHSA-2012:1233.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3515");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/6/6Client/x86_64/rhev-agent/3/debug',
      'content/dist/rhel/client/6/6Client/x86_64/rhev-agent/3/os',
      'content/dist/rhel/client/6/6Client/x86_64/rhev-agent/3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-agent/3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-agent/3/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-agent/3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-mgmt-agent/3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-mgmt-agent/3/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-mgmt-agent/3/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhev-agent/3/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhev-agent/3/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhev-agent/3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'qemu-img-rhev-0.12.1.2-2.295.el6_3.2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_3', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ovirt-'},
      {'reference':'qemu-kvm-rhev-0.12.1.2-2.295.el6_3.2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_3', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ovirt-'},
      {'reference':'qemu-kvm-rhev-tools-0.12.1.2-2.295.el6_3.2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_3', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ovirt-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu-img-rhev / qemu-kvm-rhev / qemu-kvm-rhev-tools');
}
