#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0615. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63943);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2010-2239", "CVE-2010-2242");
  script_bugtraq_id(41981);
  script_xref(name:"RHSA", value:"2010:0615");

  script_name(english:"RHEL 5 : libvirt (RHSA-2010:0615)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for libvirt.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2010:0615 advisory.

    The libvirt library is a C API for managing and interacting with the
    virtualization capabilities of Linux and other operating systems. In
    addition, libvirt provides tools for remotely managing virtualized systems.

    It was found that libvirt did not set the user-defined backing store format
    when creating a new image, possibly resulting in applications having to
    probe the backing store to discover the format. A privileged guest user
    could use this flaw to read arbitrary files on the host. (CVE-2010-2239)

    It was found that libvirt created insecure iptables rules on the host when
    a guest system was configured for IP masquerading, allowing the guest to
    use privileged ports on the host when accessing network resources. A
    privileged guest user could use this flaw to access network resources that
    would otherwise not be accessible to the guest. (CVE-2010-2242)

    Red Hat would like to thank Jeremy Nickurak for reporting the CVE-2010-2242
    issue.

    This update also fixes the following bugs:

    * a Linux software bridge assumes the MAC address of the enslaved interface
    with the numerically lowest MAC address. When the bridge changes its MAC
    address, for a period of time it does not relay packets across network
    segments, resulting in a temporary network blackout. The bridge should
    thus avoid changing its MAC address in order not to disrupt network
    communications.

    The Linux kernel assigns network TAP devices a random MAC address.
    Occasionally, this random MAC address is lower than that of the physical
    interface which is enslaved (for example, eth0 or eth1), which causes the
    bridge to change its MAC address, thereby disrupting network communications
    for a period of time.

    With this update, libvirt now sets an explicit MAC address for all TAP
    devices created using the configured MAC address from the XML, but with the
    high bit set to 0xFE. The result is that TAP device MAC addresses are now
    numerically greater than those for physical interfaces, and bridges should
    no longer attempt to switch their MAC address to that of the TAP device,
    thus avoiding potential spurious network disruptions. (BZ#617243)

    * a memory leak in the libvirt driver for the Xen hypervisor has been fixed
    with this update. (BZ#619711)

    * the xm and virsh management user interfaces for virtual guests can be
    called on the command line to list the number of active guests. However,
    under certain circumstances, running the virsh list command resulted in
    virsh not listing all of the virtual guests that were active (that is,
    running) at the time. This update incorporates a fix that matches the logic
    used for determining active guests with that of xm list, such that both
    commands should now list the same number of active virtual guests under all
    circumstances. (BZ#618200)

    All users of libvirt are advised to upgrade to these updated packages,
    which contain backported patches to correct these issues. After installing
    the updated packages, the system must be rebooted for the update to take
    effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2010/rhsa-2010_0615.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17b668a5");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#low");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=602455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=607812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=617243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=618200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=619711");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0615");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL libvirt package based on the guidance in RHSA-2010:0615.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-2239");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-2242");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Low");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '5')) audit(AUDIT_OS_NOT, 'Red Hat 5.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/5/5Server/i386/vt/debug',
      'content/dist/rhel/server/5/5Server/i386/vt/os',
      'content/dist/rhel/server/5/5Server/i386/vt/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/vt/debug',
      'content/dist/rhel/server/5/5Server/x86_64/vt/os',
      'content/dist/rhel/server/5/5Server/x86_64/vt/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/i386/vt/debug',
      'content/dist/rhel/workstation/5/5Client/i386/vt/os',
      'content/dist/rhel/workstation/5/5Client/i386/vt/source/SRPMS',
      'content/dist/rhel/workstation/5/5Client/x86_64/vt/debug',
      'content/dist/rhel/workstation/5/5Client/x86_64/vt/os',
      'content/dist/rhel/workstation/5/5Client/x86_64/vt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'libvirt-0.6.3-33.el5_5.3', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-0.6.3-33.el5_5.3', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-0.6.3-33.el5_5.3', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-0.6.3-33.el5_5.3', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-python-0.6.3-33.el5_5.3', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-python-0.6.3-33.el5_5.3', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvirt / libvirt-devel / libvirt-python');
}
