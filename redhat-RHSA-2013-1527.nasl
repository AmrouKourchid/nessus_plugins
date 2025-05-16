#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1527. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78979);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2010-5107",
    "CVE-2013-2888",
    "CVE-2013-2889",
    "CVE-2013-2892",
    "CVE-2013-4238",
    "CVE-2013-4344"
  );
  script_bugtraq_id(
    58162,
    61738,
    62042,
    62043,
    62049,
    62773
  );
  script_xref(name:"RHSA", value:"2013:1527");

  script_name(english:"RHEL 6 : rhev-hypervisor6 (RHSA-2013:1527)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for rhev-hypervisor6.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2013:1527 advisory.

    The rhev-hypervisor6 package provides a Red Hat Enterprise Virtualization
    Hypervisor ISO disk image. The Red Hat Enterprise Virtualization Hypervisor
    is a dedicated Kernel-based Virtual Machine (KVM) hypervisor. It includes
    everything necessary to run and manage virtual machines: a subset of the
    Red Hat Enterprise Linux operating environment and the Red Hat Enterprise
    Virtualization Agent.

    Note: Red Hat Enterprise Virtualization Hypervisor is only available for
    the Intel 64 and AMD64 architectures with virtualization extensions.

    Upgrade Note: If you upgrade the Red Hat Enterprise Virtualization
    Hypervisor through the 3.2 Manager administration portal, the Host may
    appear with the status of Install Failed. If this happens, place the host
    into maintenance mode, then activate it again to get the host back to an
    Up state.

    A buffer overflow flaw was found in the way QEMU processed the SCSI REPORT
    LUNS command when more than 256 LUNs were specified for a single SCSI
    target. A privileged guest user could use this flaw to corrupt QEMU process
    memory on the host, which could potentially result in arbitrary code
    execution on the host with the privileges of the QEMU process.
    (CVE-2013-4344)

    Multiple flaws were found in the way Linux kernel handled HID (Human
    Interface Device) reports. An attacker with physical access to the system
    could use this flaw to crash the system or, potentially, escalate their
    privileges on the system. (CVE-2013-2888, CVE-2013-2889, CVE-2013-2892)

    A flaw was found in the way the Python SSL module handled X.509 certificate
    fields that contain a NULL byte. An attacker could potentially exploit this
    flaw to conduct man-in-the-middle attacks to spoof SSL servers. Note that
    to exploit this issue, an attacker would need to obtain a carefully crafted
    certificate signed by an authority that the client trusts. (CVE-2013-4238)

    The default OpenSSH configuration made it easy for remote attackers to
    exhaust unauthorized connection slots and prevent other users from being
    able to log in to a system. This flaw has been addressed by enabling random
    early connection drops by setting MaxStartups to 10:30:100 by default.
    For more information, refer to the sshd_config(5) man page. (CVE-2010-5107)

    The CVE-2013-4344 issue was discovered by Asias He of Red Hat.

    This updated package provides updated components that include fixes for
    various security issues. These issues have no security impact on Red Hat
    Enterprise Virtualization Hypervisor itself, however. The security fixes
    included in this update address the following CVE numbers:

    CVE-2012-0786 and CVE-2012-0787 (augeas issues)

    CVE-2013-1813 (busybox issue)

    CVE-2013-0221, CVE-2013-0222, and CVE-2013-0223 (coreutils issues)

    CVE-2012-4453 (dracut issue)

    CVE-2013-4332, CVE-2013-0242, and CVE-2013-1914 (glibc issues)

    CVE-2013-4387, CVE-2013-0343, CVE-2013-4345, CVE-2013-4591, CVE-2013-4592,
    CVE-2012-6542, CVE-2013-3231, CVE-2013-1929, CVE-2012-6545, CVE-2013-1928,
    CVE-2013-2164, CVE-2013-2234, and CVE-2013-2851 (kernel issues)

    CVE-2013-4242 (libgcrypt issue)

    CVE-2013-4419 (libguestfs issue)

    CVE-2013-1775, CVE-2013-2776, and CVE-2013-2777 (sudo issues)

    This update also fixes the following bug:

    * A previous version of the rhev-hypervisor6 package did not contain the
    latest vhostmd package, which provides a metrics communication channel
    between a host and its hosted virtual machines, allowing limited
    introspection of host resource usage from within virtual machines. This has
    been fixed, and rhev-hypervisor6 now includes the latest vhostmd package.
    (BZ#1026703)

    This update also contains the fixes from the following errata:

    * ovirt-node: https://rhn.redhat.com/errata/RHBA-2013-1528.html

    Users of the Red Hat Enterprise Virtualization Hypervisor are advised to
    upgrade to this updated package, which corrects these issues.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2013/rhsa-2013_1527.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45696eb4");
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Hypervisor_Deployment_Guide/chap-Deployment_Guide-Upgrading_Red_Hat_Enterprise_Virtualization_Hypervisors.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d1b5f78");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:1527");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1000429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1000451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1007330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1026703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=908060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=908707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=996381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=999890");
  script_set_attribute(attribute:"see_also", value:"https://rhn.redhat.com/errata/RHBA-2013-1528.html");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL rhev-hypervisor6 package based on the guidance in RHSA-2013:1527.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4344");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-5107");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122, 400);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhev-hypervisor6");
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
      'content/dist/rhel/client/6/6Client/i386/rhv-agent/4/debug',
      'content/dist/rhel/client/6/6Client/i386/rhv-agent/4/os',
      'content/dist/rhel/client/6/6Client/i386/rhv-agent/4/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/rhv-agent/4/debug',
      'content/dist/rhel/client/6/6Client/x86_64/rhv-agent/4/os',
      'content/dist/rhel/client/6/6Client/x86_64/rhv-agent/4/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/rhv-agent/4/debug',
      'content/dist/rhel/server/6/6Server/i386/rhv-agent/4/os',
      'content/dist/rhel/server/6/6Server/i386/rhv-agent/4/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/rhevh/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhevh/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhevh/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/rhv-agent/4/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhv-agent/4/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhv-agent/4/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/rhv-agent/4/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/rhv-agent/4/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/rhv-agent/4/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhv-agent/4/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhv-agent/4/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhv-agent/4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rhev-hypervisor6-6.5-20131115.0.3.2.el6_5', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ovirt-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rhev-hypervisor6');
}
