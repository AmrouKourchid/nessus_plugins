#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1019. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63993);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2011-2511");
  script_bugtraq_id(48478);
  script_xref(name:"RHSA", value:"2011:1019");

  script_name(english:"RHEL 5 : libvirt (RHSA-2011:1019)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2011:1019 advisory.

    The libvirt library is a C API for managing and interacting with the
    virtualization capabilities of Linux and other operating systems.

    An integer overflow flaw was found in libvirtd's RPC call handling. An
    attacker able to establish read-only connections to libvirtd could trigger
    this flaw by calling virDomainGetVcpus() with specially-crafted parameters,
    causing libvirtd to crash. (CVE-2011-2511)

    This update fixes the following bugs:

    * libvirt was rebased from version 0.6.3 to version 0.8.2 in Red Hat
    Enterprise Linux 5.6. A code audit found a minor API change that effected
    error messages seen by libvirt 0.8.2 clients talking to libvirt 0.7.1 
    0.7.7 (0.7.x) servers. A libvirt 0.7.x server could send
    VIR_ERR_BUILD_FIREWALL errors where a libvirt 0.8.2 client expected
    VIR_ERR_CONFIG_UNSUPPORTED errors. In other circumstances, a libvirt 0.8.2
    client saw a Timed out during operation message where it should see an
    Invalid network filter error. This update adds a backported patch that
    allows libvirt 0.8.2 clients to interoperate with the API as used by
    libvirt 0.7.x servers, ensuring correct error messages are sent.
    (BZ#665075)

    * libvirt could crash if the maximum number of open file descriptors
    (_SC_OPEN_MAX) grew larger than the FD_SETSIZE value because it accessed
    file descriptors outside the bounds of the set. With this update the
    maximum number of open file descriptors can no longer grow larger than the
    FD_SETSIZE value. (BZ#665549)

    * A libvirt race condition was found. An array in the libvirt event
    handlers was accessed with a lock temporarily released. In rare cases, if
    one thread attempted to access this array but a second thread reallocated
    the array before the first thread reacquired a lock, it could lead to the
    first thread attempting to access freed memory, potentially causing libvirt
    to crash. With this update libvirt no longer refers to the old array and,
    consequently, behaves as expected. (BZ#671569)

    * Guests connected to a passthrough NIC would kernel panic if a
    system_reset signal was sent through the QEMU monitor. With this update you
    can reset such guests as expected. (BZ#689880)

    * When using the Xen kernel, the rpmbuild command failed on the xencapstest
    test. With this update you can run rpmbuild successfully when using the Xen
    kernel. (BZ#690459)

    * When a disk was hot unplugged, ret >= 0 was passed to the qemuAuditDisk
    calls in disk hotunplug operations before ret was, in fact, set to 0. As
    well, the error path jumped to the cleanup label prematurely. As a
    consequence, hotunplug failures were not audited and hotunplug successes
    were audited as failures. This was corrected and hot unplugging checks now
    behave as expected. (BZ#710151)

    * A conflict existed between filter update locking sequences and virtual
    machine startup locking sequences. When a filter update occurred on one or
    more virtual machines, a deadlock could consequently occur if a virtual
    machine referencing a filter was started. This update changes and makes
    more flexible several qemu locking sequences ensuring this deadlock no
    longer occurs. (BZ#697749)

    * qemudDomainSaveImageStartVM closed some incoming file descriptor (fd)
    arguments without informing the caller. The consequent double-closes could
    cause Domain restoration failure. This update alters the
    qemudDomainSaveImageStartVM signature to prevent the double-closes.
    (BZ#681623)

    This update also adds the following enhancements:

    * The libvirt Xen driver now supports more than one serial port.
    (BZ#670789)

    * Enabling and disabling the High Precision Event Timer (HPET) in Xen
    domains is now possible. (BZ#703193)

    All libvirt users should install this update which addresses this
    vulnerability, fixes these bugs and adds these enhancements. After
    installing the updated packages, libvirtd must be restarted (service
    libvirtd restart) for this update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2011/rhsa-2011_1019.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d913554");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=665075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=665549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=671569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=681623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=689880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=690459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=697749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=703193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=710151");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=717199");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2011:1019");
  script_set_attribute(attribute:"solution", value:
"Update the affected libvirt, libvirt-devel and / or libvirt-python packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-2511");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(190);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/21");
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
      {'reference':'libvirt-0.8.2-22.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-0.8.2-22.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-0.8.2-22.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-0.8.2-22.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-python-0.8.2-22.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-python-0.8.2-22.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
