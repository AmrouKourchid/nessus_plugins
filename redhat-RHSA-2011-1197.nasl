#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1197. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55966);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id("CVE-2011-2511");
  script_bugtraq_id(48478);
  script_xref(name:"RHSA", value:"2011:1197");

  script_name(english:"RHEL 6 : libvirt (RHSA-2011:1197)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for libvirt.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2011:1197 advisory.

    The libvirt library is a C API for managing and interacting with the
    virtualization capabilities of Linux and other operating systems. In
    addition, libvirt provides tools for remotely managing virtualized systems.

    An integer overflow flaw was found in libvirtd's RPC call handling. An
    attacker able to establish read-only connections to libvirtd could trigger
    this flaw by calling virDomainGetVcpus() with specially-crafted parameters,
    causing libvirtd to crash. (CVE-2011-2511)

    This update also fixes the following bugs:

    * Previously, when the virsh vol-create-from command was run on an LVM
    (Logical Volume Manager) storage pool, performance of the command was very
    low and the operation consumed an excessive amount of time. This bug has
    been fixed in the virStorageVolCreateXMLFrom() function, and the
    performance problem of the command no longer occurs.

    * Due to a regression, libvirt used undocumented command line options,
    instead of the recommended ones. Consequently, the qemu-img utility used an
    invalid argument while creating an encrypted volume, and the process
    eventually failed. With this update, the bug in the backing format of the
    storage back end has been fixed, and encrypted volumes can now be created
    as expected. (BZ#726617)

    * Due to a bug in the qemuAuditDisk() function, hot unplug failures were
    never audited, and a hot unplug success was audited as a failure. This bug
    has been fixed, and auditing of disk hot unplug operations now works as
    expected. (BZ#728516)

    * Previously, when a debug process was being activated, the act of
    preparing a debug message ended up with dereferencing a UUID (universally
    unique identifier) prior to the NULL argument check. Consequently, an API
    running the debug process sometimes terminated with a segmentation fault.
    With this update, a patch has been provided to address this issue, and the
    crashes no longer occur in the described scenario. (BZ#728546)

    * The libvirt library uses the boot=on option to mark which disk is
    bootable but it only uses that option if Qemu advertises its support. The
    qemu-kvm utility in Red Hat Enterprise Linux 6.1 removed support for that
    option and libvirt could not use it. As a consequence, when an IDE disk was
    added as the second storage with a virtio disk being set up as the first
    one by default, the operating system tried to boot from the IDE disk rather
    than the virtio disk and either failed to boot with the No bootable disk
    error message returned, or the system booted whatever operating system was
    on the IDE disk. With this update, the boot configuration is translated
    into bootindex, which provides control over which device is used for
    booting a guest operating system, thus fixing this bug.

    All users of libvirt are advised to upgrade to these updated packages,
    which contain backported patches to correct these issues. After installing
    the updated packages, libvirtd must be restarted (service libvirtd
    restart) for this update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2011/rhsa-2011_1197.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70ed6727");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=717199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=726617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=728516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=728546");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2011:1197");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL libvirt package based on the guidance in RHSA-2011:1197.");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/power/6/6Server/ppc64/debug',
      'content/dist/rhel/power/6/6Server/ppc64/optional/debug',
      'content/dist/rhel/power/6/6Server/ppc64/optional/os',
      'content/dist/rhel/power/6/6Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/os',
      'content/dist/rhel/power/6/6Server/ppc64/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/os',
      'content/dist/rhel/server/6/6Server/i386/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/optional/debug',
      'content/dist/rhel/server/6/6Server/i386/optional/os',
      'content/dist/rhel/server/6/6Server/i386/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/os',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/optional/debug',
      'content/dist/rhel/server/6/6Server/x86_64/optional/os',
      'content/dist/rhel/server/6/6Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/os',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/os',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/os',
      'content/dist/rhel/system-z/6/6Server/s390x/source/SRPMS',
      'content/fastrack/rhel/power/6/ppc64/debug',
      'content/fastrack/rhel/power/6/ppc64/optional/debug',
      'content/fastrack/rhel/power/6/ppc64/optional/os',
      'content/fastrack/rhel/power/6/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/6/ppc64/os',
      'content/fastrack/rhel/power/6/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/os',
      'content/fastrack/rhel/server/6/i386/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/loadbalancer/debug',
      'content/fastrack/rhel/server/6/i386/loadbalancer/os',
      'content/fastrack/rhel/server/6/i386/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/optional/debug',
      'content/fastrack/rhel/server/6/i386/optional/os',
      'content/fastrack/rhel/server/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/debug',
      'content/fastrack/rhel/server/6/i386/resilientstorage/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/os',
      'content/fastrack/rhel/server/6/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/debug',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/os',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/optional/debug',
      'content/fastrack/rhel/server/6/x86_64/optional/os',
      'content/fastrack/rhel/server/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/6/s390x/debug',
      'content/fastrack/rhel/system-z/6/s390x/optional/debug',
      'content/fastrack/rhel/system-z/6/s390x/optional/os',
      'content/fastrack/rhel/system-z/6/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/6/s390x/os',
      'content/fastrack/rhel/system-z/6/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'libvirt-0.8.7-18.el6_1.1', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-0.8.7-18.el6_1.1', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-0.8.7-18.el6_1.1', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-0.8.7-18.el6_1.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-0.8.7-18.el6_1.1', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-0.8.7-18.el6_1.1', 'cpu':'ppc', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-0.8.7-18.el6_1.1', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-0.8.7-18.el6_1.1', 'cpu':'s390', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-0.8.7-18.el6_1.1', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-client-0.8.7-18.el6_1.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-0.8.7-18.el6_1.1', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-0.8.7-18.el6_1.1', 'cpu':'ppc', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-0.8.7-18.el6_1.1', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-0.8.7-18.el6_1.1', 'cpu':'s390', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-0.8.7-18.el6_1.1', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-devel-0.8.7-18.el6_1.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-python-0.8.7-18.el6_1.1', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-python-0.8.7-18.el6_1.1', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-python-0.8.7-18.el6_1.1', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-python-0.8.7-18.el6_1.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvirt / libvirt-client / libvirt-devel / libvirt-python');
}
