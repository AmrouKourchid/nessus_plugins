#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:366. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(18095);
  script_version("1.38");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2005-0135",
    "CVE-2005-0207",
    "CVE-2005-0210",
    "CVE-2005-0384",
    "CVE-2005-0400",
    "CVE-2005-0449",
    "CVE-2005-0529",
    "CVE-2005-0530",
    "CVE-2005-0531",
    "CVE-2005-0736",
    "CVE-2005-0749",
    "CVE-2005-0750",
    "CVE-2005-0767",
    "CVE-2005-0815",
    "CVE-2005-0839",
    "CVE-2005-0867",
    "CVE-2005-0977",
    "CVE-2005-1041"
  );
  script_xref(name:"RHSA", value:"2005:366");

  script_name(english:"RHEL 4 : kernel (RHSA-2005:366)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 4 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2005:366 advisory.

    The Linux kernel handles the basic functions of the operating system.

    A flaw in the fib_seq_start function was discovered. A local user could use
    this flaw to cause a denial of service (system crash) via /proc/net/route.
    (CAN-2005-1041)

    A flaw in the tmpfs file system was discovered. A local user could use this
    flaw to cause a denial of service (system crash). (CAN-2005-0977)

    An integer overflow flaw was found when writing to a sysfs file. A local
    user could use this flaw to overwrite kernel memory, causing a denial of
    service (system crash) or arbitrary code execution. (CAN-2005-0867)

    Keith Owens reported a flaw in the Itanium unw_unwind_to_user function. A
    local user could use this flaw to cause a denial of service (system crash)
    on Itanium architectures. (CAN-2005-0135)

    A flaw in the NFS client O_DIRECT error case handling was discovered. A
    local user could use this flaw to cause a denial of service (system crash).
    (CAN-2005-0207)

    A small memory leak when defragmenting local packets was discovered that
    affected the Linux 2.6 kernel netfilter subsystem.  A local user could send
    a large number of carefully crafted fragments leading to memory exhaustion
    (CAN-2005-0210)

    A flaw was discovered in the Linux PPP driver. On systems allowing remote
    users to connect to a server using ppp, a remote client could cause a
    denial of service (system crash). (CAN-2005-0384)

    A flaw was discovered in the ext2 file system code. When a new directory is
    created, the ext2 block written to disk is not initialized, which could
    lead to an information leak if a disk image is made available to
    unprivileged users. (CAN-2005-0400)

    A flaw in fragment queuing was discovered that affected the Linux kernel
    netfilter subsystem. On systems configured to filter or process network
    packets (e.g. firewalling), a remote attacker could send a carefully
    crafted set of fragmented packets to a machine and cause a denial of
    service (system crash). In order to sucessfully exploit this flaw, the
    attacker would need to know or guess some aspects of the firewall ruleset
    on the target system. (CAN-2005-0449)

    A number of flaws were found in the Linux 2.6 kernel. A local user could
    use these flaws to read kernel memory or cause a denial of service (crash).
    (CAN-2005-0529, CAN-2005-0530, CAN-2005-0531)

    An integer overflow in sys_epoll_wait in eventpoll.c was discovered. A
    local user could use this flaw to overwrite low kernel memory. This memory
    is usually unused, not usually resulting in a security consequence.
    (CAN-2005-0736)

    A flaw when freeing a pointer in load_elf_library was discovered. A local
    user could potentially use this flaw to cause a denial of service (crash).
    (CAN-2005-0749)

    A flaw was discovered in the bluetooth driver system. On systems where the
    bluetooth modules are loaded, a local user could use this flaw to gain
    elevated (root) privileges. (CAN-2005-0750)

    A race condition was discovered that affected the Radeon DRI driver. A
    local user who has DRI privileges on a Radeon graphics card may be able to
    use this flaw to gain root privileges. (CAN-2005-0767)

    Multiple range checking flaws were discovered in the iso9660 file system
    handler. An attacker could create a malicious file system image which would
    cause a denial or service or potentially execute arbitrary code if mounted.
    (CAN-2005-0815)

    A flaw was discovered when setting line discipline on a serial tty. A local
    user may be able to use this flaw to inject mouse movements or keystrokes
    when another user is logged in. (CAN-2005-0839)

    Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
    to the packages associated with their machine architectures and
    configurations as listed in this erratum.

    Please note that

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2005/rhsa-2005_366.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb3aaf5e");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2005:366");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=147468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=148868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=148878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=149466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=149589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=151240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=151249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=151902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=152177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=152399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=152405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=152410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=152417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=152561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=154219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=154551");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2005:366.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-0867");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2005-0839");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2005-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '4')) audit(AUDIT_OS_NOT, 'Red Hat 4.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2005-0135', 'CVE-2005-0207', 'CVE-2005-0210', 'CVE-2005-0384', 'CVE-2005-0400', 'CVE-2005-0449', 'CVE-2005-0529', 'CVE-2005-0530', 'CVE-2005-0531', 'CVE-2005-0736', 'CVE-2005-0749', 'CVE-2005-0750', 'CVE-2005-0767', 'CVE-2005-0815', 'CVE-2005-0839', 'CVE-2005-0867', 'CVE-2005-0977', 'CVE-2005-1041');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2005:366');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/as/4/4AS/i386/os',
      'content/dist/rhel/as/4/4AS/i386/source/SRPMS',
      'content/dist/rhel/as/4/4AS/x86_64/os',
      'content/dist/rhel/as/4/4AS/x86_64/source/SRPMS',
      'content/dist/rhel/desktop/4/4Desktop/i386/os',
      'content/dist/rhel/desktop/4/4Desktop/i386/source/SRPMS',
      'content/dist/rhel/desktop/4/4Desktop/x86_64/os',
      'content/dist/rhel/desktop/4/4Desktop/x86_64/source/SRPMS',
      'content/dist/rhel/es/4/4ES/i386/os',
      'content/dist/rhel/es/4/4ES/i386/source/SRPMS',
      'content/dist/rhel/es/4/4ES/x86_64/os',
      'content/dist/rhel/es/4/4ES/x86_64/source/SRPMS',
      'content/dist/rhel/system-z/4/4AS/s390/os',
      'content/dist/rhel/system-z/4/4AS/s390/source/SRPMS',
      'content/dist/rhel/system-z/4/4AS/s390x/os',
      'content/dist/rhel/system-z/4/4AS/s390x/source/SRPMS',
      'content/dist/rhel/ws/4/4WS/i386/os',
      'content/dist/rhel/ws/4/4WS/i386/source/SRPMS',
      'content/dist/rhel/ws/4/4WS/x86_64/os',
      'content/dist/rhel/ws/4/4WS/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-2.6.9-5.0.5.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-5.0.5.EL', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-5.0.5.EL', 'cpu':'ppc64iseries', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-5.0.5.EL', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-5.0.5.EL', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-5.0.5.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-5.0.5.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-5.0.5.EL', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-5.0.5.EL', 'cpu':'ppc64iseries', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-5.0.5.EL', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-5.0.5.EL', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-5.0.5.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-hugemem-2.6.9-5.0.5.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-hugemem-devel-2.6.9-5.0.5.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-smp-2.6.9-5.0.5.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-smp-2.6.9-5.0.5.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-smp-devel-2.6.9-5.0.5.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-smp-devel-2.6.9-5.0.5.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-devel / kernel-hugemem / kernel-hugemem-devel / etc');
}
