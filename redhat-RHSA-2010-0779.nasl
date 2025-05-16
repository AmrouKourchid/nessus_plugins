#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0779. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(50037);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2010-2942", "CVE-2010-3067", "CVE-2010-3477");
  script_bugtraq_id(42529, 43353);
  script_xref(name:"RHSA", value:"2010:0779");

  script_name(english:"RHEL 4 : kernel (RHSA-2010:0779)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 4 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2010:0779 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux
    operating system.

    This update fixes the following security issues:

    * Information leak flaws were found in the Linux kernel Traffic Control
    Unit implementation. A local attacker could use these flaws to cause the
    kernel to leak kernel memory to user-space, possibly leading to the
    disclosure of sensitive information. (CVE-2010-2942, Moderate)

    * A flaw was found in the tcf_act_police_dump() function in the Linux
    kernel network traffic policing implementation. A data structure in
    tcf_act_police_dump() was not initialized properly before being copied to
    user-space. A local, unprivileged user could use this flaw to cause an
    information leak. (CVE-2010-3477, Moderate)

    * A missing upper bound integer check was found in the sys_io_submit()
    function in the Linux kernel asynchronous I/O implementation. A local,
    unprivileged user could use this flaw to cause an information leak.
    (CVE-2010-3067, Low)

    Red Hat would like to thank Tavis Ormandy for reporting CVE-2010-3067.

    This update also fixes the following bugs:

    * When two systems using bonding devices in the adaptive load balancing
    (ALB) mode communicated with each other, an endless loop of ARP replies
    started between these two systems due to a faulty MAC address update. With
    this update, the MAC address update no longer creates unneeded ARP replies.
    (BZ#629239)

    * When running the Connectathon NFS Testsuite with certain clients and Red
    Hat Enterprise Linux 4.8 as the server, nfsvers4, lock, and test2 failed
    the Connectathon test. (BZ#625535)

    * For UDP/UNIX domain sockets, due to insufficient memory barriers in the
    network code, a process sleeping in select() may have missed notifications
    about new data. In rare cases, this bug may have caused a process to sleep
    forever. (BZ#640117)

    * In certain situations, a bug found in either the HTB or TBF network
    packet schedulers in the Linux kernel could have caused a kernel panic when
    using Broadcom network cards with the bnx2 driver. (BZ#624363)

    * Previously, allocating fallback cqr for DASD reserve/release IOCTLs
    failed because it used the memory pool of the respective device. This
    update preallocates sufficient memory for a single reserve/release request.
    (BZ#626828)

    * In some situations a bug prevented force online succeeding for a DASD
    device. (BZ#626827)

    * Using the fsstress utility may have caused a kernel panic. (BZ#633968)

    * This update introduces additional stack guard patches. (BZ#632515)

    * A bug was found in the way the megaraid_sas driver handled physical disks
    and management IOCTLs. All physical disks were exported to the disk layer,
    allowing an oops in megasas_complete_cmd_dpc() when completing the IOCTL
    command if a timeout occurred. (BZ#631903)

    * Previously, a warning message was returned when a large amount of
    messages was passed through netconsole and a considerable amount of network
    load was added. With this update, the warning message is no longer
    displayed. (BZ#637729)

    * Executing a large dd command (1 to 5GB) on an iSCSI device with the
    qla3xxx driver caused a system crash due to the incorrect storing of a
    private data structure. With this update, the size of the stored data
    structure is checked and the system crashes no longer occur. (BZ#624364)

    Users should upgrade to these updated packages, which contain backported
    patches to correct these issues. The system must be rebooted for this
    update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2010/rhsa-2010_0779.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45f6426c");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=624363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=624364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=624903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=625535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=626827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=626828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=629239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=629441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=631903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=632515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=633968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=636386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=637729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=640117");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0779");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2010:0779.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3477");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-2942");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(401);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var cve_list = make_list('CVE-2010-2942', 'CVE-2010-3067', 'CVE-2010-3477');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2010:0779');
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
      {'reference':'kernel-2.6.9-89.31.1.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-89.31.1.EL', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-89.31.1.EL', 'cpu':'ppc64iseries', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-89.31.1.EL', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-89.31.1.EL', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-89.31.1.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-89.31.1.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-89.31.1.EL', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-89.31.1.EL', 'cpu':'ppc64iseries', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-89.31.1.EL', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-89.31.1.EL', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-89.31.1.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-hugemem-2.6.9-89.31.1.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-hugemem-devel-2.6.9-89.31.1.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-largesmp-2.6.9-89.31.1.EL', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-largesmp-2.6.9-89.31.1.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-largesmp-devel-2.6.9-89.31.1.EL', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-largesmp-devel-2.6.9-89.31.1.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-smp-2.6.9-89.31.1.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-smp-2.6.9-89.31.1.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-smp-devel-2.6.9-89.31.1.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-smp-devel-2.6.9-89.31.1.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xenU-2.6.9-89.31.1.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xenU-2.6.9-89.31.1.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xenU-devel-2.6.9-89.31.1.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xenU-devel-2.6.9-89.31.1.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-devel / kernel-hugemem / kernel-hugemem-devel / etc');
}
