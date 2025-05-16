#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0331. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(35919);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id(
    "CVE-2008-5700",
    "CVE-2009-0031",
    "CVE-2009-0065",
    "CVE-2009-0322"
  );
  script_bugtraq_id(33113);
  script_xref(name:"RHSA", value:"2009:0331");

  script_name(english:"RHEL 4 : kernel (RHSA-2009:0331)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 4 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2009:0331 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux
    operating system.

    This update addresses the following security issues:

    * a buffer overflow was found in the Linux kernel Partial Reliable Stream
    Control Transmission Protocol (PR-SCTP) implementation. This could,
    potentially, lead to a denial of service if a Forward-TSN chunk is received
    with a large stream ID. (CVE-2009-0065, Important)

    * a memory leak was found in keyctl handling. A local, unprivileged user
    could use this flaw to deplete kernel memory, eventually leading to a
    denial of service. (CVE-2009-0031, Important)

    * a deficiency was found in the Remote BIOS Update (RBU) driver for Dell
    systems. This could allow a local, unprivileged user to cause a denial of
    service by reading zero bytes from the image_type or packet_size file in
    /sys/devices/platform/dell_rbu/. (CVE-2009-0322, Important)

    * a deficiency was found in the libATA implementation. This could,
    potentially, lead to a denial of service. Note: by default, /dev/sg*
    devices are accessible only to the root user. (CVE-2008-5700, Low)

    This update also fixes the following bugs:

    * when the hypervisor changed a page table entry (pte) mapping from
    read-only to writable via a make_writable hypercall, accessing the changed
    page immediately following the change caused a spurious page fault. When
    trying to install a para-virtualized Red Hat Enterprise Linux 4 guest on a
    Red Hat Enterprise Linux 5.3 dom0 host, this fault crashed the installer
    with a kernel backtrace. With this update, the spurious page fault is
    handled properly. (BZ#483748)

    * net_rx_action could detect its cpu poll_list as non-empty, but have that
    same list reduced to empty by the poll_napi path. This resulted in garbage
    data being returned when net_rx_action calls list_entry, which subsequently
    resulted in several possible crash conditions. The race condition in the
    network code which caused this has been fixed. (BZ#475970, BZ#479681,
    BZ#480741)

    * a misplaced memory barrier at unlock_buffer() could lead to a concurrent
    h_refcounter update which produced a reference counter leak and, later, a
    double free in ext3_xattr_release_block(). Consequent to the double free,
    ext3 reported an error

        ext3_free_blocks_sb: bit already cleared for block [block number]

    and mounted itself as read-only. With this update, the memory barrier is
    now placed before the buffer head lock bit, forcing the write order and
    preventing the double free. (BZ#476533)

    * when the iptables module was unloaded, it was assumed the correct entry
    for removal had been found if wrapper->ops->pf matched the value passed
    in by reg->pf. If several ops ranges were registered against the same
    protocol family, however, (which was likely if you had both ip_conntrack
    and ip_contrack_* loaded) this assumption could lead to NULL list pointers
    and cause a kernel panic. With this update, wrapper->ops is matched to
    pointer values reg, which ensures the correct entry is removed and
    results in no NULL list pointers. (BZ#477147)

    * when the pidmap page (used for tracking process ids, pids) incremented to
    an even page (ie the second, fourth, sixth, etc. pidmap page), the
    alloc_pidmap() routine skipped the page. This resulted in holes in the
    allocated pids. For example, after pid 32767, you would expect 32768 to be
    allocated. If the page skipping behavior presented, however, the pid
    allocated after 32767 was 65536. With this update, alloc_pidmap() no longer
    skips alternate pidmap pages and allocated pid holes no longer occur. This
    fix also corrects an error which allowed pid_max to be set higher than the
    pid_max limit has been corrected. (BZ#479182)

    All Red Hat Enterprise Linux 4 users should upgrade to these updated
    packages, which contain backported patches to resolve these issues. The
    system must be rebooted for this update to take effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2009/rhsa-2009_0331.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee47db58");
  script_set_attribute(attribute:"see_also", value:"http://www.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=474495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=475970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=476533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=477147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=478800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=479182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=479681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=480592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=480741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=482866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=483748");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2009:0331");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2009:0331.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-0065");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2009-0322");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/13");

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

  script_copyright(english:"This script is Copyright (C) 2009-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var cve_list = make_list('CVE-2008-5700', 'CVE-2009-0031', 'CVE-2009-0065', 'CVE-2009-0322');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2009:0331');
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
      {'reference':'kernel-2.6.9-78.0.17.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-78.0.17.EL', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-78.0.17.EL', 'cpu':'ppc64iseries', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-78.0.17.EL', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-78.0.17.EL', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.9-78.0.17.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-78.0.17.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-78.0.17.EL', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-78.0.17.EL', 'cpu':'ppc64iseries', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-78.0.17.EL', 'cpu':'s390', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-78.0.17.EL', 'cpu':'s390x', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.9-78.0.17.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-hugemem-2.6.9-78.0.17.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-hugemem-devel-2.6.9-78.0.17.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-largesmp-2.6.9-78.0.17.EL', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-largesmp-2.6.9-78.0.17.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-largesmp-devel-2.6.9-78.0.17.EL', 'cpu':'ppc64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-largesmp-devel-2.6.9-78.0.17.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-smp-2.6.9-78.0.17.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-smp-2.6.9-78.0.17.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-smp-devel-2.6.9-78.0.17.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-smp-devel-2.6.9-78.0.17.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xenU-2.6.9-78.0.17.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xenU-2.6.9-78.0.17.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xenU-devel-2.6.9-78.0.17.EL', 'cpu':'i686', 'release':'4', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-xenU-devel-2.6.9-78.0.17.EL', 'cpu':'x86_64', 'release':'4', 'rpm_spec_vers_cmp':TRUE}
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
