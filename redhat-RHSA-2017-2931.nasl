#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2931. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(104004);
  script_version("3.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id(
    "CVE-2016-8399",
    "CVE-2017-1000111",
    "CVE-2017-1000112",
    "CVE-2017-11176",
    "CVE-2017-14106",
    "CVE-2017-7184",
    "CVE-2017-7541",
    "CVE-2017-7542",
    "CVE-2017-7558"
  );
  script_xref(name:"RHSA", value:"2017:2931");

  script_name(english:"RHEL 7 : kernel-rt (RHSA-2017:2931)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel-rt.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2017:2931 advisory.

    The kernel-rt packages provide the Real Time Linux Kernel, which enables fine-tuning for systems with
    extremely high determinism requirements.

    Security Fix(es):

    * Out-of-bounds kernel heap access vulnerability was found in xfrm, kernel's IP framework for transforming
    packets. An error dealing with netlink messages from an unprivileged user leads to arbitrary read/write
    and privilege escalation. (CVE-2017-7184, Important)

    * A race condition issue leading to a use-after-free flaw was found in the way the raw packet sockets are
    implemented in the Linux kernel networking subsystem handling synchronization. A local user able to open a
    raw packet socket (requires the CAP_NET_RAW capability) could use this flaw to elevate their privileges on
    the system. (CVE-2017-1000111, Important)

    * An exploitable memory corruption flaw was found in the Linux kernel. The append path can be erroneously
    switched from UFO to non-UFO in ip_ufo_append_data() when building an UFO packet with MSG_MORE option. If
    unprivileged user namespaces are available, this flaw can be exploited to gain root privileges.
    (CVE-2017-1000112, Important)

    * A flaw was found in the Linux networking subsystem where a local attacker with CAP_NET_ADMIN
    capabilities could cause an out-of-bounds memory access by creating a smaller-than-expected ICMP header
    and sending to its destination via sendto(). (CVE-2016-8399, Moderate)

    * Kernel memory corruption due to a buffer overflow was found in brcmf_cfg80211_mgmt_tx() function in
    Linux kernels from v3.9-rc1 to v4.13-rc1. The vulnerability can be triggered by sending a crafted
    NL80211_CMD_FRAME packet via netlink. This flaw is unlikely to be triggered remotely as certain userspace
    code is needed for this. An unprivileged local user could use this flaw to induce kernel memory corruption
    on the system, leading to a crash. Due to the nature of the flaw, privilege escalation cannot be fully
    ruled out, although it is unlikely. (CVE-2017-7541, Moderate)

    * An integer overflow vulnerability in ip6_find_1stfragopt() function was found. A local attacker that has
    privileges (of CAP_NET_RAW) to open raw socket can cause an infinite loop inside the ip6_find_1stfragopt()
    function. (CVE-2017-7542, Moderate)

    * A kernel data leak due to an out-of-bound read was found in the Linux kernel in
    inet_diag_msg_sctp{,l}addr_fill() and sctp_get_sctp_info() functions present since version 4.7-rc1 through
    version 4.13. A data leak happens when these functions fill in sockaddr data structures used to export
    socket's diagnostic information. As a result, up to 100 bytes of the slab data could be leaked to a
    userspace. (CVE-2017-7558, Moderate)

    * The mq_notify function in the Linux kernel through 4.11.9 does not set the sock pointer to NULL upon
    entry into the retry logic. During a user-space close of a Netlink socket, it allows attackers to possibly
    cause a situation where a value may be used after being freed (use-after-free) which may lead to memory
    corruption or other unspecified other impact. (CVE-2017-11176, Moderate)

    * A divide-by-zero vulnerability was found in the __tcp_select_window function in the Linux kernel. This
    can result in a kernel panic causing a local denial of service. (CVE-2017-14106, Moderate)

    Red Hat would like to thank Chaitin Security Research Lab for reporting CVE-2017-7184; Willem de Bruijn
    for reporting CVE-2017-1000111; and Andrey Konovalov for reporting CVE-2017-1000112. The CVE-2017-7558
    issue was discovered by Stefano Brivio (Red Hat).

    Bug Fix(es):

    * The kernel-rt packages have been upgraded to the 3.10.0-693.5.2 source tree, which provides number of
    bug fixes over the previous version. (BZ#1489084)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2017/rhsa-2017_2931.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d52cdb4f");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:2931");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1403833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1435153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1470659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1473198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1473649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1479304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1479307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1480266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1487295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1489084");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel-rt package based on the guidance in RHSA-2017:2931.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8399");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-7541");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(120, 122, 125, 20, 362, 369, 416, 835);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-trace-kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2016-8399', 'CVE-2017-7184', 'CVE-2017-7541', 'CVE-2017-7542', 'CVE-2017-7558', 'CVE-2017-11176', 'CVE-2017-14106', 'CVE-2017-1000111', 'CVE-2017-1000112');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2017:2931');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/7/7.9/x86_64/nfv/debug',
      'content/dist/rhel/server/7/7.9/x86_64/nfv/os',
      'content/dist/rhel/server/7/7.9/x86_64/nfv/source/SRPMS',
      'content/dist/rhel/server/7/7.9/x86_64/rt/debug',
      'content/dist/rhel/server/7/7.9/x86_64/rt/os',
      'content/dist/rhel/server/7/7.9/x86_64/rt/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/debug',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/os',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rt/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rt/os',
      'content/dist/rhel/server/7/7Server/x86_64/rt/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/rt/debug',
      'content/els/rhel/server/7/7Server/x86_64/rt/os',
      'content/els/rhel/server/7/7Server/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-3.10.0-693.5.2.rt56.626.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-3.10.0-693.5.2.rt56.626.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-3.10.0-693.5.2.rt56.626.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-3.10.0-693.5.2.rt56.626.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-3.10.0-693.5.2.rt56.626.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-doc-3.10.0-693.5.2.rt56.626.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-3.10.0-693.5.2.rt56.626.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-trace-3.10.0-693.5.2.rt56.626.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-trace-devel-3.10.0-693.5.2.rt56.626.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-trace-kvm-3.10.0-693.5.2.rt56.626.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-debug / kernel-rt-debug-devel / etc');
}
