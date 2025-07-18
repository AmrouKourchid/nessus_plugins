##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:1567. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(136116);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2018-16871",
    "CVE-2019-8980",
    "CVE-2020-10690",
    "CVE-2019-10639",
    "CVE-2019-12819",
    "CVE-2019-15090",
    "CVE-2019-15099",
    "CVE-2019-15221",
    "CVE-2019-15223",
    "CVE-2019-16234",
    "CVE-2019-17053",
    "CVE-2019-17055",
    "CVE-2019-18282",
    "CVE-2019-18805",
    "CVE-2019-19045",
    "CVE-2019-19047",
    "CVE-2019-19055",
    "CVE-2019-19057",
    "CVE-2019-19058",
    "CVE-2019-19059",
    "CVE-2019-19065",
    "CVE-2019-19067",
    "CVE-2019-19073",
    "CVE-2019-19074",
    "CVE-2019-19077",
    "CVE-2019-19532",
    "CVE-2019-19534",
    "CVE-2019-19768",
    "CVE-2019-19922",
    "CVE-2019-5108",
    "CVE-2020-1749",
    "CVE-2020-7053",
    "CVE-2021-33630"
  );
  script_bugtraq_id(107120, 108547, 108768);
  script_xref(name:"RHSA", value:"2020:1567");

  script_name(english:"RHEL 8 : kernel-rt (RHSA-2020:1567)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:1567 advisory.

    The kernel-rt packages provide the Real Time Linux Kernel, which enables fine-tuning for systems with
    extremely high determinism requirements.

    Security Fix(es):

    * kernel: use-after-free in __blk_add_trace in kernel/trace/blktrace.c (CVE-2019-19768)

    * kernel: nfs: NULL pointer dereference due to an anomalized NFS message sequence (CVE-2018-16871)

    * kernel: memory leak in the kernel_read_file function in fs/exec.c allows to cause a denial of service
    (CVE-2019-8980)

    * kernel: unprivileged users able to create RAW sockets  in AF_IEEE802154 network protocol.
    (CVE-2019-17053)

    * kernel: unprivileged users able to create RAW sockets in AF_ISDN  network protocol. (CVE-2019-17055)

    * kernel: integer overflow in tcp_ack_update_rtt in net/ipv4/tcp_input.c (CVE-2019-18805)

    * kernel: information leak bug caused  by a malicious USB device in the
    drivers/net/can/usb/peak_usb/pcan_usb_core.c driver (CVE-2019-19534)

    * kernel: some ipv6 protocols not encrypted over ipsec tunnel. (CVE-2020-1749)

    * Kernel: net: using kernel space address bits to derive IP ID may potentially break KASLR
    (CVE-2019-10639)

    * kernel: An out-of-bounds read in drivers/scsi/qedi/qedi_dbg.c leading to crash or information disclosure
    (CVE-2019-15090)

    * kernel: a NULL pointer dereference in drivers/net/wireless/ath/ath10k/usb.c leads to a crash
    (CVE-2019-15099)

    * kernel: Null pointer dereference in the sound/usb/line6/pcm.c (CVE-2019-15221)

    * kernel: Two memory leaks in the mwifiex_pcie_init_evt_ring() function in
    drivers/net/wireless/marvell/mwifiex/pcie.c allows for a DoS (CVE-2019-19057)

    * kernel: Memory leaks in drivers/net/wireless/ath/ath9k/htc_hst.c in the Linux kernel (DOS)
    (CVE-2019-19073)

    * kernel: a memory leak in the ath9k management function in allows local DoS (CVE-2019-19074)

    * kernel: when cpu.cfs_quota_us is used allows attackers to cause a denial of service against non-cpu-
    bound applications (CVE-2019-19922)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * RT: update RT source tree to the RHEL-8.2 tree (BZ#1708716)

    * KVM-RT guest fails boot with emulatorsched (BZ#1712781)

    * 8 vCPU guest need max latency < 20 us with stress [RT-8.2] (BZ#1757165)

    * Request nx_huge_pages=N as default value to avoid kvm-rt guest large latency spike [rt-8] (BZ#1788352)

    * RT: Add rpm Provide of 'kernel' to indicate that this is a kernel package (BZ#1796284)

    * [RHEL8] RT kernel signed by test certificate and not Red Hat Secure Boot (BZ#1806871)

    Enhancement(s):

    * update to the upstream 5.x RT patchset (BZ#1680161)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_1567.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb57d5c7");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/8.2_release_notes/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd7b3f20");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:1567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1655162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1679972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1708716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1712781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1729933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1743526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1743560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1749974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1757165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1758242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1758248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1768730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1771496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1772738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1774933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1774937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1775050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1783540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1786164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1788352");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1792512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1796284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1806871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1809833");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18805");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 125, 190, 200, 250, 319, 400, 416, 440, 476);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-extra");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2018-16871', 'CVE-2019-5108', 'CVE-2019-8980', 'CVE-2019-10639', 'CVE-2019-12819', 'CVE-2019-15090', 'CVE-2019-15099', 'CVE-2019-15221', 'CVE-2019-15223', 'CVE-2019-16234', 'CVE-2019-17053', 'CVE-2019-17055', 'CVE-2019-18282', 'CVE-2019-18805', 'CVE-2019-19045', 'CVE-2019-19047', 'CVE-2019-19055', 'CVE-2019-19057', 'CVE-2019-19058', 'CVE-2019-19059', 'CVE-2019-19065', 'CVE-2019-19067', 'CVE-2019-19073', 'CVE-2019-19074', 'CVE-2019-19077', 'CVE-2019-19532', 'CVE-2019-19534', 'CVE-2019-19768', 'CVE-2019-19922', 'CVE-2020-1749', 'CVE-2020-7053', 'CVE-2020-10690', 'CVE-2021-33630');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2020:1567');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8.10/x86_64/nfv/debug',
      'content/dist/rhel8/8.10/x86_64/nfv/os',
      'content/dist/rhel8/8.10/x86_64/nfv/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/rt/debug',
      'content/dist/rhel8/8.10/x86_64/rt/os',
      'content/dist/rhel8/8.10/x86_64/rt/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/nfv/debug',
      'content/dist/rhel8/8.6/x86_64/nfv/os',
      'content/dist/rhel8/8.6/x86_64/nfv/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/rt/debug',
      'content/dist/rhel8/8.6/x86_64/rt/os',
      'content/dist/rhel8/8.6/x86_64/rt/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/nfv/debug',
      'content/dist/rhel8/8.8/x86_64/nfv/os',
      'content/dist/rhel8/8.8/x86_64/nfv/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/rt/debug',
      'content/dist/rhel8/8.8/x86_64/rt/os',
      'content/dist/rhel8/8.8/x86_64/rt/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/nfv/debug',
      'content/dist/rhel8/8.9/x86_64/nfv/os',
      'content/dist/rhel8/8.9/x86_64/nfv/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/rt/debug',
      'content/dist/rhel8/8.9/x86_64/rt/os',
      'content/dist/rhel8/8.9/x86_64/rt/source/SRPMS',
      'content/dist/rhel8/8/x86_64/nfv/debug',
      'content/dist/rhel8/8/x86_64/nfv/os',
      'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
      'content/dist/rhel8/8/x86_64/rt/debug',
      'content/dist/rhel8/8/x86_64/rt/os',
      'content/dist/rhel8/8/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-4.18.0-193.rt13.51.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-4.18.0-193.rt13.51.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-4.18.0-193.rt13.51.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-4.18.0-193.rt13.51.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-4.18.0-193.rt13.51.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-4.18.0-193.rt13.51.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-4.18.0-193.rt13.51.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-4.18.0-193.rt13.51.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-4.18.0-193.rt13.51.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-4.18.0-193.rt13.51.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-4.18.0-193.rt13.51.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-4.18.0-193.rt13.51.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-core / kernel-rt-debug / kernel-rt-debug-core / etc');
}
