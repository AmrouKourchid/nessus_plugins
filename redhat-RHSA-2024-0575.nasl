#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:0575. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189813);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id(
    "CVE-2023-0458",
    "CVE-2023-1073",
    "CVE-2023-1075",
    "CVE-2023-1079",
    "CVE-2023-1838",
    "CVE-2023-1855",
    "CVE-2023-2162",
    "CVE-2023-2163",
    "CVE-2023-3141",
    "CVE-2023-3567",
    "CVE-2023-3611",
    "CVE-2023-3772",
    "CVE-2023-3812",
    "CVE-2023-4132",
    "CVE-2023-4622",
    "CVE-2023-4623",
    "CVE-2023-5178",
    "CVE-2023-5717",
    "CVE-2023-23455",
    "CVE-2023-26545",
    "CVE-2023-28328",
    "CVE-2023-31436",
    "CVE-2023-33203",
    "CVE-2023-35823",
    "CVE-2023-35824",
    "CVE-2023-35825",
    "CVE-2023-45871",
    "CVE-2023-46813"
  );
  script_xref(name:"RHSA", value:"2024:0575");

  script_name(english:"RHEL 8 : kernel (RHSA-2024:0575)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:0575 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: bpf: Incorrect verifier pruning leads to unsafe code paths being incorrectly marked as safe
    (CVE-2023-2163)

    * kernel: net/sched: sch_qfq component can be exploited if in qfq_change_agg function happens qfq_enqueue
    overhead (CVE-2023-3611)

    * kernel: tun: bugs for oversize packet when napi frags enabled in tun_napi_alloc_frags (CVE-2023-3812)

    * kernel: use after free in unix_stream_sendpage (CVE-2023-4622)

    * kernel: net/sched: sch_hfsc UAF (CVE-2023-4623)

    * kernel: use after free in nvmet_tcp_free_crypto in NVMe (CVE-2023-5178)

    * kernel: out-of-bounds write in qfq_change_class function (CVE-2023-31436)

    * kernel: IGB driver inadequate buffer size for frames larger than MTU (CVE-2023-45871)

    * kernel: Race Condition leading to UAF in Unix Socket could happen in sk_receive_queue (BZ#2230094)

    * kernel: speculative pointer dereference in do_prlimit() in kernel/sys.c (CVE-2023-0458)

    * kernel: HID: check empty report_list in hid_validate_values() (CVE-2023-1073)

    * kernel: hid: Use After Free in asus_remove() (CVE-2023-1079)

    * kernel: Possible use-after-free since the two fdget() during vhost_net_set_backend() (CVE-2023-1838)

    * kernel: UAF during login when accessing the shost ipaddress (CVE-2023-2162)

    * kernel: use after free in vcs_read in drivers/tty/vt/vc_screen.c due to race (CVE-2023-3567)

    * kernel: xfrm: NULL pointer dereference in xfrm_update_ae_params() (CVE-2023-3772)

    * kernel: smsusb: use-after-free caused by do_submit_urb() (CVE-2023-4132)

    * kernel: A heap out-of-bounds write (CVE-2023-5717)

    * kernel: denial of service in atm_tc_enqueue in net/sched/sch_atm.c due to type confusion
    (CVE-2023-23455)

    * kernel: mpls: double free on sysctl allocation failure (CVE-2023-26545)

    * kernel: Denial of service issue in az6027 driver in drivers/media/usb/dev-usb/az6027.c (CVE-2023-28328)

    * kernel: net: qcom/emac: race condition leading to use-after-free in emac_remove() (CVE-2023-33203)

    * kernel: saa7134: race condition leading to use-after-free in saa7134_finidev() (CVE-2023-35823)

    * kernel: dm1105: race condition leading to use-after-free in dm1105_remove.c() (CVE-2023-35824)

    * kernel: r592: race condition leading to use-after-free in r592_remove() (CVE-2023-35825)

    * kernel: SEV-ES local priv escalation (CVE-2023-46813)

    * kernel: net/tls: tls_is_tx_ready() checked list_entry (CVE-2023-1075)

    * kernel: use-after-free bug in remove function xgene_hwmon_remove (CVE-2023-1855)

    * kernel: Use after free bug in r592_remove (CVE-2023-3141)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * [RHEL 8.9] Proactively backport locking fixes from upstream (BZ#2235393)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_0575.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e50d6007");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2087568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2168332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2173403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2173434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2173444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2177389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2182443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2187773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2192667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2192671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2193219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2213199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2215835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2215836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2215837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2218943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2221463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2221707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2230094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2240249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2244723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2246944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2246945");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:0575");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2024:0575.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5178");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(120, 269, 415, 416, 476, 682, 787, 843);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.8')) audit(AUDIT_OS_NOT, 'Red Hat 8.8', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2023-0458', 'CVE-2023-1073', 'CVE-2023-1075', 'CVE-2023-1079', 'CVE-2023-1838', 'CVE-2023-1855', 'CVE-2023-2162', 'CVE-2023-2163', 'CVE-2023-3141', 'CVE-2023-3567', 'CVE-2023-3611', 'CVE-2023-3772', 'CVE-2023-3812', 'CVE-2023-4132', 'CVE-2023-4622', 'CVE-2023-4623', 'CVE-2023-5178', 'CVE-2023-5717', 'CVE-2023-23455', 'CVE-2023-26545', 'CVE-2023-28328', 'CVE-2023-31436', 'CVE-2023-33203', 'CVE-2023-35823', 'CVE-2023-35824', 'CVE-2023-35825', 'CVE-2023-45871', 'CVE-2023-46813');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2024:0575');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/e4s/rhel8/8.8/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.8/ppc64le/baseos/os',
      'content/e4s/rhel8/8.8/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.8/x86_64/baseos/debug',
      'content/e4s/rhel8/8.8/x86_64/baseos/os',
      'content/e4s/rhel8/8.8/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/aarch64/baseos/debug',
      'content/eus/rhel8/8.8/aarch64/baseos/os',
      'content/eus/rhel8/8.8/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.8/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.8/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.8/ppc64le/baseos/debug',
      'content/eus/rhel8/8.8/ppc64le/baseos/os',
      'content/eus/rhel8/8.8/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.8/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.8/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.8/s390x/baseos/debug',
      'content/eus/rhel8/8.8/s390x/baseos/os',
      'content/eus/rhel8/8.8/s390x/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/s390x/codeready-builder/debug',
      'content/eus/rhel8/8.8/s390x/codeready-builder/os',
      'content/eus/rhel8/8.8/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.8/x86_64/baseos/debug',
      'content/eus/rhel8/8.8/x86_64/baseos/os',
      'content/eus/rhel8/8.8/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.8/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.8/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.8/x86_64/codeready-builder/source/SRPMS',
      'content/tus/rhel8/8.8/x86_64/baseos/debug',
      'content/tus/rhel8/8.8/x86_64/baseos/os',
      'content/tus/rhel8/8.8/x86_64/baseos/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-core-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-cross-headers-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-core-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-extra-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-extra-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-477.43.1.el8_8', 'sp':'8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-477.43.1.el8_8', 'sp':'8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-477.43.1.el8_8', 'sp':'8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.43.1.el8_8', 'sp':'8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.43.1.el8_8', 'sp':'8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-477.43.1.el8_8', 'sp':'8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-4.18.0-477.43.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-core-4.18.0-477.43.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-devel-4.18.0-477.43.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-4.18.0-477.43.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-477.43.1.el8_8', 'sp':'8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-perf-4.18.0-477.43.1.el8_8', 'sp':'8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-core / kernel-cross-headers / etc');
}
