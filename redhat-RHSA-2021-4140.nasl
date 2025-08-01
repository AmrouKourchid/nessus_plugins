#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:4140. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155172);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2019-14615",
    "CVE-2020-0427",
    "CVE-2020-24502",
    "CVE-2020-24503",
    "CVE-2020-24504",
    "CVE-2020-24586",
    "CVE-2020-24587",
    "CVE-2020-24588",
    "CVE-2020-26139",
    "CVE-2020-26140",
    "CVE-2020-26141",
    "CVE-2020-26143",
    "CVE-2020-26144",
    "CVE-2020-26145",
    "CVE-2020-26146",
    "CVE-2020-26147",
    "CVE-2020-29368",
    "CVE-2020-29660",
    "CVE-2020-36158",
    "CVE-2020-36312",
    "CVE-2020-36386",
    "CVE-2021-0129",
    "CVE-2021-3348",
    "CVE-2021-3489",
    "CVE-2021-3564",
    "CVE-2021-3573",
    "CVE-2021-3600",
    "CVE-2021-3635",
    "CVE-2021-3659",
    "CVE-2021-3679",
    "CVE-2021-3732",
    "CVE-2021-46905",
    "CVE-2022-20166",
    "CVE-2021-20194",
    "CVE-2021-20239",
    "CVE-2021-23133",
    "CVE-2021-28950",
    "CVE-2021-28971",
    "CVE-2021-29155",
    "CVE-2021-29646",
    "CVE-2021-29650",
    "CVE-2021-31440",
    "CVE-2021-31829",
    "CVE-2021-31916",
    "CVE-2021-33033",
    "CVE-2021-33200"
  );
  script_xref(name:"RHSA", value:"2021:4140");
  script_xref(name:"IAVA", value:"2021-A-0223-S");
  script_xref(name:"IAVA", value:"2021-A-0222-S");

  script_name(english:"RHEL 8 : kernel-rt (RHSA-2021:4140)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel-rt.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:4140 advisory.

    The kernel-rt packages provide the Real Time Linux Kernel, which enables fine-tuning for systems with
    extremely high determinism requirements.

    Security Fix(es):
    * kernel: out-of-bounds reads in pinctrl subsystem. (CVE-2020-0427)
    * kernel: Improper input validation in some Intel(R) Ethernet E810 Adapter drivers (CVE-2020-24502)
    * kernel: Insufficient access control in some Intel(R) Ethernet E810 Adapter drivers (CVE-2020-24503)
    * kernel: Uncontrolled resource consumption in some Intel(R) Ethernet E810 Adapter drivers
    (CVE-2020-24504)
    * kernel: Fragmentation cache not cleared on reconnection (CVE-2020-24586)
    * kernel: Reassembling fragments encrypted under different keys (CVE-2020-24587)
    * kernel: wifi frame payload being parsed incorrectly as an L2 frame (CVE-2020-24588)
    * kernel: Forwarding EAPOL from unauthenticated wifi client (CVE-2020-26139)
    * kernel: accepting plaintext data frames in protected networks (CVE-2020-26140)
    * kernel: not verifying TKIP MIC of fragmented frames (CVE-2020-26141)
    * kernel: accepting fragmented plaintext frames in protected networks (CVE-2020-26143)
    * kernel: accepting unencrypted A-MSDU frames that start with RFC1042 header (CVE-2020-26144)
    * kernel: accepting plaintext broadcast fragments as full frames (CVE-2020-26145)
    * kernel: locking inconsistency in tty_io.c and tty_jobctrl.c can lead to a read-after-free
    (CVE-2020-29660)
    * kernel: buffer overflow in mwifiex_cmd_802_11_ad_hoc_start function via a long SSID value
    (CVE-2020-36158)
    * kernel: slab out-of-bounds read in hci_extended_inquiry_result_evt() (CVE-2020-36386)
    * kernel: Improper access control in BlueZ may allow information disclosure vulnerability. (CVE-2021-0129)
    * kernel: Use-after-free in ndb_queue_rq() (CVE-2021-3348)
    * kernel: Linux kernel eBPF RINGBUF map oversized allocation (CVE-2021-3489)
    * kernel: double free in bluetooth subsystem when the HCI device initialization fails (CVE-2021-3564)
    * kernel: use-after-free in function hci_sock_bound_ioctl() (CVE-2021-3573)
    * kernel: eBPF 32-bit source register truncation on div/mod (CVE-2021-3600)
    * kernel: DoS in rb_per_cpu_empty() (CVE-2021-3679)
    * kernel: overlayfs: Mounting overlayfs inside an unprivileged user namespace can reveal files
    (CVE-2021-3732)
    * kernel: heap overflow in __cgroup_bpf_run_filter_getsockopt() (CVE-2021-20194)
    * kernel: Race condition in sctp_destroy_sock list_del (CVE-2021-23133)
    * kernel: fuse: stall on CPU can occur because a retry loop continually finds the same bad inode
    (CVE-2021-28950)
    * kernel: System crash in intel_pmu_drain_pebs_nhm (CVE-2021-28971)
    * kernel: protection for sequences of pointer arithmetic operations against speculatively out-of-bounds
    loads can be bypassed to leak content of kernel memory (CVE-2021-29155)
    * kernel: improper input validation in tipc_nl_retrieve_key function (CVE-2021-29646)
    * kernel: lack a full memory barrier upon the assignment of a new table value in x_tables.h may lead to
    DoS (CVE-2021-29650)
    * kernel: local escalation of privileges in handling of eBPF programs (CVE-2021-31440)
    * kernel: protection of stack pointer against speculative pointer arithmetic can be bypassed to leak
    content of kernel memory (CVE-2021-31829)
    * kernel: out-of-bounds reads and writes due to enforcing incorrect limits for pointer arithmetic
    operations by BPF verifier (CVE-2021-33200)
    * kernel: reassembling encrypted fragments with non-consecutive packet numbers (CVE-2020-26146)
    * kernel: reassembling mixed encrypted/plaintext fragments (CVE-2020-26147)
    * kernel: the copy-on-write implementation can grant unintended write access because of a race condition
    in a THP mapcount check (CVE-2020-29368)
    * kernel: flowtable list del corruption with kernel BUG (CVE-2021-3635)
    * kernel: NULL pointer dereference in llsec_key_alloc()  (CVE-2021-3659)
    * kernel: setsockopt System Call Untrusted Pointer Dereference Information Disclosure (CVE-2021-20239)
    * kernel: out of bounds array access in drivers/md/dm-ioctl.c (CVE-2021-31916)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa-2021_4140.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?314249f5");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/8.5_release_notes/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7240878e");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:4140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1875275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1902412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1903244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1905747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1906522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1912683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1913348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1919893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1921958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1923636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1930376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1930379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1930381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1941762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1941784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1945345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1945388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1946965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1948772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1951595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1957788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1959559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1959642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1959654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1959657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1959663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1960490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1960492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1960496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1960498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1960500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1960502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1960504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1964028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1964139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1965038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1965458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1966578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1969489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1975949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1976946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1981954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1989165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1995249");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel-rt package based on the guidance in RHSA-2021:4140.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3489");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3600");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 120, 125, 200, 212, 252, 287, 290, 307, 345, 346, 362, 400, 415, 416, 476, 662, 682, 772, 787, 829, 835, 863);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

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
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var cve_list = make_list('CVE-2019-14615', 'CVE-2020-0427', 'CVE-2020-24502', 'CVE-2020-24503', 'CVE-2020-24504', 'CVE-2020-24586', 'CVE-2020-24587', 'CVE-2020-24588', 'CVE-2020-26139', 'CVE-2020-26140', 'CVE-2020-26141', 'CVE-2020-26143', 'CVE-2020-26144', 'CVE-2020-26145', 'CVE-2020-26146', 'CVE-2020-26147', 'CVE-2020-29368', 'CVE-2020-29660', 'CVE-2020-36158', 'CVE-2020-36312', 'CVE-2020-36386', 'CVE-2021-0129', 'CVE-2021-3348', 'CVE-2021-3489', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3600', 'CVE-2021-3635', 'CVE-2021-3659', 'CVE-2021-3679', 'CVE-2021-3732', 'CVE-2021-20194', 'CVE-2021-20239', 'CVE-2021-23133', 'CVE-2021-28950', 'CVE-2021-28971', 'CVE-2021-29155', 'CVE-2021-29646', 'CVE-2021-29650', 'CVE-2021-31440', 'CVE-2021-31829', 'CVE-2021-31916', 'CVE-2021-33033', 'CVE-2021-33200', 'CVE-2021-46905', 'CVE-2022-20166');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2021:4140');
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
      {'reference':'kernel-rt-4.18.0-348.rt7.130.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-4.18.0-348.rt7.130.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-4.18.0-348.rt7.130.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-4.18.0-348.rt7.130.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-4.18.0-348.rt7.130.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-4.18.0-348.rt7.130.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-4.18.0-348.rt7.130.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-4.18.0-348.rt7.130.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-4.18.0-348.rt7.130.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-4.18.0-348.rt7.130.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-4.18.0-348.rt7.130.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-4.18.0-348.rt7.130.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
