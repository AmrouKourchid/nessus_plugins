#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-8856.
##

include('compat.inc');

if (description)
{
  script_id(210399);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id(
    "CVE-2022-48773",
    "CVE-2022-48936",
    "CVE-2023-52492",
    "CVE-2024-24857",
    "CVE-2024-26851",
    "CVE-2024-26924",
    "CVE-2024-26976",
    "CVE-2024-27017",
    "CVE-2024-27062",
    "CVE-2024-35839",
    "CVE-2024-35898",
    "CVE-2024-35939",
    "CVE-2024-38540",
    "CVE-2024-38541",
    "CVE-2024-38586",
    "CVE-2024-38608",
    "CVE-2024-39503",
    "CVE-2024-40924",
    "CVE-2024-40961",
    "CVE-2024-40983",
    "CVE-2024-40984",
    "CVE-2024-41009",
    "CVE-2024-41042",
    "CVE-2024-41066",
    "CVE-2024-41092",
    "CVE-2024-41093",
    "CVE-2024-42070",
    "CVE-2024-42079",
    "CVE-2024-42244",
    "CVE-2024-42284",
    "CVE-2024-42292",
    "CVE-2024-42301",
    "CVE-2024-43854",
    "CVE-2024-43880",
    "CVE-2024-43889",
    "CVE-2024-43892",
    "CVE-2024-44935",
    "CVE-2024-44989",
    "CVE-2024-44990",
    "CVE-2024-45018",
    "CVE-2024-46826",
    "CVE-2024-47668"
  );
  script_xref(name:"IAVA", value:"2024-A-0487");

  script_name(english:"Oracle Linux 8 : kernel (ELSA-2024-8856)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-8856 advisory.

    - lib/generic-radix-tree.c: Fix rare race in __genradix_ptr_alloc() (Waiman Long) [RHEL-62139]
    {CVE-2024-47668}
    - bonding: fix xfrm real_dev null pointer dereference (Hangbin Liu) [RHEL-57239] {CVE-2024-44989}
    - bonding: fix null pointer deref in bond_ipsec_offload_ok (Hangbin Liu) [RHEL-57233] {CVE-2024-44990}
    - bpf: Fix overrunning reservations in ringbuf (Viktor Malik) [RHEL-49414] {CVE-2024-41009}
    - xprtrdma: fix pointer derefs in error cases of rpcrdma_ep_create (CKI Backport Bot) [RHEL-49309]
    {CVE-2022-48773}
    - ELF: fix kernel.randomize_va_space double read (Rafael Aquini) [RHEL-60669] {CVE-2024-46826}
    - nouveau: lock the client object tree. (Abdiel Janulgue) [RHEL-35118] {CVE-2024-27062}
    - dmaengine: fix NULL pointer in channel unregistration function (Jerry Snitselaar) [RHEL-28867]
    {CVE-2023-52492}
    - dma-direct: Leak pages on dma_set_decrypted() failure (Jerry Snitselaar) [RHEL-37335] {CVE-2024-35939}
    - drm/i915/gt: Fix potential UAF by revoke of fence registers (Mika Penttila) [RHEL-53633]
    {CVE-2024-41092}
    - kobject_uevent: Fix OOB access within zap_modalias_env() (Rafael Aquini) [RHEL-55000] {CVE-2024-42292}
    - gfs2: Fix NULL pointer dereference in gfs2_log_flush (Andrew Price) [RHEL-51553] {CVE-2024-42079}
    - of: module: add buffer overflow check in of_modalias() (Charles Mirabile) [RHEL-44267] {CVE-2024-38541}
    - padata: Fix possible divide-by-0 panic in padata_mt_helper() (Steve Best) [RHEL-56162] {CVE-2024-43889}
    - sctp: Fix null-ptr-deref in reuseport_add_sock(). (Xin Long) [RHEL-56234] {CVE-2024-44935}
    - net/mlx5e: Fix netif state handling (Michal Schmidt) [RHEL-43864] {CVE-2024-38608}
    - net/mlx5e: Add wrapping for auxiliary_driver ops and remove unused args (Michal Schmidt) [RHEL-43864]
    {CVE-2024-38608}
    - r8169: Fix possible ring buffer corruption on fragmented Tx packets. (cki-backport-bot) [RHEL-44031]
    {CVE-2024-38586}
    - netfilter: flowtable: initialise extack before use (Florian Westphal) [RHEL-58542] {CVE-2024-45018}
    - memcg: protect concurrent access to mem_cgroup_idr (Rafael Aquini) [RHEL-56252] {CVE-2024-43892}
    - memcontrol: ensure memcg acquired by id is properly set up (Rafael Aquini) [RHEL-56252] {CVE-2024-43892}
    - mm: memcontrol: fix cannot alloc the maximum memcg ID (Rafael Aquini) [RHEL-56252] {CVE-2024-43892}
    - mm/memcg: minor cleanup for MEM_CGROUP_ID_MAX (Rafael Aquini) [RHEL-56252] {CVE-2024-43892}
    - netfilter: nft_set_pipapo: do not free live element (Phil Sutter) [RHEL-34221] {CVE-2024-26924}
    - netfilter: nf_tables: missing iterator type in lookup walk (Phil Sutter) [RHEL-35033] {CVE-2024-27017}
    - netfilter: nft_set_pipapo: walk over current view on netlink dump (Phil Sutter) [RHEL-35033]
    {CVE-2024-27017}
    - netfilter: nftables: add helper function to flush set elements (Phil Sutter) [RHEL-35033]
    {CVE-2024-27017}
    - netfilter: nf_tables: prefer nft_chain_validate (Phil Sutter) [RHEL-51040] {CVE-2024-41042}
    - netfilter: nf_tables: fully validate NFT_DATA_VALUE on store to data registers (Phil Sutter)
    [RHEL-51516] {CVE-2024-42070}
    - netfilter: nf_tables: Fix potential data-race in __nft_flowtable_type_get() (Phil Sutter) [RHEL-43003]
    {CVE-2024-35898}
    - netfilter: ipset: Fix suspicious rcu_dereference_protected() (Phil Sutter) [RHEL-47606] {CVE-2024-39503}
    - netfilter: ipset: Fix race between namespace cleanup and gc in the list:set type (Phil Sutter)
    [RHEL-47606] {CVE-2024-39503}
    - netfilter: ipset: Add list flush to cancel_gc (Phil Sutter) [RHEL-47606] {CVE-2024-39503}
    - netfilter: nf_conntrack_h323: Add protection for bmp length out of range (Phil Sutter) [RHEL-42680]
    {CVE-2024-26851}
    - netfilter: bridge: replace physindev with physinif in nf_bridge_info (Florian Westphal) [RHEL-37038
    RHEL-37039] {CVE-2024-35839}
    - netfilter: propagate net to nf_bridge_get_physindev (Florian Westphal) [RHEL-37038 RHEL-37039]
    {CVE-2024-35839}
    - netfilter: nfnetlink_log: use proper helper for fetching physinif (Florian Westphal) [RHEL-37038
    RHEL-37039] {CVE-2024-35839}
    - netfilter: nf_queue: remove excess nf_bridge variable (Florian Westphal) [RHEL-37038 RHEL-37039]
    {CVE-2024-35839}
    - dev/parport: fix the array out-of-bounds risk (Steve Best) [RHEL-54985] {CVE-2024-42301}
    - KVM: Always flush async #PF workqueue when vCPU is being destroyed (Sean Christopherson) [RHEL-35100]
    {CVE-2024-26976}
    - bnxt_re: avoid shift undefined behavior in bnxt_qplib_alloc_init_hwq (Kamal Heib) [RHEL-44279]
    {CVE-2024-38540}
    - tipc: Return non-zero value from tipc_udp_addr2str() on error (Xin Long) [RHEL-55069] {CVE-2024-42284}
    - Bluetooth: Fix TOCTOU in HCI debugfs implementation (CKI Backport Bot) [RHEL-26831] {CVE-2024-24857}
    - drm/i915/dpt: Make DPT object unshrinkable (CKI Backport Bot) [RHEL-47856] {CVE-2024-40924}
    - tipc: force a dst refcount before doing decryption (Xin Long) [RHEL-48363] {CVE-2024-40983}
    - block: initialize integrity buffer to zero before writing it to media (Ming Lei) [RHEL-54763]
    {CVE-2024-43854}
    - gso: do not skip outer ip header in case of ipip and net_failover (CKI Backport Bot) [RHEL-55790]
    {CVE-2022-48936}
    - drm/amdgpu: avoid using null object of framebuffer (CKI Backport Bot) [RHEL-51405] {CVE-2024-41093}
    - ipv6: prevent possible NULL deref in fib6_nh_init() (Guillaume Nault) [RHEL-48170] {CVE-2024-40961}
    - mlxsw: spectrum_acl_erp: Fix object nesting warning (CKI Backport Bot) [RHEL-55568] {CVE-2024-43880}
    - ibmvnic: Add tx check to prevent skb leak (CKI Backport Bot) [RHEL-51249] {CVE-2024-41066}
    - ibmvnic: rename local variable index to bufidx (CKI Backport Bot) [RHEL-51249] {CVE-2024-41066}
    - netfilter: bridge: replace physindev with physinif in nf_bridge_info (Florian Westphal) [RHEL-37038
    RHEL-37039] {CVE-2024-35839}
    - netfilter: propagate net to nf_bridge_get_physindev (Florian Westphal) [RHEL-37038 RHEL-37039]
    {CVE-2024-35839}
    - netfilter: nfnetlink_log: use proper helper for fetching physinif (Florian Westphal) [RHEL-37038
    RHEL-37039] {CVE-2024-35839}
    - netfilter: nf_queue: remove excess nf_bridge variable (Florian Westphal) [RHEL-37038 RHEL-37039]
    {CVE-2024-35839}
    - USB: serial: mos7840: fix crash on resume (CKI Backport Bot) [RHEL-53680] {CVE-2024-42244}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-8856.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42301");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8:10:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.18.0-553.27.1.el8_10'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-8856');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.18';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-4.18.0-553.27.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-553.27.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-4.18.0'},
    {'reference':'kernel-headers-4.18.0-553.27.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-4.18.0'},
    {'reference':'kernel-tools-4.18.0-553.27.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-4.18.0'},
    {'reference':'kernel-tools-libs-4.18.0-553.27.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-4.18.0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.27.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-4.18.0'},
    {'reference':'perf-4.18.0-553.27.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-553.27.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-4.18.0'},
    {'reference':'kernel-abi-stablelists-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-4.18.0'},
    {'reference':'kernel-core-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-4.18.0'},
    {'reference':'kernel-cross-headers-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-4.18.0'},
    {'reference':'kernel-debug-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-4.18.0'},
    {'reference':'kernel-debug-core-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-4.18.0'},
    {'reference':'kernel-debug-devel-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-4.18.0'},
    {'reference':'kernel-debug-modules-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-4.18.0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-4.18.0'},
    {'reference':'kernel-devel-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-4.18.0'},
    {'reference':'kernel-headers-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-4.18.0'},
    {'reference':'kernel-modules-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-4.18.0'},
    {'reference':'kernel-modules-extra-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-4.18.0'},
    {'reference':'kernel-tools-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-4.18.0'},
    {'reference':'kernel-tools-libs-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-4.18.0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-4.18.0'},
    {'reference':'perf-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-553.27.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / etc');
}
