#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-5928.
##

include('compat.inc');

if (description)
{
  script_id(206319);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id(
    "CVE-2023-52771",
    "CVE-2023-52880",
    "CVE-2024-26581",
    "CVE-2024-26668",
    "CVE-2024-26810",
    "CVE-2024-26855",
    "CVE-2024-26908",
    "CVE-2024-26925",
    "CVE-2024-27016",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27415",
    "CVE-2024-35839",
    "CVE-2024-35896",
    "CVE-2024-35897",
    "CVE-2024-35898",
    "CVE-2024-35962",
    "CVE-2024-36003",
    "CVE-2024-36025",
    "CVE-2024-38538",
    "CVE-2024-38540",
    "CVE-2024-38544",
    "CVE-2024-38579",
    "CVE-2024-38608",
    "CVE-2024-39476",
    "CVE-2024-40905",
    "CVE-2024-40911",
    "CVE-2024-40912",
    "CVE-2024-40914",
    "CVE-2024-40929",
    "CVE-2024-40939",
    "CVE-2024-40941",
    "CVE-2024-40957",
    "CVE-2024-40978",
    "CVE-2024-40983",
    "CVE-2024-41041",
    "CVE-2024-41076",
    "CVE-2024-41090",
    "CVE-2024-41091",
    "CVE-2024-42110",
    "CVE-2024-42152"
  );

  script_name(english:"Oracle Linux 9 : kernel (ELSA-2024-5928)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-5928 advisory.

    - bnxt_re: avoid shift undefined behavior in bnxt_qplib_alloc_init_hwq (Kamal Heib) [RHEL-44287]
    {CVE-2024-38540}
    - netfilter: flowtable: validate pppoe header (Florian Westphal) [RHEL-44430 RHEL-33469] {CVE-2024-27016}
    - crypto: bcm - Fix pointer arithmetic (cki-backport-bot) [RHEL-44116] {CVE-2024-38579}
    - udp: Set SOCK_RCU_FREE earlier in udp_lib_get_port(). (CKI Backport Bot) [RHEL-51035 RHEL-51033]
    {CVE-2024-41041}
    - netfilter: nf_tables: Fix potential data-race in __nft_obj_type_get() (Florian Westphal) [RHEL-42832
    RHEL-33985] {CVE-2024-27019}
    - netfilter: nf_tables: release mutex after nft_gc_seq_end from abort path (Florian Westphal) [RHEL-41802
    RHEL-33985] {CVE-2024-26925}
    - netfilter: nf_tables: discard table flag update with pending basechain deletion (Florian Westphal)
    [RHEL-40231 RHEL-33985] {CVE-2024-35897}
    - netfilter: bridge: replace physindev with physinif in nf_bridge_info (Florian Westphal) [RHEL-42966
    RHEL-37040] {CVE-2024-35839}
    - netfilter: propagate net to nf_bridge_get_physindev (Florian Westphal) [RHEL-42966 RHEL-37040]
    {CVE-2024-35839}
    - netfilter: nfnetlink_log: use proper helper for fetching physinif (Florian Westphal) [RHEL-42966
    RHEL-37040] {CVE-2024-35839}
    - netfilter: nf_queue: remove excess nf_bridge variable (Florian Westphal) [RHEL-42966 RHEL-37040]
    {CVE-2024-35839}
    - netfilter: nft_limit: reject configurations that cause integer overflow (Florian Westphal) [RHEL-40065
    RHEL-33985] {CVE-2024-26668}
    - scsi: qedi: Fix crash while reading debugfs attribute (CKI Backport Bot) [RHEL-48339] {CVE-2024-40978}
    - mm/huge_memory: don't unpoison huge_zero_folio (Aristeu Rozanski) [RHEL-47804] {CVE-2024-40914}
    - tipc: force a dst refcount before doing decryption (Xin Long) [RHEL-48375 RHEL-6118] {CVE-2024-40983}
    - netfilter: nft_set_rbtree: skip end interval element from gc (Florian Westphal) [RHEL-41265]
    {CVE-2024-26581}
    - nvmet: fix a possible leak when destroy a ctrl during qp establishment (CKI Backport Bot) [RHEL-52021
    RHEL-52019 RHEL-52020] {CVE-2024-42152}
    - net: ntb_netdev: Move ntb_netdev_rx_handler() to call netif_rx() from __netif_rx() (CKI Backport Bot)
    [RHEL-51756] {CVE-2024-42110}
    - netfilter: nf_tables: Fix potential data-race in __nft_flowtable_type_get() (Florian Westphal)
    [RHEL-40265 RHEL-33985] {CVE-2024-35898}
    - netfilter: br_netfilter: remove WARN traps (CKI Backport Bot) [RHEL-42882] {CVE-2024-27415}
    - netfilter: br_netfilter: skip conntrack input hook for promisc packets (CKI Backport Bot) [RHEL-42882]
    {CVE-2024-27415}
    - netfilter: bridge: confirm multicast packets before passing them up the stack (CKI Backport Bot)
    [RHEL-42882] {CVE-2024-27415}
    - netfilter: nf_conntrack_bridge: initialize err to 0 (CKI Backport Bot) [RHEL-42882] {CVE-2024-27415}
    - netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get() (Florian Westphal) [RHEL-42842
    RHEL-33985] {CVE-2024-27020}
    - net/mlx5e: Fix netif state handling (Benjamin Poirier) [RHEL-43872 RHEL-43870] {CVE-2024-38608}
    - net/mlx5e: Add wrapping for auxiliary_driver ops and remove unused args (Benjamin Poirier) [RHEL-43872
    RHEL-43870] {CVE-2024-38608}
    - tun: add missing verification for short frame (Patrick Talbert) [RHEL-50202 RHEL-50203] {CVE-2024-41091}
    - tap: add missing verification for short frame (Patrick Talbert) [RHEL-50264 RHEL-50265] {CVE-2024-41090}
    - vfio/pci: Lock external INTx masking ops (Alex Williamson) [RHEL-43421 RHEL-30023] {CVE-2024-26810}
    - net: bridge: xmit: make sure we have at least eth header len bytes (cki-backport-bot) [RHEL-44299]
    {CVE-2024-38538}
    - RDMA/rxe: Fix seg fault in rxe_comp_queue_pkt (cki-backport-bot) [RHEL-44250] {CVE-2024-38544}
    - NFSv4: Fix memory leak in nfs4_set_security_label (CKI Backport Bot) [RHEL-52082] {CVE-2024-41076}
    - md/raid5: fix deadlock that raid5d() wait for itself to clear MD_SB_CHANGE_PENDING (Nigel Croxon)
    [RHEL-46421 RHEL-35393] {CVE-2024-39476}
    - cxl/port: Fix delete_endpoint() vs parent unregistration race (John W. Linville) [RHEL-39290 RHEL-23582]
    {CVE-2023-52771}
    - net: ice: Fix potential NULL pointer dereference in ice_bridge_setlink() (Petr Oros) [RHEL-49862
    RHEL-17486] {CVE-2024-26855}
    - ice: fix LAG and VF lock dependency in ice_reset_vf() (Petr Oros) [RHEL-49820 RHEL-17486]
    {CVE-2024-36003}
    - net: wwan: iosm: Fix tainted pointer delete is case of region creation fail (Jose Ignacio Tornos
    Martinez) [RHEL-47992 RHEL-9429] {CVE-2024-40939}
    - wifi: cfg80211: Lock wiphy in cfg80211_get_station (CKI Backport Bot) [RHEL-47770] {CVE-2024-40911}
    - wifi: mac80211: Fix deadlock in ieee80211_sta_ps_deliver_wakeup() (CKI Backport Bot) [RHEL-47788]
    {CVE-2024-40912}
    - wifi: iwlwifi: mvm: check n_ssids before accessing the ssids (CKI Backport Bot) [RHEL-47920]
    {CVE-2024-40929}
    - wifi: iwlwifi: mvm: don't read past the mfuart notifcation (CKI Backport Bot) [RHEL-48028]
    {CVE-2024-40941}
    - seg6: fix parameter passing when calling NF_HOOK() in End.DX4 and End.DX6 behaviors (Hangbin Liu)
    [RHEL-48098 RHEL-45826] {CVE-2024-40957}
    - ipv6: fix possible race in __fib6_drop_pcpu_from() (Hangbin Liu) [RHEL-47572 RHEL-45826]
    {CVE-2024-40905}
    - tty: n_gsm: require CAP_NET_ADMIN to attach N_GSM0710 ldisc (Andrew Halaney) [RHEL-42566 RHEL-24205]
    {CVE-2023-52880}
    - netfilter: complete validation of user input (Phil Sutter) [RHEL-47384 RHEL-37212] {CVE-2024-35962}
    - netfilter: validate user input for expected length (Phil Sutter) [RHEL-41668 RHEL-37212]
    {CVE-2024-35896}
    - scsi: qla2xxx: Fix off by one in qla_edif_app_getstats() (Ewan D. Milne) [RHEL-40051 RHEL-39719]
    {CVE-2024-36025}
    - x86/xen: Add some null pointer checking to smp.c (Vitaly Kuznetsov) [RHEL-37615 RHEL-33260]
    {CVE-2024-26908}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-5928.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26581");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9:4:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rtla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.14.0-427.33.1.el9_4'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-5928');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.14';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-7.3.0-427.33.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-5.14.0-427.33.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-headers-5.14.0-427.33.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-tools-5.14.0-427.33.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-427.33.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-427.33.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'perf-5.14.0-427.33.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-427.33.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-7.3.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.14.0'},
    {'reference':'kernel-abi-stablelists-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-5.14.0'},
    {'reference':'kernel-core-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-5.14.0'},
    {'reference':'kernel-cross-headers-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-debug-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-5.14.0'},
    {'reference':'kernel-debug-core-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-5.14.0'},
    {'reference':'kernel-debug-devel-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-5.14.0'},
    {'reference':'kernel-debug-devel-matched-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-matched-5.14.0'},
    {'reference':'kernel-debug-modules-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-5.14.0'},
    {'reference':'kernel-debug-modules-core-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-core-5.14.0'},
    {'reference':'kernel-debug-modules-extra-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-5.14.0'},
    {'reference':'kernel-debug-uki-virt-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-uki-virt-5.14.0'},
    {'reference':'kernel-devel-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-5.14.0'},
    {'reference':'kernel-devel-matched-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-matched-5.14.0'},
    {'reference':'kernel-headers-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-modules-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-5.14.0'},
    {'reference':'kernel-modules-core-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-core-5.14.0'},
    {'reference':'kernel-modules-extra-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-5.14.0'},
    {'reference':'kernel-tools-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'kernel-uki-virt-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uki-virt-5.14.0'},
    {'reference':'libperf-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-427.33.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
