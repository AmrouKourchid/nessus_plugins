#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-4211.
##

include('compat.inc');

if (description)
{
  script_id(201306);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/31");

  script_cve_id(
    "CVE-2020-26555",
    "CVE-2021-46909",
    "CVE-2021-46972",
    "CVE-2021-47069",
    "CVE-2021-47073",
    "CVE-2021-47236",
    "CVE-2021-47310",
    "CVE-2021-47311",
    "CVE-2021-47353",
    "CVE-2021-47356",
    "CVE-2021-47456",
    "CVE-2021-47495",
    "CVE-2023-5090",
    "CVE-2023-52464",
    "CVE-2023-52560",
    "CVE-2023-52615",
    "CVE-2023-52626",
    "CVE-2023-52667",
    "CVE-2023-52669",
    "CVE-2023-52675",
    "CVE-2023-52686",
    "CVE-2023-52700",
    "CVE-2023-52703",
    "CVE-2023-52781",
    "CVE-2023-52813",
    "CVE-2023-52835",
    "CVE-2023-52877",
    "CVE-2023-52878",
    "CVE-2023-52881",
    "CVE-2024-26583",
    "CVE-2024-26584",
    "CVE-2024-26585",
    "CVE-2024-26656",
    "CVE-2024-26675",
    "CVE-2024-26735",
    "CVE-2024-26759",
    "CVE-2024-26801",
    "CVE-2024-26804",
    "CVE-2024-26826",
    "CVE-2024-26859",
    "CVE-2024-26906",
    "CVE-2024-26907",
    "CVE-2024-26974",
    "CVE-2024-26982",
    "CVE-2024-27397",
    "CVE-2024-27410",
    "CVE-2024-35789",
    "CVE-2024-35835",
    "CVE-2024-35838",
    "CVE-2024-35845",
    "CVE-2024-35852",
    "CVE-2024-35853",
    "CVE-2024-35854",
    "CVE-2024-35855",
    "CVE-2024-35888",
    "CVE-2024-35890",
    "CVE-2024-35958",
    "CVE-2024-35959",
    "CVE-2024-35960",
    "CVE-2024-36004",
    "CVE-2024-36007"
  );

  script_name(english:"Oracle Linux 8 : kernel (ELSA-2024-4211)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-4211 advisory.

    - udf: Fix NULL pointer dereference in udf_symlink function (Pavel Reichl) [RHEL-37769] {CVE-2021-47353}
    - net: ti: fix UAF in tlan_remove_one (Jose Ignacio Tornos Martinez) [RHEL-38940] {CVE-2021-47310}
    - ARM: footbridge: fix PCI interrupt mapping (Myron Stowe) [RHEL-26971] {CVE-2021-46909}
    - i40e: Do not use WQ_MEM_RECLAIM flag for workqueue (Kamal Heib) [RHEL-37454] {CVE-2024-36004}
    - net/mlx5e: Fix mlx5e_priv_init() cleanup flow (Kamal Heib) [RHEL-37424] {CVE-2024-35959}
    - net/mlx5: Properly link new fs rules into the tree (Kamal Heib) [RHEL-37420] {CVE-2024-35960}
    - net/mlx5e: fix a potential double-free in fs_any_create_groups (Kamal Heib) [RHEL-37091]
    {CVE-2023-52667}
    - net: ena: Fix incorrect descriptor free behavior (Kamal Heib) [RHEL-37428] {CVE-2024-35958}
    - mISDN: hfcpci: Fix use-after-free bug in hfcpci_softirq (Jose Ignacio Tornos Martinez) [RHEL-37763]
    {CVE-2021-47356}
    - mISDN: fix possible use-after-free in HFC_cleanup() (Jose Ignacio Tornos Martinez) [RHEL-37763]
    {CVE-2021-47356}
    - crypto: qat - Fix ADF_DEV_RESET_SYNC memory leak (Vladis Dronov) [RHEL-35106] {CVE-2024-26974}
    - crypto: qat - resolve race condition during AER recovery (Vladis Dronov) [RHEL-35106] {CVE-2024-26974}
    - mptcp: fix data re-injection from stale subflow (Davide Caratti) [RHEL-33133] {CVE-2024-26826}
    - ipv6: sr: fix possible use-after-free and null-ptr-deref (Hangbin Liu) [RHEL-31730] {CVE-2024-26735}
    - net/bnx2x: Prevent access to a freed page in page_pool (Michal Schmidt) [RHEL-14195 RHEL-33243]
    {CVE-2024-26859}
    - x86: KVM: SVM: always update the x2avic msr interception (Maxim Levitsky) [RHEL-15495] {CVE-2023-5090}
    - EDAC/thunderx: Fix possible out-of-bounds string access (Aristeu Rozanski) [RHEL-26573] {CVE-2023-52464}
    - net: qcom/emac: fix UAF in emac_remove (Ken Cox) [RHEL-37834] {CVE-2021-47311}
    - perf/core: Bail out early if the request AUX area is out of bound (Michael Petlan) [RHEL-38268]
    {CVE-2023-52835}
    - crypto: pcrypt - Fix hungtask for PADATA_RESET (Herbert Xu) [RHEL-38171] {CVE-2023-52813}
    - drm/amdgpu: fix use-after-free bug (Jocelyn Falempe) [RHEL-31240] {CVE-2024-26656}
    - mlxsw: spectrum_acl_tcam: Fix possible use-after-free during rehash (Ivan Vecera) [RHEL-37008]
    {CVE-2024-35854}
    - mlxsw: spectrum_acl_tcam: Fix possible use-after-free during activity update (Ivan Vecera) [RHEL-37004]
    {CVE-2024-35855}
    - mlxsw: spectrum_acl_tcam: Fix memory leak during rehash (Ivan Vecera) [RHEL-37012] {CVE-2024-35853}
    - mlxsw: spectrum_acl_tcam: Fix memory leak when canceling rehash work (Ivan Vecera) [RHEL-37016]
    {CVE-2024-35852}
    - mlxsw: spectrum_acl_tcam: Fix warning during rehash (Ivan Vecera) [RHEL-37480] {CVE-2024-36007}
    - can: peak_pci: peak_pci_remove(): fix UAF (Jose Ignacio Tornos Martinez) [RHEL-38419] {CVE-2021-47456}
    - usbnet: fix error return code in usbnet_probe() (Jose Ignacio Tornos Martinez) [RHEL-38440]
    {CVE-2021-47495}
    - usbnet: sanity check for maxpacket (Jose Ignacio Tornos Martinez) [RHEL-38440] {CVE-2021-47495}
    - net/mlx5e: fix a double-free in arfs_create_groups (Kamal Heib) [RHEL-36920] {CVE-2024-35835}
    - can: dev: can_put_echo_skb(): don't crash kernel if can_priv::echo_skb is accessed out of bounds (Jose
    Ignacio Tornos Martinez) [RHEL-38220] {CVE-2023-52878}
    - net: cdc_eem: fix tx fixup skb leak (Jose Ignacio Tornos Martinez) [RHEL-38080] {CVE-2021-47236}
    - net/usb: kalmia: Don't pass act_len in usb_bulk_msg error path (Jose Ignacio Tornos Martinez)
    [RHEL-38113] {CVE-2023-52703}
    - usb: typec: tcpm: Fix NULL pointer dereference in tcpm_pd_svdm() (Desnes Nunes) [RHEL-38248]
    {CVE-2023-52877}
    - usb: config: fix iteration issue in 'usb_get_bos_descriptor()' (Desnes Nunes) [RHEL-38240]
    {CVE-2023-52781}
    - gro: fix ownership transfer (Xin Long) [RHEL-37226] {CVE-2024-35890}
    - tipc: fix kernel warning when sending SYN message (Xin Long) [RHEL-38109] {CVE-2023-52700}
    - erspan: make sure erspan_base_hdr is present in skb->head (Xin Long) [RHEL-37230] {CVE-2024-35888}
    - netfilter: nf_tables: use timestamp to check for set element timeout (Phil Sutter) [RHEL-38023]
    {CVE-2024-27397}
    - crypto: s390/aes - Fix buffer overread in CTR mode (Herbert Xu) [RHEL-37089] {CVE-2023-52669}
    - wifi: iwlwifi: dbg-tlv: ensure NUL termination (Jose Ignacio Tornos Martinez) [RHEL-37026]
    {CVE-2024-35845}
    - wifi: mac80211: fix potential sta-link leak (Jose Ignacio Tornos Martinez) [RHEL-36916] {CVE-2024-35838}
    - wifi: nl80211: reject iftype change with mesh ID change (Jose Ignacio Tornos Martinez) [RHEL-36884]
    {CVE-2024-27410}
    - wifi: mac80211: check/clear fast rx for non-4addr sta VLAN changes (Jose Ignacio Tornos Martinez)
    [RHEL-36807] {CVE-2024-35789}
    - Bluetooth: Avoid potential use-after-free in hci_error_reset (David Marlin) [RHEL-31826]
    {CVE-2024-26801}
    - tls: disable async encrypt/decrypt (Sabrina Dubroca) [RHEL-26362 RHEL-26409 RHEL-26420] {CVE-2024-26584
    CVE-2024-26583 CVE-2024-26585}
    - Squashfs: check the inode number is not the invalid value of zero (Phillip Lougher) [RHEL-35096]
    {CVE-2024-26982}
    - ipc/mqueue, msg, sem: avoid relying on a stack reference past its expiry (Rafael Aquini) [RHEL-27782]
    {CVE-2021-47069}
    - ipc/msg.c: update and document memory barriers (Rafael Aquini) [RHEL-27782] {CVE-2021-47069}
    - ipc/sem.c: document and update memory barriers (Rafael Aquini) [RHEL-27782] {CVE-2021-47069}
    - ipc/mqueue.c: update/document memory barriers (Rafael Aquini) [RHEL-27782] {CVE-2021-47069}
    - ipc/mqueue.c: remove duplicated code (Rafael Aquini) [RHEL-27782] {CVE-2021-47069}
    - net/mlx5e: Fix operation precedence bug in port timestamping napi_poll context (Kamal Heib) [RHEL-30582]
    {CVE-2023-52626}
    - hwrng: core - Fix page fault dead lock on mmap-ed hwrng (Prarit Bhargava) [RHEL-29485] {CVE-2023-52615}
    - powerpc/powernv: Add a null pointer check in opal_event_init() (Mamatha Inamdar) [RHEL-37058]
    {CVE-2023-52686}
    - net: ip_tunnel: prevent perpetual headroom growth (Felix Maurer) [RHEL-31814] {CVE-2024-26804}
    - RDMA/mlx5: Fix fortify source warning while accessing Eth segment (Kamal Heib) [RHEL-33162]
    {CVE-2024-26907}
    - ovl: fix leaked dentry (Miklos Szeredi) [RHEL-27306] {CVE-2021-46972}
    - x86/mm: Disallow vsyscall page read for copy_from_kernel_nofault() (Rafael Aquini) [RHEL-33166]
    {CVE-2024-26906}
    - x86/mm: Move is_vsyscall_vaddr() into asm/vsyscall.h (Rafael Aquini) [RHEL-33166] {CVE-2024-26906}
    - x86/mm/vsyscall: Consider vsyscall page part of user address space (Rafael Aquini) [RHEL-33166]
    {CVE-2024-26906}
    - x86/mm: Add vsyscall address helper (Rafael Aquini) [RHEL-33166] {CVE-2024-26906}
    - mm/swap: fix race when skipping swapcache (Rafael Aquini) [RHEL-31644] {CVE-2024-26759}
    - swap: fix do_swap_page() race with swapoff (Rafael Aquini) [RHEL-31644] {CVE-2024-26759}
    - mm/swapfile: use percpu_ref to serialize against concurrent swapoff (Rafael Aquini) [RHEL-31644]
    {CVE-2024-26759}
    - mm/damon/vaddr-test: fix memory leak in damon_do_test_apply_three_regions() (Rafael Aquini) [RHEL-29294]
    {CVE-2023-52560}
    - platform/x86: dell-smbios-wmi: Fix oops on rmmod dell_smbios (Prarit Bhargava) [RHEL-27790]
    {CVE-2021-47073}
    - Bluetooth: avoid memcmp() out of bounds warning (David Marlin) [RHEL-3017] {CVE-2020-26555}
    - Bluetooth: hci_event: Fix coding style (David Marlin) [RHEL-3017] {CVE-2020-26555}
    - Bluetooth: hci_event: Fix using memcmp when comparing keys (David Marlin) [RHEL-3017] {CVE-2020-26555}
    - Bluetooth: Reject connection with the device which has same BD_ADDR (David Marlin) [RHEL-3017]
    {CVE-2020-26555}
    - Bluetooth: hci_event: Ignore NULL link key (David Marlin) [RHEL-3017] {CVE-2020-26555}
    - ppp_async: limit MRU to 64K (Guillaume Nault) [RHEL-31353] {CVE-2024-26675}
    - powerpc/imc-pmu: Add a null pointer check in update_events_in_group() (Mamatha Inamdar) [RHEL-37078]
    {CVE-2023-52675}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-4211.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26555");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-35855");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:exadata_dbserver:23.1.16.0.0::ol8");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:exadata_dbserver:23.1.17.0.0::ol8");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:exadata_dbserver:24.1.2.0.0::ol8");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:exadata_dbserver:24.1.3.0.0::ol8");
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
  var fixed_uptrack_levels = ['4.18.0-553.8.1.el8_10'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-4211');
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
    {'reference':'bpftool-4.18.0-553.8.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-553.8.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-4.18.0'},
    {'reference':'kernel-headers-4.18.0-553.8.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-4.18.0'},
    {'reference':'kernel-tools-4.18.0-553.8.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-4.18.0'},
    {'reference':'kernel-tools-libs-4.18.0-553.8.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-4.18.0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.8.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-4.18.0'},
    {'reference':'perf-4.18.0-553.8.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-553.8.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-4.18.0'},
    {'reference':'kernel-abi-stablelists-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-4.18.0'},
    {'reference':'kernel-core-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-4.18.0'},
    {'reference':'kernel-cross-headers-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-4.18.0'},
    {'reference':'kernel-debug-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-4.18.0'},
    {'reference':'kernel-debug-core-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-4.18.0'},
    {'reference':'kernel-debug-devel-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-4.18.0'},
    {'reference':'kernel-debug-modules-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-4.18.0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-4.18.0'},
    {'reference':'kernel-devel-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-4.18.0'},
    {'reference':'kernel-headers-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-4.18.0'},
    {'reference':'kernel-modules-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-4.18.0'},
    {'reference':'kernel-modules-extra-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-4.18.0'},
    {'reference':'kernel-tools-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-4.18.0'},
    {'reference':'kernel-tools-libs-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-4.18.0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-4.18.0'},
    {'reference':'perf-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-553.8.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
