#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-5363.
##

include('compat.inc');

if (description)
{
  script_id(205608);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id(
    "CVE-2021-47606",
    "CVE-2023-52651",
    "CVE-2023-52864",
    "CVE-2024-21823",
    "CVE-2024-26600",
    "CVE-2024-26808",
    "CVE-2024-26828",
    "CVE-2024-26853",
    "CVE-2024-26868",
    "CVE-2024-26897",
    "CVE-2024-27049",
    "CVE-2024-27052",
    "CVE-2024-27065",
    "CVE-2024-27417",
    "CVE-2024-27434",
    "CVE-2024-33621",
    "CVE-2024-35789",
    "CVE-2024-35800",
    "CVE-2024-35823",
    "CVE-2024-35845",
    "CVE-2024-35848",
    "CVE-2024-35852",
    "CVE-2024-35899",
    "CVE-2024-35911",
    "CVE-2024-35937",
    "CVE-2024-35969",
    "CVE-2024-36005",
    "CVE-2024-36017",
    "CVE-2024-36020",
    "CVE-2024-36489",
    "CVE-2024-36903",
    "CVE-2024-36921",
    "CVE-2024-36922",
    "CVE-2024-36929",
    "CVE-2024-36941",
    "CVE-2024-36971",
    "CVE-2024-37353",
    "CVE-2024-37356",
    "CVE-2024-38391",
    "CVE-2024-38558",
    "CVE-2024-38575",
    "CVE-2024-39487",
    "CVE-2024-40928",
    "CVE-2024-40954",
    "CVE-2024-40958",
    "CVE-2024-40961"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");

  script_name(english:"Oracle Linux 9 : kernel (ELSA-2024-5363)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-5363 advisory.

    - net: fix __dst_negative_advice() race (CKI Backport Bot) [RHEL-46798] {CVE-2024-36971}
    - net: annotate data-races around sk->sk_dst_pending_confirm (CKI Backport Bot) [RHEL-46798]
    {CVE-2024-36971}
    - dmaengine: idxd: add a write() method for applications to submit work (Jerry Snitselaar) [RHEL-35840]
    {CVE-2024-21823}
    - dmaengine: idxd: add a new security check to deal with a hardware erratum (Jerry Snitselaar)
    [RHEL-35840] {CVE-2024-21823}
    - VFIO: Add the SPR_DSA and SPR_IAX devices to the denylist (Jerry Snitselaar) [RHEL-35840]
    {CVE-2024-21823}
    - virtio: delete vq in vp_find_vqs_msix() when request_irq() fails (Jon Maloy) [RHEL-44467]
    {CVE-2024-37353}
    - phy: ti: phy-omap-usb2: Fix NULL pointer dereference for SRP (Izabela Bakollari) [RHEL-36271 RHEL-26682]
    {CVE-2024-26600}
    - eeprom: at24: fix memory corruption race condition (CKI Backport Bot) [RHEL-42970] {CVE-2024-35848}
    - eeprom: at24: Probe for DDR3 thermal sensor in the SPD case (CKI Backport Bot) [RHEL-42970]
    {CVE-2024-35848}
    - eeprom: at24: Use dev_err_probe for nvmem register failure (CKI Backport Bot) [RHEL-42970]
    {CVE-2024-35848}
    - eeprom: at24: Add support for 24c1025 EEPROM (CKI Backport Bot) [RHEL-42970] {CVE-2024-35848}
    - eeprom: at24: remove struct at24_client (CKI Backport Bot) [RHEL-42970] {CVE-2024-35848}
    - at24: Support probing while in non-zero ACPI D state (CKI Backport Bot) [RHEL-42970] {CVE-2024-35848}
    - tcp: Fix shift-out-of-bounds in dctcp_update_alpha(). (CKI Backport Bot) [RHEL-44439] {CVE-2024-37356}
    - cxl/region: Fix cxlr_pmem leaks (cki-backport-bot) [RHEL-44486] {CVE-2024-38391}
    - tls: fix missing memory barrier in tls_init (cki-backport-bot) [RHEL-44480] {CVE-2024-36489}
    - igc: avoid returning frame twice in XDP_REDIRECT (Corinna Vinschen) [RHEL-42714 RHEL-33266]
    {CVE-2024-26853}
    - ipvlan: Dont Use skb->sk in ipvlan_process_v{4,6}_outbound (Hangbin Liu) [RHEL-44404 RHEL-44402]
    {CVE-2024-33621}
    - wifi: nl80211: don't free NULL coalescing rule (Jose Ignacio Tornos Martinez) [RHEL-41698 RHEL-39754]
    {CVE-2024-36941}
    - wifi: iwlwifi: dbg-tlv: ensure NUL termination (Jose Ignacio Tornos Martinez) [RHEL-41658 RHEL-37028]
    {CVE-2024-35845}
    - mlxsw: spectrum_acl_tcam: Fix memory leak when canceling rehash work (Ivan Vecera) [RHEL-41556
    RHEL-37018] {CVE-2024-35852}
    - net: openvswitch: fix overwriting ct original tuple for ICMPv6 (cki-backport-bot) [RHEL-44215]
    {CVE-2024-38558}
    - wifi: iwlwifi: read txq->read_ptr under lock (Jose Ignacio Tornos Martinez) [RHEL-41520 RHEL-39799]
    {CVE-2024-36922}
    - wifi: cfg80211: check A-MSDU format more carefully (Jose Ignacio Tornos Martinez) [RHEL-38754
    RHEL-37345] {CVE-2024-35937}
    - ice: fix memory corruption bug with suspend and rebuild (Petr Oros) [RHEL-49858 RHEL-17486]
    {CVE-2024-35911}
    - ipv6: prevent possible NULL deref in fib6_nh_init() (Hangbin Liu) [RHEL-48182 RHEL-45826]
    {CVE-2024-40961}
    - netns: Make get_net_ns() handle zero refcount net (Paolo Abeni) [RHEL-48117 RHEL-46610] {CVE-2024-40958}
    - net: do not leave a dangling sk pointer, when socket creation fails (Paolo Abeni) [RHEL-48072
    RHEL-46610] {CVE-2024-40954}
    - net: ethtool: fix the error condition in ethtool_get_phy_stats_ethtool() (CKI Backport Bot) [RHEL-47902]
    {CVE-2024-40928}
    - net: netlink: af_netlink: Prevent empty skb by adding a check on len. (Ivan Vecera) [RHEL-43619
    RHEL-30344] {CVE-2021-47606}
    - bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set() (CKI Backport Bot) [RHEL-46921]
    {CVE-2024-39487}
    - nfs: fix panic when nfs4_ff_layout_prepare_ds() fails (Benjamin Coddington) [RHEL-42732 RHEL-34875]
    {CVE-2024-26868}
    - efi: fix panic in kdump kernel (Steve Best) [RHEL-42920 RHEL-36998] {CVE-2024-35800}
    - ipv6: fix potential 'struct net' leak in inet6_rtm_getaddr() (Hangbin Liu) [RHEL-41735 RHEL-31050]
    {CVE-2024-27417}
    - netfilter: nf_tables: do not compare internal table flags on updates (Florian Westphal) [RHEL-41682
    RHEL-33985] {CVE-2024-27065}
    - ipv6: Fix potential uninit-value access in __ip6_make_skb() (Antoine Tenart) [RHEL-41466 RHEL-39786]
    {CVE-2024-36903}
    - netfilter: nf_tables: honor table dormant flag from netdev release event path (Florian Westphal)
    [RHEL-40056 RHEL-33985] {CVE-2024-36005}
    - cifs: fix underflow in parse_server_interfaces() (Paulo Alcantara) [RHEL-34636 RHEL-31245]
    {CVE-2024-26828}
    - platform/x86: wmi: Fix opening of char device (David Arcari) [RHEL-42548 RHEL-38260] {CVE-2023-52864}
    - platform/x86: wmi: remove unnecessary initializations (David Arcari) [RHEL-42548 RHEL-38260]
    {CVE-2023-52864}
    - rtnetlink: Correct nested IFLA_VF_VLAN_LIST attribute validation (CKI Backport Bot) [RHEL-43170]
    {CVE-2024-36017}
    - netfilter: nft_chain_filter: handle NETDEV_UNREGISTER for inet/ingress basechain (Florian Westphal)
    [RHEL-40062 RHEL-33985] {CVE-2024-26808}
    - ipv6: fix race condition between ipv6_get_ifaddr and ipv6_del_addr (Jiri Benc) [RHEL-39017 RHEL-32372]
    {CVE-2024-35969}
    - netfilter: nf_tables: flush pending destroy work before exit_net release (Florian Westphal) [RHEL-38765
    RHEL-33985] {CVE-2024-35899}
    - vt: fix unicode buffer corruption when deleting characters (Andrew Halaney) [RHEL-42947 RHEL-24205]
    {CVE-2024-35823}
    - i40e: fix vf may be used uninitialized in this function warning (Kamal Heib) [RHEL-41638 RHEL-39704]
    {CVE-2024-36020}
    - wifi: brcmfmac: pcie: handle randbuf allocation failure (Jose Ignacio Tornos Martinez) [RHEL-44132]
    {CVE-2024-38575}
    - wifi: iwlwifi: mvm: guard against invalid STA ID on removal (Jose Ignacio Tornos Martinez) [RHEL-43208
    RHEL-39803] {CVE-2024-36921}
    - wifi: mac80211: check/clear fast rx for non-4addr sta VLAN changes (Jose Ignacio Tornos Martinez)
    [RHEL-42906 RHEL-36809] {CVE-2024-35789}
    - wifi: iwlwifi: mvm: don't set the MFP flag for the GTK (Jose Ignacio Tornos Martinez) [RHEL-42886
    RHEL-36900] {CVE-2024-27434}
    - wifi: rtl8xxxu: add cancel_work_sync() for c2hcmd_work (Jose Ignacio Tornos Martinez) [RHEL-42860
    RHEL-35142] {CVE-2024-27052}
    - wifi: mt76: mt7925e: fix use-after-free in free_irq() (Jose Ignacio Tornos Martinez) [RHEL-42856
    RHEL-35148] {CVE-2024-27049}
    - wifi: ath9k: delay all of ath9k_wmi_event_tasklet() until init is complete (Jose Ignacio Tornos
    Martinez) [RHEL-42743 RHEL-34187] {CVE-2024-26897}
    - wifi: ath10k: fix NULL pointer dereference in ath10k_wmi_tlv_op_pull_mgmt_tx_compl_ev() (Jose Ignacio
    Tornos Martinez) [RHEL-42383 RHEL-35199] {CVE-2023-52651}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-5363.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40958");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/15");

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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.14.0-427.31.1.el9_4'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-5363');
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
    {'reference':'bpftool-7.3.0-427.31.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-5.14.0-427.31.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-headers-5.14.0-427.31.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-tools-5.14.0-427.31.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-427.31.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-427.31.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'perf-5.14.0-427.31.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-427.31.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-7.3.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.14.0'},
    {'reference':'kernel-abi-stablelists-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-5.14.0'},
    {'reference':'kernel-core-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-5.14.0'},
    {'reference':'kernel-cross-headers-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-debug-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-5.14.0'},
    {'reference':'kernel-debug-core-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-5.14.0'},
    {'reference':'kernel-debug-devel-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-5.14.0'},
    {'reference':'kernel-debug-devel-matched-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-matched-5.14.0'},
    {'reference':'kernel-debug-modules-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-5.14.0'},
    {'reference':'kernel-debug-modules-core-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-core-5.14.0'},
    {'reference':'kernel-debug-modules-extra-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-5.14.0'},
    {'reference':'kernel-debug-uki-virt-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-uki-virt-5.14.0'},
    {'reference':'kernel-devel-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-5.14.0'},
    {'reference':'kernel-devel-matched-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-matched-5.14.0'},
    {'reference':'kernel-headers-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-modules-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-5.14.0'},
    {'reference':'kernel-modules-core-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-core-5.14.0'},
    {'reference':'kernel-modules-extra-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-5.14.0'},
    {'reference':'kernel-tools-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'kernel-uki-virt-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uki-virt-5.14.0'},
    {'reference':'libperf-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-427.31.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
