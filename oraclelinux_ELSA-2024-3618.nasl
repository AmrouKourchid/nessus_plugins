#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-3618.
##

include('compat.inc');

if (description)
{
  script_id(200159);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id(
    "CVE-2019-25162",
    "CVE-2020-36777",
    "CVE-2021-46934",
    "CVE-2021-47013",
    "CVE-2021-47055",
    "CVE-2021-47118",
    "CVE-2021-47153",
    "CVE-2021-47171",
    "CVE-2021-47185",
    "CVE-2022-48627",
    "CVE-2022-48669",
    "CVE-2023-6240",
    "CVE-2023-52439",
    "CVE-2023-52445",
    "CVE-2023-52477",
    "CVE-2023-52513",
    "CVE-2023-52520",
    "CVE-2023-52528",
    "CVE-2023-52565",
    "CVE-2023-52578",
    "CVE-2023-52594",
    "CVE-2023-52595",
    "CVE-2023-52598",
    "CVE-2023-52606",
    "CVE-2023-52607",
    "CVE-2023-52610",
    "CVE-2024-0340",
    "CVE-2024-23307",
    "CVE-2024-25744",
    "CVE-2024-26593",
    "CVE-2024-26603",
    "CVE-2024-26610",
    "CVE-2024-26615",
    "CVE-2024-26642",
    "CVE-2024-26643",
    "CVE-2024-26659",
    "CVE-2024-26664",
    "CVE-2024-26693",
    "CVE-2024-26694",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26779",
    "CVE-2024-26872",
    "CVE-2024-26892",
    "CVE-2024-26897",
    "CVE-2024-26901",
    "CVE-2024-26919",
    "CVE-2024-26933",
    "CVE-2024-26934",
    "CVE-2024-26964",
    "CVE-2024-26973",
    "CVE-2024-26993",
    "CVE-2024-27014",
    "CVE-2024-27048",
    "CVE-2024-27052",
    "CVE-2024-27056",
    "CVE-2024-27059"
  );

  script_name(english:"Oracle Linux 8 : kernel (ELSA-2024-3618)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-3618 advisory.

    - uio: Fix use-after-free in uio_open (Ricardo Robaina) [RHEL-26232] {CVE-2023-52439}
    - net:emac/emac-mac: Fix a use after free in emac_mac_tx_buf_send (Ken Cox) [RHEL-27316] {CVE-2021-47013}
    - wifi: brcm80211: handle pmk_op allocation failure (Jose Ignacio Tornos Martinez) [RHEL-35150]
    {CVE-2024-27048}
    - wifi: rtl8xxxu: add cancel_work_sync() for c2hcmd_work (Jose Ignacio Tornos Martinez) [RHEL-35140]
    {CVE-2024-27052}
    - wifi: iwlwifi: mvm: ensure offloading TID queue exists (Jose Ignacio Tornos Martinez) [RHEL-35130]
    {CVE-2024-27056}
    - wifi: mt76: mt7921e: fix use-after-free in free_irq() (Jose Ignacio Tornos Martinez) [RHEL-34866]
    {CVE-2024-26892}
    - wifi: ath9k: delay all of ath9k_wmi_event_tasklet() until init is complete (Jose Ignacio Tornos
    Martinez) [RHEL-34189] {CVE-2024-26897}
    - wifi: iwlwifi: mvm: fix a crash when we run out of stations (Jose Ignacio Tornos Martinez) [RHEL-31547]
    {CVE-2024-26693}
    - wifi: iwlwifi: fix double-free bug (Jose Ignacio Tornos Martinez) [RHEL-31543] {CVE-2024-26694}
    - wifi: ath9k: Fix potential array-index-out-of-bounds read in ath9k_htc_txstatus() (Jose Ignacio Tornos
    Martinez) [RHEL-29089] {CVE-2023-52594}
    - wifi: rt2x00: restart beacon queue when hardware reset (Jose Ignacio Tornos Martinez) [RHEL-29093]
    {CVE-2023-52595}
    - wifi: iwlwifi: fix a memory corruption (Jose Ignacio Tornos Martinez) [RHEL-28903] {CVE-2024-26610}
    - net/mlx5e: Prevent deadlock while disabling aRFS (Kamal Heib) [RHEL-35041] {CVE-2024-27014}
    - net: usb: fix possible use-after-free in smsc75xx_bind (Jose Ignacio Tornos Martinez) [RHEL-30311]
    {CVE-2021-47171}
    - net: usb: fix memory leak in smsc75xx_bind (Jose Ignacio Tornos Martinez) [RHEL-30311] {CVE-2021-47171}
    - netfilter: nf_tables: mark set as dead when unbinding anonymous set with timeout (Phil Sutter)
    [RHEL-30076] {CVE-2024-26643}
    - netfilter: nf_tables: disallow anonymous set with timeout flag (Phil Sutter) [RHEL-30080]
    {CVE-2024-26642}
    - md/raid5: fix atomicity violation in raid5_cache_count (Nigel Croxon) [RHEL-27930] {CVE-2024-23307}
    - usb: ulpi: Fix debugfs directory leak (Desnes Nunes) [RHEL-33287] {CVE-2024-26919}
    - powerpc/pseries: Fix potential memleak in papr_get_attr() (Mamatha Inamdar) [RHEL-35213]
    {CVE-2022-48669}
    - USB: usb-storage: Prevent divide-by-0 error in isd200_ata_command (Desnes Nunes) [RHEL-35122]
    {CVE-2024-27059}
    - USB: core: Fix deadlock in usb_deauthorize_interface() (Desnes Nunes) [RHEL-35002] {CVE-2024-26934}
    - usb: xhci: Add error handling in xhci_map_urb_for_dma (Desnes Nunes) [RHEL-34958] {CVE-2024-26964}
    - fs: sysfs: Fix reference leak in sysfs_break_active_protection() (Ewan D. Milne) [RHEL-35076]
    {CVE-2024-26993}
    - xhci: handle isoc Babble and Buffer Overrun events properly (Desnes Nunes) [RHEL-31297] {CVE-2024-26659}
    - xhci: process isoc TD properly when there was a transaction error mid TD. (Desnes Nunes) [RHEL-31297]
    {CVE-2024-26659}
    - USB: core: Fix deadlock in port disable sysfs attribute (Desnes Nunes) [RHEL-35006] {CVE-2024-26933}
    - USB: core: Add hub_get() and hub_put() routines (Desnes Nunes) [RHEL-35006] {CVE-2024-26933}
    - x86/coco: Disable 32-bit emulation by default on TDX and SEV (Vitaly Kuznetsov) [RHEL-25087]
    {CVE-2024-25744}
    - x86: Make IA32_EMULATION boot time configurable (Vitaly Kuznetsov) [RHEL-25087] {CVE-2024-25744}
    - x86/entry: Make IA32 syscalls' availability depend on ia32_enabled() (Vitaly Kuznetsov) [RHEL-25087]
    {CVE-2024-25744}
    - x86/elf: Make loading of 32bit processes depend on ia32_enabled() (Vitaly Kuznetsov) [RHEL-25087]
    {CVE-2024-25744}
    - x86/entry: Rename ignore_sysret() (Vitaly Kuznetsov) [RHEL-25087] {CVE-2024-25744}
    - x86/cpu: Don't write CSTAR MSR on Intel CPUs (Vitaly Kuznetsov) [RHEL-25087] {CVE-2024-25744}
    - x86: Introduce ia32_enabled() (Vitaly Kuznetsov) [RHEL-25087] {CVE-2024-25744}
    - s390/ptrace: handle setting of fpc register correctly (Tobias Huschle) [RHEL-29106] {CVE-2023-52598}
    - net/smc: fix illegal rmb_desc access in SMC-D connection dump (Tobias Huschle) [RHEL-27746]
    {CVE-2024-26615}
    - wifi: mac80211: fix race condition on enabling fast-xmit (Jose Ignacio Tornos Martinez) [RHEL-31664]
    {CVE-2024-26779}
    - mtd: require write permissions for locking and badblock ioctls (Prarit Bhargava) [RHEL-27585]
    {CVE-2021-47055}
    - mtd: properly check all write ioctls for permissions (Prarit Bhargava) [RHEL-27585] {CVE-2021-47055}
    - pid: take a reference when initializing  (Waiman Long) [RHEL-29420] {CVE-2021-47118}
    - i2c: i801: Don't generate an interrupt on bus reset (Prarit Bhargava) [RHEL-30325] {CVE-2021-47153}
    - RDMA/srpt: Do not register event handler until srpt device is fully setup (Kamal Heib) [RHEL-33224]
    {CVE-2024-26872}
    - fat: fix uninitialized field in nostale filehandles (Andrey Albershteyn) [RHEL-33186 RHEL-35108]
    {CVE-2024-26973}
    - do_sys_name_to_handle(): use kzalloc() to fix kernel-infoleak (Andrey Albershteyn) [RHEL-33186]
    {CVE-2024-26901}
    - tty: tty_buffer: Fix the softlockup issue in flush_to_ldisc (Prarit Bhargava) [RHEL-32590]
    {CVE-2021-47185}
    - RDMA/srpt: Support specifying the srpt_service_guid parameter (Kamal Heib) [RHEL-31710] {CVE-2024-26744}
    - RDMA/qedr: Fix qedr_create_user_qp error flow (Kamal Heib) [RHEL-31714] {CVE-2024-26743}
    - hwmon: (coretemp) Fix out-of-bounds memory access (David Arcari) [RHEL-31305] {CVE-2024-26664}
    - net: bridge: use DEV_STATS_INC() (Ivan Vecera) [RHEL-27989] {CVE-2023-52578}
    - net: Fix unwanted sign extension in netdev_stats_to_stats64() (Ivan Vecera) [RHEL-27989]
    {CVE-2023-52578}
    - net: add atomic_long_t to net_device_stats fields (Ivan Vecera) [RHEL-27989] {CVE-2023-52578}
    - net/sched: act_ct: fix skb leak and crash on ooo frags (Xin Long) [RHEL-29467] {CVE-2023-52610}
    - net: usb: smsc75xx: Fix uninit-value access in __smsc75xx_read_reg (Jose Ignacio Tornos Martinez)
    [RHEL-28015] {CVE-2023-52528
    }
    - powerpc/mm: Fix null-pointer dereference in pgtable_cache_add (Mamatha Inamdar) [RHEL-29118]
    {CVE-2023-52607}
    - powerpc/lib: Validate size for vector operations (Mamatha Inamdar) [RHEL-29114] {CVE-2023-52606}
    - usb: hub: Guard against accesses to uninitialized BOS descriptors (Desnes Nunes) [RHEL-28986]
    {CVE-2023-52477}
    - media: uvcvideo: Fix OOB read (Desnes Nunes) [RHEL-27940] {CVE-2023-52565}
    - media: pvrusb2: fix use after free on context disconnection (Desnes Nunes) [RHEL-26498] {CVE-2023-52445}
    - i2c: i801: Fix block process call transactions (Prarit Bhargava) [RHEL-26478] {CVE-2024-26593}
    - media: dvbdev: Fix memory leak in dvb_media_device_free() (Prarit Bhargava) [RHEL-27254]
    {CVE-2020-36777}
    - i2c: Fix a potential use after free (Prarit Bhargava) [RHEL-26849] {CVE-2019-25162}
    - i2c: validate user data in compat ioctl (Prarit Bhargava) [RHEL-27022] {CVE-2021-46934}
    - platform/x86: think-lmi: Fix reference leak (Prarit Bhargava) [RHEL-28030] {CVE-2023-52520}
    - vhost: use kzalloc() instead of kmalloc() followed by memset() (Jon Maloy) [RHEL-21505] {CVE-2024-0340}
    - RDMA/siw: Fix connection failure handling (Kamal Heib) [RHEL-28042] {CVE-2023-52513}
    - vt: fix memory overlapping when deleting chars in the buffer (Waiman Long) [RHEL-27778 RHEL-27779]
    {CVE-2022-48627}
    - x86/fpu: Stop relying on userspace for info to fault in xsave buffer (Steve Best) [RHEL-26669]
    {CVE-2024-26603}
    - mptcp: fix double-free on socket dismantle (Davide Caratti) [RHEL-22773] {CVE-2024-26782}
    - crypto: akcipher - Disable signing and decryption (Herbert Xu) [RHEL-17114] {CVE-2023-6240}
    - crypto: akcipher - default implementations for request callbacks (Herbert Xu) [RHEL-17114]
    {CVE-2023-6240}
    - crypto: testmgr - split akcipher tests by a key type (Herbert Xu) [RHEL-17114] {CVE-2023-6240}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-3618.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26934");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-25744");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/06");

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
  var fixed_uptrack_levels = ['4.18.0-553.5.1.el8_10'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-3618');
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
    {'reference':'bpftool-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-4.18.0'},
    {'reference':'kernel-headers-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-4.18.0'},
    {'reference':'kernel-tools-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-4.18.0'},
    {'reference':'kernel-tools-libs-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-4.18.0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-4.18.0'},
    {'reference':'perf-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-553.5.1.el8_10', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-4.18.0'},
    {'reference':'kernel-abi-stablelists-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-4.18.0'},
    {'reference':'kernel-core-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-4.18.0'},
    {'reference':'kernel-cross-headers-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-4.18.0'},
    {'reference':'kernel-debug-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-4.18.0'},
    {'reference':'kernel-debug-core-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-4.18.0'},
    {'reference':'kernel-debug-devel-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-4.18.0'},
    {'reference':'kernel-debug-modules-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-4.18.0'},
    {'reference':'kernel-debug-modules-extra-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-4.18.0'},
    {'reference':'kernel-devel-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-4.18.0'},
    {'reference':'kernel-headers-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-4.18.0'},
    {'reference':'kernel-modules-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-4.18.0'},
    {'reference':'kernel-modules-extra-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-4.18.0'},
    {'reference':'kernel-tools-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-4.18.0'},
    {'reference':'kernel-tools-libs-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-4.18.0'},
    {'reference':'kernel-tools-libs-devel-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-4.18.0'},
    {'reference':'perf-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-4.18.0-553.5.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
