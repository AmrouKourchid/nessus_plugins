#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12813.
##

include('compat.inc');

if (description)
{
  script_id(210882);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/13");

  script_cve_id(
    "CVE-2023-31083",
    "CVE-2024-26951",
    "CVE-2024-36028",
    "CVE-2024-41011",
    "CVE-2024-41098",
    "CVE-2024-42228",
    "CVE-2024-43835",
    "CVE-2024-43853",
    "CVE-2024-43854",
    "CVE-2024-43884",
    "CVE-2024-44946",
    "CVE-2024-44947",
    "CVE-2024-44987",
    "CVE-2024-44988",
    "CVE-2024-44995",
    "CVE-2024-44998",
    "CVE-2024-44999",
    "CVE-2024-45003",
    "CVE-2024-45006",
    "CVE-2024-45008",
    "CVE-2024-45016",
    "CVE-2024-45021",
    "CVE-2024-45025",
    "CVE-2024-45026",
    "CVE-2024-45028",
    "CVE-2024-46673",
    "CVE-2024-46674",
    "CVE-2024-46675",
    "CVE-2024-46676",
    "CVE-2024-46677",
    "CVE-2024-46679",
    "CVE-2024-46685",
    "CVE-2024-46714",
    "CVE-2024-46719",
    "CVE-2024-46721",
    "CVE-2024-46722",
    "CVE-2024-46723",
    "CVE-2024-46737",
    "CVE-2024-46739",
    "CVE-2024-46740",
    "CVE-2024-46743",
    "CVE-2024-46744",
    "CVE-2024-46745",
    "CVE-2024-46747",
    "CVE-2024-46750",
    "CVE-2024-46755",
    "CVE-2024-46756",
    "CVE-2024-46757",
    "CVE-2024-46758",
    "CVE-2024-46759",
    "CVE-2024-46761",
    "CVE-2024-46771",
    "CVE-2024-46777",
    "CVE-2024-46780",
    "CVE-2024-46781",
    "CVE-2024-46782",
    "CVE-2024-46783",
    "CVE-2024-46798",
    "CVE-2024-46800",
    "CVE-2024-46815",
    "CVE-2024-46817",
    "CVE-2024-46818",
    "CVE-2024-46822",
    "CVE-2024-46828",
    "CVE-2024-46829",
    "CVE-2024-46840",
    "CVE-2024-46844",
    "CVE-2024-47663",
    "CVE-2024-47667",
    "CVE-2024-47668",
    "CVE-2024-47669",
    "CVE-2024-49863",
    "CVE-2024-49958"
  );

  script_name(english:"Oracle Linux 7 / 8 : Unbreakable Enterprise kernel (ELSA-2024-12813)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2024-12813 advisory.

    - vhost/scsi: null-ptr-dereference in vhost_scsi_get_req() (Haoran Zhang)  [Orabug: 37137548]
    {CVE-2024-49863}
    - mm/hugetlb: fix DEBUG_LOCKS_WARN_ON(1) when dissolve_free_hugetlb_folio() (Miaohe Lin)  [Orabug:
    36683094]  {CVE-2024-36028}
    - rtmutex: Drop rt_mutex::wait_lock before scheduling (Roland Xu) [Orabug: 37116446] {CVE-2024-46829}
    - nvmet-tcp: fix kernel crash if commands allocation fails (Maurizio Lombardi) [Orabug: 37074465]
    {CVE-2024-46737}
    - arm64: acpi: Harden get_cpu_for_acpi_id() against missing CPU entry (Jonathan Cameron) [Orabug:
    37116413] {CVE-2024-46822}
    - nilfs2: protect references to superblock parameters exposed in sysfs (Ryusuke Konishi) [Orabug:
    37074677] {CVE-2024-46780}
    - uio_hv_generic: Fix kernel NULL pointer dereference in hv_uio_rescind (Saurabh Sengar) [Orabug:
    37074473] {CVE-2024-46739}
    - binder: fix UAF caused by offsets overwrite (Carlos Llamas) [Orabug: 37074477] {CVE-2024-46740}
    - staging: iio: frequency: ad9834: Validate frequency parameter value (Aleksandr Mishin) [Orabug:
    37159728] {CVE-2024-47663}
    - lib/generic-radix-tree.c: Fix rare race in __genradix_ptr_alloc() (Kent Overstreet) [Orabug: 37159757]
    {CVE-2024-47668}
    - of/irq: Prevent device address out-of-bounds read in interrupt map walk (Stefan Wiehler) [Orabug:
    37074488] {CVE-2024-46743}
    - Squashfs: sanity check symbolic link size (Phillip Lougher) [Orabug: 37074495] {CVE-2024-46744}
    - Input: uinput - reject requests with unreasonable number of slots (Dmitry Torokhov) [Orabug: 37074503]
    {CVE-2024-46745}
    - HID: cougar: fix slab-out-of-bounds Read in cougar_report_fixup (Camila Alvarez) [Orabug: 37074513]
    {CVE-2024-46747}
    - PCI: Add missing bridge lock to pci_bus_lock() (Dan Williams) [Orabug: 37074532] {CVE-2024-46750}
    - btrfs: clean up our handling of refs == 0 in snapshot delete (Josef Bacik) [Orabug: 37116494]
    {CVE-2024-46840}
    - wifi: mwifiex: Do not return unused priv in mwifiex_get_priv_by_id() (Sascha Hauer) [Orabug: 37074561]
    {CVE-2024-46755}
    - hwmon: (w83627ehf) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug: 37074566]
    {CVE-2024-46756}
    - hwmon: (nct6775-core) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug:
    37074571] {CVE-2024-46757}
    - hwmon: (lm95234) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug: 37074579]
    {CVE-2024-46758}
    - hwmon: (adc128d818) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug: 37074584]
    {CVE-2024-46759}
    - pci/hotplug/pnv_php: Fix hotplug driver crash on Powernv (Krishna Kumar) [Orabug: 37074595]
    {CVE-2024-46761}
    - um: line: always fill *error_out in setup_one_line() (Johannes Berg) [Orabug: 37116518] {CVE-2024-46844}
    - tcp_bpf: fix return value of tcp_bpf_sendmsg() (Cong Wang) [Orabug: 37074693] {CVE-2024-46783}
    - can: bcm: Remove proc entry when dev is unregistered. (Kuniyuki Iwashima) [Orabug: 37074625]
    {CVE-2024-46771}
    - PCI: keystone: Add workaround for Errata #i2037 (AM65x SR 1.0) (Kishon Vijay Abraham I) [Orabug:
    37159750] {CVE-2024-47667}
    - udf: Avoid excessive partition lengths (Jan Kara) [Orabug: 37074665] {CVE-2024-46777}
    - nilfs2: fix state management in error path of log writing function (Ryusuke Konishi) [Orabug: 37159765]
    {CVE-2024-47669}
    - nilfs2: fix missing cleanup on rollforward recovery error (Ryusuke Konishi) [Orabug: 37074684]
    {CVE-2024-46781}
    - sched: sch_cake: fix bulk flow accounting logic for host fairness (Toke Hoiland-Jorgensen) [Orabug:
    37116443] {CVE-2024-46828}
    - ila: call nf_unregister_net_hooks() sooner (Eric Dumazet) [Orabug: 37074689] {CVE-2024-46782}
    - ASoC: dapm: Fix UAF for snd_soc_pcm_runtime object (robelin) [Orabug: 37074722] {CVE-2024-46798}
    - sch/netem: fix use after free in netem_dequeue (Stephen Hemminger) [Orabug: 37074726] {CVE-2024-46800}
    - virtio_net: Fix napi_skb_cache_put warning (Breno Leitao) [Orabug: 36964474] {CVE-2024-43835}
    - block: initialize integrity buffer to zero before writing it to media (Christoph Hellwig) [Orabug:
    36964515] {CVE-2024-43854}
    - drm/amd/display: Skip wbscl_set_scaler_filter if filter is null (Alex Hung) [Orabug: 37073032]
    {CVE-2024-46714}
    - usb: typec: ucsi: Fix null pointer dereference in trace (Abhishek Pandit-Subedi) [Orabug: 37073065]
    {CVE-2024-46719}
    - apparmor: fix possible NULL pointer dereference (Leesoo Ahn) [Orabug: 37073078] {CVE-2024-46721}
    - drm/amdgpu: fix mc_data out-of-bounds read warning (Tim Huang) [Orabug: 37073083] {CVE-2024-46722}
    - drm/amdgpu: fix ucode out-of-bounds read warning (Tim Huang) [Orabug: 37073088] {CVE-2024-46723}
    - drm/amd/display: Check num_valid_sets before accessing reader_wm_sets[] (Alex Hung) [Orabug: 37116366]
    {CVE-2024-46815}
    - drm/amd/display: Stop amdgpu_dm initialize when stream nums greater than 6 (Hersen Wu) [Orabug:
    37116376] {CVE-2024-46817}
    - drm/amd/display: Check gpio_id before used as array index (Alex Hung) [Orabug: 37116385]
    {CVE-2024-46818}
    - scsi: aacraid: Fix double-free on probe failure (Ben Hutchings) [Orabug: 37070700] {CVE-2024-46673}
    - usb: dwc3: st: fix probed platform device ref count on probe error path (Krzysztof Kozlowski) [Orabug:
    37070705] {CVE-2024-46674}
    - usb: dwc3: core: Prevent USB core invalid event buffer address access (Selvarasu Ganesan) [Orabug:
    37070710] {CVE-2024-46675}
    - nfc: pn533: Add poll mod list filling check (Aleksandr Mishin) [Orabug: 37070717] {CVE-2024-46676}
    - gtp: fix a potential NULL pointer dereference (Cong Wang) [Orabug: 37070722] {CVE-2024-46677}
    - ethtool: check device is present when getting link settings (Jamie Bainbridge) [Orabug: 37070728]
    {CVE-2024-46679}
    - cgroup/cpuset: Prevent UAF in proc_cpuset_show() (Chen Ridong) [Orabug: 36964510] {CVE-2024-43853}
    - ata: libata-core: Fix null pointer dereference on error (Niklas Cassel) [Orabug: 36897457]
    {CVE-2024-41098}
    - drm/amdkfd: don't allow mapping the MMIO HDP page with large pages (Alex Deucher) [Orabug: 36867631]
    {CVE-2024-41011}
    - pinctrl: single: fix potential NULL dereference in pcs_get_function() (Ma Ke) [Orabug: 37070744]
    {CVE-2024-46685}
    - drm/amdgpu: Using uninitialized value *size when calling amdgpu_vce_cs_reloc (Jesse Zhang) [Orabug:
    36898009] {CVE-2024-42228}
    (Alexander Lobakin)
    - Input: MT - limit max slots (Tetsuo Handa) [Orabug: 37029137] {CVE-2024-45008}
    - Bluetooth: hci_ldisc: check HCI_UART_PROTO_READY flag in HCIUARTGETPROTO (Lee, Chun-Yi) [Orabug:
    36654191] {CVE-2023-31083}
    - Bluetooth: MGMT: Add error handling to pair_device() (Griffin Kroah-Hartman) [Orabug: 36992976]
    {CVE-2024-43884}
    - mmc: mmc_test: Fix NULL dereference on allocation failure (Dan Carpenter) [Orabug: 37070691]
    {CVE-2024-45028}
    - ipv6: prevent UAF in ip6_send_skb() (Eric Dumazet) [Orabug: 37029076] {CVE-2024-44987}
    - netem: fix return value if duplicate enqueue fails (Stephen Hemminger) [Orabug: 37070660]
    {CVE-2024-45016}
    - net: dsa: mv88e6xxx: Fix out-of-bound access (Joseph Huang) [Orabug: 37029082] {CVE-2024-44988}
    - kcm: Serialise kcm_sendmsg() for the same socket. (Kuniyuki Iwashima) [Orabug: 37013761]
    {CVE-2024-44946}
    - gtp: pull network headers in gtp_dev_xmit() (Eric Dumazet) [Orabug: 37029111] {CVE-2024-44999}
    - net: hns3: fix a deadlock problem when config TC during resetting (Jie Wang) [Orabug: 37029098]
    {CVE-2024-44995}
    - atm: idt77252: prevent use after free in dequeue_rx() (Dan Carpenter) [Orabug: 37029105]
    {CVE-2024-44998}
    - memcg_write_event_control(): fix a user-triggerable oops (Al Viro) [Orabug: 37070672] {CVE-2024-45021}
    - fix bitmap corruption on close_range() with CLOSE_RANGE_UNSHARE (Al Viro) [Orabug: 37070680]
    {CVE-2024-45025}
    - vfs: Don't evict inode under the inode lru traversing context (Zhihao Cheng) [Orabug: 37029119]
    {CVE-2024-45003}
    - s390/dasd: fix error recovery leading to data corruption on ESE devices (Stefan Haberland) [Orabug:
    37070687] {CVE-2024-45026}
    - xhci: Fix Panther point NULL pointer deref at full-speed re-enumeration (Mathias Nyman) [Orabug:
    37029125] {CVE-2024-45006}
    - fuse: Initialize beyond-EOF page contents before setting uptodate (Jann Horn) [Orabug: 37017951]
    {CVE-2024-44947}
    - wireguard: netlink: check for dangling peer via is_dead instead of empty list (Jason A. Donenfeld)
    [Orabug: 36596766]  {CVE-2024-26951}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12813.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46844");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8:10:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
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
if (! preg(pattern:"^(7|8)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7 / 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.4.17-2136.337.5.el7uek', '5.4.17-2136.337.5.el8uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-12813');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.4';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-5.4.17-2136.337.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.337.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.337.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.337.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.337.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2136.337.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-tools-libs-5.4.17-2136.337.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-5.4.17'},
    {'reference':'perf-5.4.17-2136.337.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-5.4.17'},
    {'reference':'python-perf-5.4.17-2136.337.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.337.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-container-5.4.17-2136.337.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.337.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.337.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.337.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.337.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.337.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2136.337.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-tools-libs-5.4.17-2136.337.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-5.4.17'},
    {'reference':'perf-5.4.17-2136.337.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-5.4.17'},
    {'reference':'python-perf-5.4.17-2136.337.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.337.5.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.337.5.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.337.5.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.337.5.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.337.5.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.337.5.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-container-5.4.17-2136.337.5.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.337.5.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.337.5.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.337.5.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.337.5.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.337.5.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-container / kernel-uek-container-debug / etc');
}
