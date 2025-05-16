#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12868.
##

include('compat.inc');

if (description)
{
  script_id(212202);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/09");

  script_cve_id(
    "CVE-2019-15222",
    "CVE-2021-3759",
    "CVE-2021-33655",
    "CVE-2023-31083",
    "CVE-2024-36971",
    "CVE-2024-42131",
    "CVE-2024-42228",
    "CVE-2024-42259",
    "CVE-2024-42265",
    "CVE-2024-42271",
    "CVE-2024-42280",
    "CVE-2024-42284",
    "CVE-2024-42285",
    "CVE-2024-42289",
    "CVE-2024-42295",
    "CVE-2024-42297",
    "CVE-2024-42301",
    "CVE-2024-42304",
    "CVE-2024-42305",
    "CVE-2024-42309",
    "CVE-2024-42310",
    "CVE-2024-42311",
    "CVE-2024-42313",
    "CVE-2024-43839",
    "CVE-2024-43853",
    "CVE-2024-43854",
    "CVE-2024-43856",
    "CVE-2024-43858",
    "CVE-2024-43860",
    "CVE-2024-43861",
    "CVE-2024-43871",
    "CVE-2024-43882",
    "CVE-2024-43883",
    "CVE-2024-43884",
    "CVE-2024-43890",
    "CVE-2024-43893",
    "CVE-2024-43914",
    "CVE-2024-44944",
    "CVE-2024-44946",
    "CVE-2024-44947",
    "CVE-2024-44948",
    "CVE-2024-44954",
    "CVE-2024-44960",
    "CVE-2024-44968",
    "CVE-2024-44987",
    "CVE-2024-44998",
    "CVE-2024-44999",
    "CVE-2024-45008",
    "CVE-2024-45021",
    "CVE-2024-45028",
    "CVE-2024-46673",
    "CVE-2024-46674",
    "CVE-2024-46675",
    "CVE-2024-46677",
    "CVE-2024-46685",
    "CVE-2024-46721",
    "CVE-2024-46722",
    "CVE-2024-46723",
    "CVE-2024-46743",
    "CVE-2024-46744",
    "CVE-2024-46745",
    "CVE-2024-46750",
    "CVE-2024-46755",
    "CVE-2024-46756",
    "CVE-2024-46757",
    "CVE-2024-46758",
    "CVE-2024-46759",
    "CVE-2024-46761",
    "CVE-2024-46771",
    "CVE-2024-46780",
    "CVE-2024-46781",
    "CVE-2024-46800",
    "CVE-2024-46829",
    "CVE-2024-46840",
    "CVE-2024-46844",
    "CVE-2024-47669",
    "CVE-2024-47696",
    "CVE-2024-47709",
    "CVE-2024-49958",
    "CVE-2024-50074"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel (ELSA-2024-12868)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-12868 advisory.

    - ocfs2: reserve space for inline xattr before attaching reflink tree (Gautham Ananthakrishna)  [Orabug:
    37199021] {CVE-2024-49958}
    - rtmutex: Drop rt_mutex::wait_lock before scheduling (Roland Xu) [Orabug: 37116447] {CVE-2024-46829}
    - nilfs2: protect references to superblock parameters exposed in sysfs (Ryusuke Konishi) [Orabug:
    37074678] {CVE-2024-46780}
    - of/irq: Prevent device address out-of-bounds read in interrupt map walk (Stefan Wiehler) [Orabug:
    37074490] {CVE-2024-46743}
    - Squashfs: sanity check symbolic link size (Phillip Lougher) [Orabug: 37074496] {CVE-2024-46744}
    - Input: uinput - reject requests with unreasonable number of slots (Dmitry Torokhov) [Orabug: 37074504]
    {CVE-2024-46745}
    - PCI: Add missing bridge lock to pci_bus_lock() (Dan Williams) [Orabug: 37074533] {CVE-2024-46750}
    - btrfs: clean up our handling of refs == 0 in snapshot delete (Josef Bacik) [Orabug: 37116495]
    {CVE-2024-46840}
    - wifi: mwifiex: Do not return unused priv in mwifiex_get_priv_by_id() (Sascha Hauer) [Orabug: 37074562]
    {CVE-2024-46755}
    - hwmon: (w83627ehf) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug: 37074567]
    {CVE-2024-46756}
    - hwmon: (nct6775-core) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug:
    37074572] {CVE-2024-46757}
    - hwmon: (lm95234) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug: 37074580]
    {CVE-2024-46758}
    - hwmon: (adc128d818) Fix underflows seen when writing limit attributes (Guenter Roeck) [Orabug: 37074586]
    {CVE-2024-46759}
    - pci/hotplug/pnv_php: Fix hotplug driver crash on Powernv (Krishna Kumar) [Orabug: 37074596]
    {CVE-2024-46761}
    - um: line: always fill *error_out in setup_one_line() (Johannes Berg) [Orabug: 37116519] {CVE-2024-46844}
    - can: bcm: Remove proc entry when dev is unregistered. (Kuniyuki Iwashima) [Orabug: 37074626]
    {CVE-2024-46771}
    - nilfs2: fix state management in error path of log writing function (Ryusuke Konishi) [Orabug: 37159766]
    {CVE-2024-47669}
    - nilfs2: fix missing cleanup on rollforward recovery error (Ryusuke Konishi) [Orabug: 37074685]
    {CVE-2024-46781}
    - sch/netem: fix use after free in netem_dequeue (Stephen Hemminger) [Orabug: 37074727] {CVE-2024-46800}
    - ALSA: usb-audio: Fix gpf in snd_usb_pipe_sanity_check (Hillf Danton) [Orabug: 30562949] {CVE-2019-15222}
    - block: initialize integrity buffer to zero before writing it to media (Christoph Hellwig) [Orabug:
    36964517] {CVE-2024-43854}
    - apparmor: fix possible NULL pointer dereference (Leesoo Ahn) [Orabug: 37073079] {CVE-2024-46721}
    - drm/amdgpu: fix mc_data out-of-bounds read warning (Tim Huang) [Orabug: 37073084] {CVE-2024-46722}
    - drm/amdgpu: fix ucode out-of-bounds read warning (Tim Huang) [Orabug: 37073089] {CVE-2024-46723}
    - scsi: aacraid: Fix double-free on probe failure (Ben Hutchings) [Orabug: 37070701] {CVE-2024-46673}
    - usb: dwc3: st: fix probed platform device ref count on probe error path (Krzysztof Kozlowski) [Orabug:
    37070706] {CVE-2024-46674}
    - usb: dwc3: core: Prevent USB core invalid event buffer address access (Selvarasu Ganesan) [Orabug:
    37070711] {CVE-2024-46675}
    - gtp: fix a potential NULL pointer dereference (Cong Wang) [Orabug: 37070723] {CVE-2024-46677}
    - fbmem: Check virtual screen sizes in fb_set_var() (Helge Deller) [Orabug: 34408909] {CVE-2021-33655}
    - fbcon: Prevent that screen size is smaller than font size (Helge Deller) [Orabug: 34408909]
    {CVE-2021-33655}
    - memcg: enable accounting of ipc resources (Vasily Averin) [Orabug: 34214321] {CVE-2021-3759}
    - cgroup/cpuset: Prevent UAF in proc_cpuset_show() (Chen Ridong) [Orabug: 36964511] {CVE-2024-43853}
    - pinctrl: single: fix potential NULL dereference in pcs_get_function() (Ma Ke) [Orabug: 37070745]
    {CVE-2024-46685}
    - drm/amdgpu: Using uninitialized value *size when calling amdgpu_vce_cs_reloc (Jesse Zhang) [Orabug:
    36898010] {CVE-2024-42228}
    - Input: MT - limit max slots (Tetsuo Handa) [Orabug: 37029138] {CVE-2024-45008}
    - Bluetooth: hci_ldisc: check HCI_UART_PROTO_READY flag in HCIUARTGETPROTO (Lee, Chun-Yi) [Orabug:
    36654193] {CVE-2023-31083}
    - Bluetooth: MGMT: Add error handling to pair_device() (Griffin Kroah-Hartman) [Orabug: 36992977]
    {CVE-2024-43884}
    - mmc: mmc_test: Fix NULL dereference on allocation failure (Dan Carpenter) [Orabug: 37070692]
    {CVE-2024-45028}
    - ipv6: prevent UAF in ip6_send_skb() (Eric Dumazet) [Orabug: 37029077] {CVE-2024-44987}
    - kcm: Serialise kcm_sendmsg() for the same socket. (Kuniyuki Iwashima) [Orabug: 37013762]
    {CVE-2024-44946}
    - gtp: pull network headers in gtp_dev_xmit() (Eric Dumazet) [Orabug: 37029112] {CVE-2024-44999}
    - atm: idt77252: prevent use after free in dequeue_rx() (Dan Carpenter) [Orabug: 37029106]
    {CVE-2024-44998}
    - memcg_write_event_control(): fix a user-triggerable oops (Al Viro) [Orabug: 37070673] {CVE-2024-45021}
    - fuse: Initialize beyond-EOF page contents before setting uptodate (Jann Horn) [Orabug: 37017952]
    {CVE-2024-44947}
    - net: fix __dst_negative_advice() race (Eric Dumazet)  [Orabug: 36720418]  {CVE-2024-36971}
    - exec: Fix ToCToU between perm check and set-uid/gid usage (Kees Cook) [Orabug: 36984018]
    {CVE-2024-43882}
    - drm/i915/gem: Fix Virtual Memory mapping boundaries calculation (Andi Shyti) [Orabug: 36953970]
    {CVE-2024-42259}
    - x86/mtrr: Check if fixed MTRRs exist before saving them (Andi Kleen) [Orabug: 37028937] {CVE-2024-44948}
    - tracing: Fix overflow in get_free_elt() (Tze-nan Wu) [Orabug: 36992999] {CVE-2024-43890}
    - serial: core: check uartclk for zero to avoid divide by zero (George Kennedy) [Orabug: 36993010]
    {CVE-2024-43893}
    - tick/broadcast: Move per CPU pointer access into the atomic section (Thomas Gleixner) [Orabug: 37242882]
    {CVE-2024-44968}
    - usb: gadget: core: Check for unset descriptor (Chris Wulff) [Orabug: 37028989] {CVE-2024-44960}
    - usb: vhci-hcd: Do not drop references before new references are gained (Oliver Neukum) [Orabug:
    36992972] {CVE-2024-43883}
    - ALSA: line6: Fix racy access to midibuf (Takashi Iwai) [Orabug: 37028959] {CVE-2024-44954}
    - md/raid5: avoid BUG_ON() while continue reshape after reassembling (Yu Kuai) [Orabug: 36993128]
    {CVE-2024-43914}
    - net: usb: qmi_wwan: fix memory leak for not ip packets (Daniele Palmas) [Orabug: 36983960]
    {CVE-2024-43861}
    - protect the fetch of ->fd[fd] in do_dup2() from mispredictions (Al Viro) [Orabug: 36963809]
    {CVE-2024-42265}
    - net/iucv: fix use after free in iucv_sock_close() (Alexandra Winter) [Orabug: 36964007] {CVE-2024-42271}
    - remoteproc: imx_rproc: Skip over memory region when node value is NULL (Aleksandr Mishin) [Orabug:
    36964539] {CVE-2024-43860}
    - devres: Fix memory leakage caused by driver API devm_free_percpu() (Zijun Hu) [Orabug: 36983992]
    {CVE-2024-43871}
    - dev/parport: fix the array out-of-bounds risk (tuhaowen) [Orabug: 36964224] {CVE-2024-42301}
    - mm: avoid overflows in dirty throttling logic (Jan Kara) [Orabug: 36897804] {CVE-2024-42131}
    - mISDN: Fix a use after free in hfcmulti_tx() (Dan Carpenter) [Orabug: 36964033] {CVE-2024-42280}
    - tipc: Return non-zero value from tipc_udp_addr2str() on error (Shigeru Yoshida) [Orabug: 36964048]
    {CVE-2024-42284}
    - dma: fix call order in dmam_free_coherent (Lance Richardson) [Orabug: 36964524] {CVE-2024-43856}
    - jfs: Fix array-index-out-of-bounds in diFree (Jeongjun Park) [Orabug: 36964531] {CVE-2024-43858}
    - nilfs2: handle inconsistent state in nilfs_btnode_create_block() (Ryusuke Konishi) [Orabug: 36964204]
    {CVE-2024-42295}
    - RDMA/iwcm: Fix a use-after-free related to destroying CM IDs (Bart Van Assche) [Orabug: 36964055]
    {CVE-2024-42285}
    - scsi: qla2xxx: During vport delete send async logout explicitly (Manish Rangankar) [Orabug: 36964081]
    {CVE-2024-42289}
    - f2fs: fix to don't dirty inode for readonly filesystem (Chao Yu) [Orabug: 36964214] {CVE-2024-42297}
    - ext4: make sure the first directory block is not a hole (Baokun Li) [Orabug: 36964233] {CVE-2024-42304}
    - ext4: check dot and dotdot of dx_root before making dir indexed (Baokun Li) [Orabug: 36964238]
    {CVE-2024-42305}
    - drm/gma500: fix null pointer dereference in psb_intel_lvds_get_modes (Ma Ke) [Orabug: 36964254]
    {CVE-2024-42309}
    - drm/gma500: fix null pointer dereference in cdv_intel_lvds_get_modes (Ma Ke) [Orabug: 36964261]
    {CVE-2024-42310}
    - hfs: fix to initialize fields of hfs_inode_info after hfs_alloc_inode() (Chao Yu) [Orabug: 36964266]
    {CVE-2024-42311}
    - media: venus: fix use after free in vdec_close (Dikshita Agarwal) [Orabug: 36964276] {CVE-2024-42313}
    - netfilter: ctnetlink: use helper function to calculate expect ID (Pablo Neira Ayuso) [Orabug: 37013756]
    {CVE-2024-44944}
    - bna: adjust 'name' buf size of bna_tcb and bna_ccb structures (Alexey Kodanev) [Orabug: 36964481]
    {CVE-2024-43839}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12868.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15222");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-50074");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7:9:patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::UEKR5");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::developer_UEKR5");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::optional_latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs-devel");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['4.14.35-2047.543.3.el7uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-12868');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '4.14';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-4.14.35-2047.543.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.14.35'},
    {'reference':'kernel-uek-debug-4.14.35-2047.543.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.14.35'},
    {'reference':'kernel-uek-debug-devel-4.14.35-2047.543.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.14.35'},
    {'reference':'kernel-uek-devel-4.14.35-2047.543.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.14.35'},
    {'reference':'kernel-uek-headers-4.14.35-2047.543.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-4.14.35'},
    {'reference':'kernel-uek-tools-4.14.35-2047.543.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-4.14.35'},
    {'reference':'kernel-uek-tools-libs-4.14.35-2047.543.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-4.14.35'},
    {'reference':'kernel-uek-tools-libs-devel-4.14.35-2047.543.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-devel-4.14.35'},
    {'reference':'perf-4.14.35-2047.543.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-4.14.35'},
    {'reference':'python-perf-4.14.35-2047.543.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-4.14.35'},
    {'reference':'kernel-uek-4.14.35-2047.543.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-4.14.35'},
    {'reference':'kernel-uek-debug-4.14.35-2047.543.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-4.14.35'},
    {'reference':'kernel-uek-debug-devel-4.14.35-2047.543.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-4.14.35'},
    {'reference':'kernel-uek-devel-4.14.35-2047.543.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-4.14.35'},
    {'reference':'kernel-uek-doc-4.14.35-2047.543.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-4.14.35'},
    {'reference':'kernel-uek-headers-4.14.35-2047.543.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-headers-4.14.35'},
    {'reference':'kernel-uek-tools-4.14.35-2047.543.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-4.14.35'},
    {'reference':'kernel-uek-tools-libs-4.14.35-2047.543.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-4.14.35'},
    {'reference':'kernel-uek-tools-libs-devel-4.14.35-2047.543.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-devel-4.14.35'},
    {'reference':'perf-4.14.35-2047.543.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-4.14.35'},
    {'reference':'python-perf-4.14.35-2047.543.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-4.14.35'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek / kernel-uek-debug / kernel-uek-debug-devel / etc');
}
