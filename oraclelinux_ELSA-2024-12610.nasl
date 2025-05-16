#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12610.
##

include('compat.inc');

if (description)
{
  script_id(206999);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/12");

  script_cve_id(
    "CVE-2022-3566",
    "CVE-2022-3567",
    "CVE-2023-4881",
    "CVE-2023-52628",
    "CVE-2023-52803",
    "CVE-2024-36484",
    "CVE-2024-36894",
    "CVE-2024-36974",
    "CVE-2024-36978",
    "CVE-2024-37078",
    "CVE-2024-38619",
    "CVE-2024-39469",
    "CVE-2024-39487",
    "CVE-2024-39495",
    "CVE-2024-39499",
    "CVE-2024-39501",
    "CVE-2024-39502",
    "CVE-2024-39505",
    "CVE-2024-39506",
    "CVE-2024-39509",
    "CVE-2024-40901",
    "CVE-2024-40902",
    "CVE-2024-40904",
    "CVE-2024-40905",
    "CVE-2024-40912",
    "CVE-2024-40932",
    "CVE-2024-40934",
    "CVE-2024-40941",
    "CVE-2024-40942",
    "CVE-2024-40943",
    "CVE-2024-40945",
    "CVE-2024-40958",
    "CVE-2024-40959",
    "CVE-2024-40960",
    "CVE-2024-40961",
    "CVE-2024-40963",
    "CVE-2024-40968",
    "CVE-2024-40974",
    "CVE-2024-40978",
    "CVE-2024-40980",
    "CVE-2024-40981",
    "CVE-2024-40987",
    "CVE-2024-40988",
    "CVE-2024-40993",
    "CVE-2024-40995",
    "CVE-2024-41006",
    "CVE-2024-41007",
    "CVE-2024-41022",
    "CVE-2024-41034",
    "CVE-2024-41035",
    "CVE-2024-41041",
    "CVE-2024-41044",
    "CVE-2024-41046",
    "CVE-2024-41049",
    "CVE-2024-41087",
    "CVE-2024-41089",
    "CVE-2024-41095",
    "CVE-2024-41097",
    "CVE-2024-42070",
    "CVE-2024-42076",
    "CVE-2024-42084",
    "CVE-2024-42086",
    "CVE-2024-42087",
    "CVE-2024-42089",
    "CVE-2024-42090",
    "CVE-2024-42092",
    "CVE-2024-42093",
    "CVE-2024-42094",
    "CVE-2024-42096",
    "CVE-2024-42097",
    "CVE-2024-42101",
    "CVE-2024-42104",
    "CVE-2024-42105",
    "CVE-2024-42106",
    "CVE-2024-42115",
    "CVE-2024-42119",
    "CVE-2024-42124",
    "CVE-2024-42127",
    "CVE-2024-42143",
    "CVE-2024-42145",
    "CVE-2024-42148",
    "CVE-2024-42153",
    "CVE-2024-42154",
    "CVE-2024-42157",
    "CVE-2024-42223",
    "CVE-2024-42224",
    "CVE-2024-42232",
    "CVE-2024-42236"
  );
  script_xref(name:"IAVA", value:"2024-A-0487");

  script_name(english:"Oracle Linux 7 / 8 : Unbreakable Enterprise kernel (ELSA-2024-12610)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2024-12610 advisory.

    - MIPS: Octeon: Add PCIe link status check (Dave Kleikamp)  [Orabug: 36947196] {CVE-2024-40968}
    - drm/amdgpu: Fix signedness bug in sdma_v4_0_process_trap_irq() (Dan Carpenter) [Orabug: 36898075]
    {CVE-2024-41022}
    - net: relax socket state check at accept time. (Paolo Abeni) [Orabug: 36768889] {CVE-2024-36484}
    - nilfs2: fix kernel bug on rename operation of broken directory (Ryusuke Konishi) [Orabug: 36896821]
    {CVE-2024-41034}
    - tcp: avoid too many retransmit packets (Eric Dumazet) [Orabug: 36841816] {CVE-2024-41007}
    - SUNRPC: Fix RPC client cleaned up the freed pipefs dentries (felix) [Orabug: 36940547] {CVE-2023-52803}
    - libceph: fix race between delayed_work() and ceph_monc_stop() (Ilya Dryomov) [Orabug: 36930128]
    {CVE-2024-42232}
    - USB: core: Fix duplicate endpoint bug by clearing reserved bits in the descriptor (Alan Stern) [Orabug:
    36896826] {CVE-2024-41035}
    - usb: gadget: configfs: Prevent OOB read/write in usb_string_copy() (Lee Jones) [Orabug: 36930138]
    {CVE-2024-42236}
    - udp: Set SOCK_RCU_FREE earlier in udp_lib_get_port(). (Kuniyuki Iwashima) [Orabug: 36896842]
    {CVE-2024-41041}
    - ppp: reject claimed-as-LCP but actually malformed packets (Dmitry Antipov) [Orabug: 36896856]
    {CVE-2024-41044}
    - net: ethernet: lantiq_etop: fix double free in detach (Aleksander Jan Bajkowski) [Orabug: 36896863]
    {CVE-2024-41046}
    - filelock: fix potential use-after-free in posix_lock_inode (Jeff Layton) [Orabug: 36896877]
    {CVE-2024-41049}
    - i2c: pnx: Fix potential deadlock warning from del_timer_sync() call in isr (Piotr Wojtaszczyk) [Orabug:
    36897909] {CVE-2024-42153}
    - bnx2x: Fix multiple UBSAN array-index-out-of-bounds (Ghadi Elie Rahme) [Orabug: 36897886]
    {CVE-2024-42148}
    - drm/nouveau: fix null pointer dereference in nouveau_connector_get_modes (Ma Ke) [Orabug: 36897640]
    {CVE-2024-42101}
    - nilfs2: add missing check for inode numbers on directory entries (Ryusuke Konishi) [Orabug: 36897652]
    {CVE-2024-42104}
    - nilfs2: fix inode number range checks (Ryusuke Konishi) [Orabug: 36897658] {CVE-2024-42105}
    - inet_diag: Initialize pad field in struct inet_diag_req_v2 (Shigeru Yoshida) [Orabug: 36897666]
    {CVE-2024-42106}
    - bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set() (Sam Sun) [Orabug: 36825248]
    {CVE-2024-39487}
    - tcp_metrics: validate source addr length (Jakub Kicinski) [Orabug: 36897915] {CVE-2024-42154}
    - s390/pkey: Wipe sensitive data on failure (Holger Dengler) [Orabug: 36897934] {CVE-2024-42157}
    - jffs2: Fix potential illegal address access in jffs2_free_inode (Wang Yong) [Orabug: 36897696]
    {CVE-2024-42115}
    - orangefs: fix out-of-bounds fsid access (Mike Marshall) [Orabug: 36897837] {CVE-2024-42143}
    - media: dvb-frontends: tda10048: Fix integer overflow (Ricardo Ribalda) [Orabug: 36897976]
    {CVE-2024-42223}
    - net: dsa: mv88e6xxx: Correct check for empty list (Simon Horman) [Orabug: 36897982] {CVE-2024-42224}
    - drm/amd/display: Skip finding free audio for unknown engine_id (Alex Hung) [Orabug: 36897726]
    {CVE-2024-42119}
    - scsi: qedf: Make qedf_execute_tmf() non-preemptible (John Meneghini) [Orabug: 36897761] {CVE-2024-42124}
    - IB/core: Implement a limit on UMAD receive List (Michael Guralnik) [Orabug: 36897847] {CVE-2024-42145}
    - drm/lima: fix shared irq handling on driver remove (Erico Nunes) [Orabug: 36897779] {CVE-2024-42127}
    - tcp: Fix data races around icsk->icsk_af_ops. (Kuniyuki Iwashima) [Orabug: 34719866] {CVE-2022-3566}
    - ipv6: Fix data races around sk->sk_prot. (Kuniyuki Iwashima) [Orabug: 34719906] {CVE-2022-3567}
    - ftruncate: pass a signed offset (Arnd Bergmann) [Orabug: 36897558] {CVE-2024-42084}
    - ata: libata-core: Fix double free on error (Niklas Cassel) [Orabug: 36897374] {CVE-2024-41087}
    - drm/nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_hd_modes (Ma Ke) [Orabug: 36897380]
    {CVE-2024-41089}
    - drm/nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_ld_modes (Ma Ke) [Orabug: 36897444]
    {CVE-2024-41095}
    - net: can: j1939: Initialize unused data in j1939_send_one() (Shigeru Yoshida) [Orabug: 36897516]
    {CVE-2024-42076}
    - usb: atm: cxacru: fix endpoint checking in cxacru_bind() (Nikita Zhandarovich) [Orabug: 36897451]
    {CVE-2024-41097}
    - iio: chemical: bme680: Fix overflows in compensate() functions (Vasileios Amoiridis) [Orabug: 36897566]
    {CVE-2024-42086}
    - x86: stop playing stack games in profile_pc() (Linus Torvalds) [Orabug: 36897616] {CVE-2024-42096}
    - gpio: davinci: Validate the obtained number of IRQs (Aleksandr Mishin) [Orabug: 36897599]
    {CVE-2024-42092}
    - ALSA: emux: improve patch ioctl data validation (Oswald Buddenhagen) [Orabug: 36897624] {CVE-2024-42097}
    - net/dpaa2: Avoid explicit cpumask var allocation on stack (Dawei Li) [Orabug: 36897602] {CVE-2024-42093}
    - net/iucv: Avoid explicit cpumask var allocation on stack (Dawei Li) [Orabug: 36897608] {CVE-2024-42094}
    - drm/panel: ilitek-ili9881c: Fix warning with GPIO controllers that sleep (Laurent Pinchart) [Orabug:
    36897570] {CVE-2024-42087}
    - netfilter: nf_tables: fully validate NFT_DATA_VALUE on store to data registers (Pablo Neira Ayuso)
    [Orabug: 36897500] {CVE-2024-42070}
    - ASoC: fsl-asoc-card: set priv->pdev before using it (Elinor Montmasson) [Orabug: 36897578]
    {CVE-2024-42089}
    - drm/amdgpu: fix UBSAN warning in kv_dpm.c (Alex Deucher) [Orabug: 36835992] {CVE-2024-40987}
    - pinctrl: fix deadlock in create_pinctrl() when handling -EPROBE_DEFER (Hagar Hemdan) [Orabug: 36897586]
    {CVE-2024-42090}
    - drm/radeon: fix UBSAN warning in kv_dpm.c (Alex Deucher) [Orabug: 36835997] {CVE-2024-40988}
    - netfilter: ipset: Fix suspicious rcu_dereference_protected() (Jozsef Kadlecsik) [Orabug: 36838634]
    {CVE-2024-40993}
    - net/sched: act_api: fix possible infinite loop in tcf_idr_check_alloc() (David Ruth) [Orabug: 36836019]
    {CVE-2024-40995}
    - netns: Make get_net_ns() handle zero refcount net (Yue Haibing) [Orabug: 36835849] {CVE-2024-40958}
    - xfrm6: check ip6_dst_idev() return value in xfrm6_get_saddr() (Eric Dumazet) [Orabug: 36835852]
    {CVE-2024-40959}
    - ipv6: prevent possible NULL dereference in rt6_probe() (Eric Dumazet) [Orabug: 36835857]
    {CVE-2024-40960}
    - ipv6: prevent possible NULL deref in fib6_nh_init() (Eric Dumazet) [Orabug: 36835862] {CVE-2024-40961}
    - netrom: Fix a memory leak in nr_heartbeat_expiry() (Gavrilov Ilia) [Orabug: 36836086] {CVE-2024-41006}
    - mips: bmips: BCM6358: make sure CBR is correctly set (Christian Marangi) [Orabug: 36835870]
    {CVE-2024-40963}
    - powerpc/pseries: Enforce hcall result buffer validity and size (Nathan Lynch) [Orabug: 36835926]
    {CVE-2024-40974}
    - scsi: qedi: Fix crash while reading debugfs attribute (Manish Rangankar) [Orabug: 36835947]
    {CVE-2024-40978}
    - drop_monitor: replace spin_lock by raw_spin_lock (Wander Lairson Costa) [Orabug: 36835960]
    {CVE-2024-40980}
    - batman-adv: bypass empty buckets in batadv_purge_orig_ref() (Eric Dumazet) [Orabug: 36835966]
    {CVE-2024-40981}
    - usb-storage: alauda: Check whether the media is initialized (Shichao Lai) [Orabug: 36753734]
    {CVE-2024-38619}
    - greybus: Fix use-after-free bug in gb_interface_release due to race condition. (Sicong Huang) [Orabug:
    36835564] {CVE-2024-39495}
    - netfilter: nftables: exthdr: fix 4-byte stack OOB write (Florian Westphal) [Orabug: 35814445]
    {CVE-2023-4881} {CVE-2023-52628}
    - nilfs2: fix potential kernel bug due to lack of writeback flag waiting (Ryusuke Konishi) [Orabug:
    36774571] {CVE-2024-37078}
    - ocfs2: fix races between hole punching and AIO+DIO (Su Yue) [Orabug: 36835817] {CVE-2024-40943}
    - vmci: prevent speculation leaks by sanitizing event in event_deliver() (Hagar Gamal Halim Hemdan)
    [Orabug: 36835582] {CVE-2024-39499}
    - drm/exynos/vidi: fix memory leak in .get_modes() (Jani Nikula) [Orabug: 36835786] {CVE-2024-40932}
    - drivers: core: synchronize really_probe() and dev_uevent() (Dirk Behme) [Orabug: 36835589]
    {CVE-2024-39501}
    - ionic: fix use after netif_napi_del() (Taehee Yoo) [Orabug: 36835595] {CVE-2024-39502}
    - drm/komeda: check for error-valued pointer (Amjad Ouled-Ameur) [Orabug: 36835674] {CVE-2024-39505}
    - liquidio: Adjust a NULL pointer handling path in lio_vf_rep_copy_packet (Aleksandr Mishin) [Orabug:
    36835677] {CVE-2024-39506}
    - HID: logitech-dj: Fix memory leak in logi_dj_recv_switch_to_dj_mode() (Jose Exposito) [Orabug: 36835793]
    {CVE-2024-40934}
    - iommu: Return right value in iommu_sva_bind_device() (Lu Baolu) [Orabug: 36835824] {CVE-2024-40945}
    - HID: core: remove unnecessary WARN_ON() in implement() (Nikita Zhandarovich) [Orabug: 36835689]
    {CVE-2024-39509}
    - scsi: mpt3sas: Avoid test/set_bit() operating in non-allocated memory (Breno Leitao) [Orabug: 36835696]
    {CVE-2024-40901}
    - jfs: xattr: fix buffer overflow for invalid xattr (Greg Kroah-Hartman) [Orabug: 36835701]
    {CVE-2024-40902}
    - USB: class: cdc-wdm: Fix CPU lockup caused by excessive log messages (Alan Stern) [Orabug: 36835709]
    {CVE-2024-40904}
    - nilfs2: fix nilfs_empty_dir() misjudgment and long loop on I/O errors (Ryusuke Konishi) [Orabug:
    36774647] {CVE-2024-39469}
    - usb: gadget: f_fs: Fix race between aio_cancel() and AIO request complete (Wesley Cheng) [Orabug:
    36683255] {CVE-2024-36894}
    - ipv6: fix possible race in __fib6_drop_pcpu_from() (Eric Dumazet) [Orabug: 36835716] {CVE-2024-40905}
    - net/sched: taprio: always validate TCA_TAPRIO_ATTR_PRIOMAP (Eric Dumazet) [Orabug: 36748169]
    {CVE-2024-36974}
    - net: sched: sch_multiq: fix possible OOB write in multiq_tune() (Hangyu Hua) [Orabug: 36748177]
    {CVE-2024-36978}
    - wifi: iwlwifi: mvm: don't read past the mfuart notifcation (Emmanuel Grumbach) [Orabug: 36835808]
    {CVE-2024-40941}
    - wifi: mac80211: Fix deadlock in ieee80211_sta_ps_deliver_wakeup() (Remi Pommarel) [Orabug: 36835735]
    {CVE-2024-40912}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12610.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42154");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::developer_UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::developer_UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8:10:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
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
if (! preg(pattern:"^(7|8)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7 / 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.4.17-2136.335.4.el7uek', '5.4.17-2136.335.4.el8uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-12610');
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
    {'reference':'kernel-uek-5.4.17-2136.335.4.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.335.4.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.335.4.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.335.4.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.335.4.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2136.335.4.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-tools-libs-5.4.17-2136.335.4.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-5.4.17'},
    {'reference':'perf-5.4.17-2136.335.4.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-5.4.17'},
    {'reference':'python-perf-5.4.17-2136.335.4.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.335.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.335.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.335.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.335.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.335.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2136.335.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-tools-libs-5.4.17-2136.335.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-5.4.17'},
    {'reference':'perf-5.4.17-2136.335.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-5.4.17'},
    {'reference':'python-perf-5.4.17-2136.335.4.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.335.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.335.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.335.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.335.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.335.4.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.335.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.335.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.335.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.335.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.335.4.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'}
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
      severity   : SECURITY_HOLE,
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
