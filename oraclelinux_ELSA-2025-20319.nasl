#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2025-20319.
##

include('compat.inc');

if (description)
{
  script_id(235714);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/12");

  script_cve_id("CVE-2023-52532", "CVE-2024-36929");

  script_name(english:"Oracle Linux 7 / 8 : Unbreakable Enterprise kernel (ELSA-2025-20319)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2025-20319 advisory.

    - net: mana: Fix TX CQE error handling (Haiyang Zhang)  [Orabug: 36983924]  {CVE-2023-52532}
    - net: core: reject skb_copy(_expand) for fraglist GSO skbs (Felix Fietkau)  [Orabug: 36683418]
    {CVE-2024-36929}
    - ima: Fix use-after-free on a dentry's dname.name (Stefan Berger)  [Orabug: 36835558]  {CVE-2024-39494}
    - ipv6: fix possible UAF in ip6_finish_output2() (Eric Dumazet) [Orabug: 37029070] {CVE-2024-44986}
    - dmaengine: at_xdmac: avoid null_prt_deref in at_xdmac_prep_dma_memset (Chen Ridong) [Orabug: 37452681]
    {CVE-2024-56767}
    - media: dvb-frontends: dib3000mb: fix uninit-value in dib3000_write_reg (Nikita Zhandarovich) [Orabug:
    37452687] {CVE-2024-56769}
    - net: sched: fix ordering of qlen adjustment (Lion Ackermann) [Orabug: 37433383] {CVE-2024-53164}
    - mtd: rawnand: fix double free in atmel_pmecc_create_user() (Dan Carpenter) [Orabug: 37506347]
    {CVE-2024-56766}
    - xen/netfront: fix crash when removing device (Juergen Gross) [Orabug: 37427542] {CVE-2024-53240}
    - net: lapb: increase LAPB_HEADER_LEN (Eric Dumazet) [Orabug: 37434237] {CVE-2024-56659}
    - tipc: fix NULL deref in cleanup_bearer() (Eric Dumazet) [Orabug: 37506456] {CVE-2024-56661}
    - usb: gadget: u_serial: Fix the issue that gs_start_io crashed due to accessing null pointer (Lianqin Hu)
    [Orabug: 37434264] {CVE-2024-56670}
    - ALSA: usb-audio: Fix out of bounds reads when finding clock sources (Takashi Iwai) [Orabug: 37427489]
    {CVE-2024-53150}
    - bpf: fix OOB devmap writes when deleting elements (Maciej Fijalkowski) [Orabug: 37434047]
    {CVE-2024-56615}
    - f2fs: fix f2fs_bug_on when uninstalling filesystem call f2fs_evict_inode. (Qi Han) [Orabug: 37433861]
    {CVE-2024-56586}
    - leds: class: Protect brightness_show() with led_cdev->led_access mutex (Mukesh Ojha) [Orabug: 37433869]
    {CVE-2024-56587}
    - wifi: brcmfmac: Fix oops due to NULL pointer dereference in brcmf_sdiod_sglist_rw() (Norbert van
    Bolhuis) [Orabug: 37433908] {CVE-2024-56593}
    - drm/amdgpu: set the right AMDGPU sg segment limitation (Prike Liang) [Orabug: 37433914] {CVE-2024-56594}
    - jfs: add a check to prevent array-index-out-of-bounds in dbAdjTree (Nihar Chaithanya) [Orabug: 37433920]
    {CVE-2024-56595}
    - jfs: fix array-index-out-of-bounds in jfs_readdir (Ghanshyam Agrawal) [Orabug: 37433928]
    {CVE-2024-56596}
    - jfs: fix shift-out-of-bounds in dbSplit (Ghanshyam Agrawal) [Orabug: 37433934] {CVE-2024-56597}
    - jfs: array-index-out-of-bounds fix in dtReadFirst (Ghanshyam Agrawal) [Orabug: 37433941]
    {CVE-2024-56598}
    - net: inet6: do not leave a dangling sk pointer in inet6_create() (Ignat Korchagin) [Orabug: 37433955]
    {CVE-2024-56600}
    - net: inet: do not leave a dangling sk pointer in inet_create() (Ignat Korchagin) [Orabug: 37433962]
    {CVE-2024-56601}
    - net: ieee802154: do not leave a dangling sk pointer in ieee802154_create() (Ignat Korchagin) [Orabug:
    37433970] {CVE-2024-56602}
    - net: af_can: do not leave a dangling sk pointer in can_create() (Ignat Korchagin) [Orabug: 37433977]
    {CVE-2024-56603}
    - Bluetooth: L2CAP: do not leave dangling sk pointer on error in l2cap_sock_create() (Ignat Korchagin)
    [Orabug: 37433990] {CVE-2024-56605}
    - af_packet: avoid erroring out after sock_init_data() in packet_create() (Ignat Korchagin) [Orabug:
    37433996] {CVE-2024-56606}
    - nilfs2: fix potential out-of-bounds memory access in nilfs_find_entry() (Ryusuke Konishi) [Orabug:
    37434065] {CVE-2024-56619}
    - HID: wacom: fix when get product name maybe null pointer (WangYuli) [Orabug: 37434108] {CVE-2024-56629}
    - ocfs2: free inode when ocfs2_get_init_inode() fails (Tetsuo Handa) [Orabug: 37434113] {CVE-2024-56630}
    - tcp_bpf: Fix the sk_mem_uncharge logic in tcp_bpf_sendmsg (Zijian Zhang) [Orabug: 37434127]
    {CVE-2024-56633}
    - gpio: grgpio: Add NULL check in grgpio_probe (Charles Han) [Orabug: 37434131] {CVE-2024-56634}
    - xen: Fix the issue of resource not being properly released in xenbus_dev_probe() (Qiu-ji Chen) [Orabug:
    37433540] {CVE-2024-53198}
    - netfilter: ipset: Hold module reference while requesting a module (Phil Sutter) [Orabug: 37434143]
    {CVE-2024-56637}
    - tipc: Fix use-after-free of kernel socket in cleanup_bearer(). (Kuniyuki Iwashima) [Orabug: 37434161]
    {CVE-2024-56642}
    - dccp: Fix memory leak in dccp_feat_change_recv (Ivan Solodovnikov) [Orabug: 37434167] {CVE-2024-56643}
    - netfilter: x_tables: fix LED ID check in led_tg_check() (Dmitry Antipov) [Orabug: 37434200]
    {CVE-2024-56650}
    - nfsd: make sure exp active before svc_export_show (Yang Erkun) [Orabug: 37433745] {CVE-2024-56558}
    - i3c: master: Fix miss free init_dyn_addr at i3c_master_put_i3c_addrs() (Frank Li) [Orabug: 37433756]
    {CVE-2024-56562}
    - ad7780: fix division by zero in ad7780_write_raw() (Zicheng Qu) [Orabug: 37433772] {CVE-2024-56567}
    - ftrace: Fix regression with module command in stack_trace_filter (guoweikang) [Orabug: 37433784]
    {CVE-2024-56569}
    - ovl: Filter invalid inodes with missing lookup function (Vasiliy Kovalev) [Orabug: 37433789]
    {CVE-2024-56570}
    - media: platform: allegro-dvt: Fix possible memory leak in allocate_buffers_internal() (Gaosheng Cui)
    [Orabug: 37433798] {CVE-2024-56572}
    - media: ts2020: fix null-ptr-deref in ts2020_probe() (Li Zetao) [Orabug: 37433805] {CVE-2024-56574}
    - media: i2c: tc358743: Fix crash in the probe error path when using polling (Alexander Shiyan) [Orabug:
    37433817] {CVE-2024-56576}
    - btrfs: ref-verify: fix use-after-free after invalid ref action (Filipe Manana) [Orabug: 37433832]
    {CVE-2024-56581}
    - sh: intc: Fix use-after-free bug in register_intc_controller() (Dan Carpenter) [Orabug: 37433393]
    {CVE-2024-53165}
    - sunrpc: clear XPRT_SOCK_UPD_TIMEOUT when reset transport (Liu Jian) [Orabug: 37434314] {CVE-2024-56688}
    - 9p/xen: fix release of IRQ (Alex Zenla) [Orabug: 37434374] {CVE-2024-56704}
    - ubifs: authentication: Fix use-after-free in ubifs_tnc_end_commit (Waqar Hameed) [Orabug: 37433414]
    {CVE-2024-53171}
    - ubi: fastmap: Fix duplicate slab cache names while attaching (Zhihao Cheng) [Orabug: 37433419]
    {CVE-2024-53172}
    - rtc: check if __rtc_read_time was successful in rtc_timer_do_work() (Yongliang Gao) [Orabug: 37434456]
    {CVE-2024-56739}
    - NFSv4.0: Fix a use-after-free problem in the asynchronous open() (Trond Myklebust) [Orabug: 37433426]
    {CVE-2024-53173}
    - um: Fix potential integer overflow during physmem setup (Tiwei Bie) [Orabug: 37427464] {CVE-2024-53145}
    - SUNRPC: make sure cache entry active before cache_show (Yang Erkun) [Orabug: 37433433] {CVE-2024-53174}
    - NFSD: Prevent a potential integer overflow (Chuck Lever) [Orabug: 37427470] {CVE-2024-53146}
    - media: wl128x: Fix atomicity violation in fmc_send_cmd() (Qiu-ji Chen) [Orabug: 37434358]
    {CVE-2024-56700}
    - um: vector: Do not use drvdata in release (Tiwei Bie) [Orabug: 37433467] {CVE-2024-53181}
    - um: net: Do not use drvdata in release (Tiwei Bie) [Orabug: 37433475] {CVE-2024-53183}
    - um: ubd: Do not use drvdata in release (Tiwei Bie) [Orabug: 37433484] {CVE-2024-53184}
    - netfilter: ipset: add missing range check in bitmap_ip_uadt (Jeongjun Park) [Orabug: 37388867]
    {CVE-2024-53141}
    - comedi: Flush partial mappings in error case (Jann Horn) [Orabug: 37427482] {CVE-2024-53148}
    - PCI: Fix use-after-free of slot->bus on hot remove (Lukas Wunner) [Orabug: 37433516] {CVE-2024-53194}
    - ALSA: usb-audio: Fix potential out-of-bound accesses for Extigy and Mbox devices (Benoit Sevens)
    [Orabug: 37433532] {CVE-2024-53197}
    - vfio/pci: Properly hide first-in-list PCIe extended capability (Avihai Horon) [Orabug: 37433578]
    {CVE-2024-53214}
    - NFSD: Prevent NULL dereference in nfsd4_process_cb_update() (Chuck Lever) [Orabug: 37433594]
    {CVE-2024-53217}
    - fbdev: sh7760fb: Fix a possible memory leak in sh7760fb_alloc_mem() (Zhen Lei) [Orabug: 37434478]
    {CVE-2024-56746}
    - ocfs2: fix uninitialized value in ocfs2_file_read_iter() (Dmitry Antipov) [Orabug: 37427503]
    {CVE-2024-53155}
    - scsi: qedi: Fix a possible memory leak in qedi_alloc_and_init_sb() (Zhen Lei) [Orabug: 37434484]
    {CVE-2024-56747}
    - scsi: qedf: Fix a possible memory leak in qedf_alloc_and_init_sb() (Zhen Lei) [Orabug: 37434489]
    {CVE-2024-56748}
    - scsi: bfa: Fix use-after-free in bfad_im_module_exit() (Ye Bin) [Orabug: 37433630] {CVE-2024-53227}
    - mfd: intel_soc_pmic_bxtwc: Use IRQ domain for PMIC devices (Andy Shevchenko) [Orabug: 37434429]
    {CVE-2024-56723}
    - mfd: intel_soc_pmic_bxtwc: Use IRQ domain for TMU device (Andy Shevchenko) [Orabug: 37434434]
    {CVE-2024-56724}
    - mfd: intel_soc_pmic_bxtwc: Use IRQ domain for USB Type-C device (Andy Shevchenko) [Orabug: 37434330]
    {CVE-2024-56691}
    - ALSA: 6fire: Release resources at card release (Takashi Iwai) [Orabug: 37433660] {CVE-2024-53239}
    - ALSA: caiaq: Use snd_card_free_when_closed() at disconnection (Takashi Iwai) [Orabug: 37433666]
    {CVE-2024-56531}
    - ALSA: us122l: Use snd_card_free_when_closed() at disconnection (Takashi Iwai) [Orabug: 37433672]
    {CVE-2024-56532}
    - wifi: mwifiex: Fix memcpy() field-spanning write warning in mwifiex_config_scan() (Alper Nebi Yasak)
    [Orabug: 37433695] {CVE-2024-56539}
    - wifi: ath9k: add range check for conn_rsp_epid in htc_connect_service() (Jeongjun Park) [Orabug:
    37427509] {CVE-2024-53156}
    - firmware: arm_scpi: Check the DVFS OPP count returned by the firmware (Luo Qiu) [Orabug: 37427515]
    {CVE-2024-53157}
    - soc: qcom: geni-se: fix array underflow in geni_se_clk_tbl_get() (Dan Carpenter) [Orabug: 37427524]
    {CVE-2024-53158}
    - crypto: bcm - add error check in the ahash_hmac_init function (Chen Ridong) [Orabug: 37434298]
    {CVE-2024-56681}
    - crypto: pcrypt - Call crypto layer directly when padata_do_parallel() return -EBUSY (Yi Yang) [Orabug:
    37434323] {CVE-2024-56690}
    - EDAC/bluefield: Fix potential integer overflow (David Thompson) [Orabug: 37427533] {CVE-2024-53161}
    - hfsplus: don't query the device logical block size multiple times (Thadeu Lima de Souza Cascardo)
    [Orabug: 37433720] {CVE-2024-56548}
    - nvme-pci: fix freeing of the HMB descriptor table (Christoph Hellwig) [Orabug: 37434510]
    {CVE-2024-56756}
    - initramfs: avoid filename buffer overrun (David Disseldorp) [Orabug: 37388874] {CVE-2024-53142}
    - cifs: Fix buffer overflow when parsing NFS reparse points (Pali Rohar) [Orabug: 37206284]
    {CVE-2024-49996}
    - nilfs2: fix null-ptr-deref in block_dirty_buffer tracepoint (Ryusuke Konishi) [Orabug: 37388819]
    {CVE-2024-53130}
    - nilfs2: fix null-ptr-deref in block_touch_buffer tracepoint (Ryusuke Konishi) [Orabug: 37388825]
    {CVE-2024-53131}
    - KVM: VMX: Bury Intel PT virtualization (guest/host mode) behind CONFIG_BROKEN (Sean Christopherson)
    [Orabug: 37388846] {CVE-2024-53135}
    - ocfs2: uncache inode which has failed entering the group (Dmitry Antipov) [Orabug: 37388753]
    {CVE-2024-53112}
    - netlink: terminate outstanding dump on socket close (Jakub Kicinski) [Orabug: 37388861] {CVE-2024-53140}
    - fs: Fix uninitialized value issue in from_kuid and from_kgid (Alessandro Zanni) [Orabug: 37331928]
    {CVE-2024-53101}
    - vsock/virtio: Initialization of the dangling pointer occurring in vsk->trans (Hyunwoo Kim) [Orabug:
    37298681] {CVE-2024-50264}
    - hv_sock: Initializing vsk->trans to NULL to prevent a dangling pointer (Hyunwoo Kim) [Orabug: 37344480]
    {CVE-2024-53103}
    - ftrace: Fix possible use-after-free issue in ftrace_location() (Zheng Yejian) [Orabug: 36753574]
    {CVE-2024-38588}
    - ocfs2: remove entry once instead of null-ptr-dereference in ocfs2_xa_remove() (Andrew Kanner) [Orabug:
    37298685] {CVE-2024-50265}
    - USB: serial: io_edgeport: fix use after free in debug printk (Dan Carpenter) [Orabug: 37298695]
    {CVE-2024-50267}
    - usb: musb: sunxi: Fix accessing an released usb phy (Zijun Hu) [Orabug: 37298703] {CVE-2024-50269}
    - media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format (Benoit Sevens)
    [Orabug: 37344485] {CVE-2024-53104}
    - net: bridge: xmit: make sure we have at least eth header len bytes (Nikolay Aleksandrov) [Orabug:
    36753372] {CVE-2024-38538}
    - btrfs: reinitialize delayed ref list after deleting it from the list (Filipe Manana) [Orabug: 37298715]
    {CVE-2024-50273}
    - nfs: Fix KMSAN warning in decode_getfattr_attrs() (Roberto Sassu) [Orabug: 37304779] {CVE-2024-53066}
    - dm cache: fix potential out-of-bounds access on the first resume (Ming-Hung Tsai) [Orabug: 37298732]
    {CVE-2024-50278}
    - dm cache: fix out-of-bounds access to the dirty bitset when resizing (Ming-Hung Tsai) [Orabug: 37298737]
    {CVE-2024-50279}
    - drm/amdgpu: add missing size check in amdgpu_debugfs_gprwave_read() (Alex Deucher) [Orabug: 37298751]
    {CVE-2024-50282}
    - media: v4l2-tpg: prevent the risk of a division by zero (Mauro Carvalho Chehab) [Orabug: 37298782]
    {CVE-2024-50287}
    - media: cx24116: prevent overflows on SNR calculus (Mauro Carvalho Chehab) [Orabug: 37298797]
    {CVE-2024-50290}
    - media: s5p-jpeg: prevent buffer overflows (Mauro Carvalho Chehab) [Orabug: 37304763] {CVE-2024-53061}
    - media: dvbdev: prevent the risk of out of memory access (Mauro Carvalho Chehab) [Orabug: 37304769]
    {CVE-2024-53063}
    - net: hns3: fix kernel crash when uninstalling driver (Peiyang Wang) [Orabug: 37298811] {CVE-2024-50296}
    - sctp: properly validate chunk size in sctp_sf_ootb() (Xin Long) [Orabug: 37298820] {CVE-2024-50299}
    - security/keys: fix slab-out-of-bounds in key_task_permission (Chen Ridong) [Orabug: 37298827]
    {CVE-2024-50301}
    - HID: core: zero-initialize the report buffer (Jiri Kosina) [Orabug: 37298834] {CVE-2024-50302}
    - net/ipv6: release expired exception dst cached in socket (Jiri Wiesner) [Orabug: 37434173]
    {CVE-2024-56644}
    - objtool: Default ignore INT3 for unreachable (Peter Zijlstra)  [Orabug: 37273706] {CVE-2022-29901}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2025-20319.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52532");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7:9:UEKR6_ELS");
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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['5.4.17-2136.343.5.1.el7uek', '5.4.17-2136.343.5.1.el8uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2025-20319');
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
    {'reference':'kernel-uek-5.4.17-2136.343.5.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-container-5.4.17-2136.343.5.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.343.5.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.343.5.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.343.5.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.343.5.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.343.5.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2136.343.5.1.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.343.5.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.343.5.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.343.5.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.343.5.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.343.5.1.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.343.5.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-container-5.4.17-2136.343.5.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.343.5.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.343.5.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.343.5.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.343.5.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.343.5.1.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'}
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
