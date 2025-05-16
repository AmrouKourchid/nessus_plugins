#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-12974.
##

include('compat.inc');

if (description)
{
  script_id(185497);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2023-1989");

  script_name(english:"Oracle Linux 7 / 8 : Unbreakable Enterprise kernel (ELSA-2023-12974)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 / 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2023-12974 advisory.

    [5.4.17-2136.325.5]
    - perf symbols: Symbol lookup with kcore can fail if multiple segments match stext (Krister Johansen)
    [Orabug: 35905508]
    - char: misc: Increase the maximum number of dynamic misc devices to 1048448 (D Scott Phillips)  [Orabug:
    35905508]
    - perf/arm-cmn: Fix invalid pointer when access dtc object sharing the same IRQ number (Tuan Phan)
    [Orabug: 35905508]
    - char: misc: increase DYNAMIC_MINORS value (Sangmoon Kim)  [Orabug: 35905508]

    [5.4.17-2136.325.4]
    - net: nfc: llcp: Add lock when modifying device list (Jeremy Cline)
    - net: dsa: mv88e6xxx: Avoid EEPROM timeout when EEPROM is absent (Fabio Estevam)
    - ima: Finish deprecation of IMA_TRUSTED_KEYRING Kconfig (Oleksandr Tymoshenko)
    - wifi: mwifiex: Fix oob check condition in mwifiex_process_rx_packet (Pin-yen Lin)
    - Revert 'PCI: qcom: Disable write access to read only registers for IP v2.3.3' (Greg Kroah-Hartman)
    - rbd: take header_rwsem in rbd_dev_refresh() only when updating (Ilya Dryomov)
    - rbd: decouple parent info read-in from updating rbd_dev (Ilya Dryomov)
    - rbd: decouple header read-in from updating rbd_dev->header (Ilya Dryomov)
    - rbd: move rbd_dev_refresh() definition (Ilya Dryomov)
    - MIPS: Alchemy: only build mmc support helpers if au1xmmc is enabled (Christoph Hellwig)
    - netfilter: ipset: Fix race between IPSET_CMD_CREATE and IPSET_CMD_SWAP (Jozsef Kadlecsik)
    - dccp: fix dccp_v4_err()/dccp_v6_err() again (Eric Dumazet)
    - fix breakage in do_rmdir() (Al Viro)  [Orabug: 35722671]
    - scsi: target: core: Fix deadlock due to recursive locking (Junxiao Bi)  [Orabug: 35761341]
    - rds: Add proper refcnt when an RDS MR references an RDS Socket (Hakon Bugge)  [Orabug: 35836949]
    - rds: Check for UAF in rds_destroy_mr (Hakon Bugge)  [Orabug: 35836949]
    - i2c: designware: Fix corrupted memory seen in the ISR (Jan Bottorff)  [Orabug: 35857601]
    - xfs: reserve less log space when recovering log intent items (Darrick J. Wong)  [Orabug: 35871840]
    - octeontx_edac: Fix mcc_edac failure at boot (Thomas Tai)  [Orabug: 35895526]
    - bpf: bpf_check() must fail when btf_linux is null (Dave Kleikamp)  [Orabug: 35899889]

    [5.4.17-2136.325.3]
    - LTS tag: v5.4.257 (Sherry Yang)
    - drm/amdgpu: fix amdgpu_cs_p1_user_fence (Christian Konig)
    - mtd: rawnand: brcmnand: Fix ECC level field setting for v7.2 controller (William Zhang)
    - ext4: fix rec_len verify error (Shida Zhang)
    - i2c: aspeed: Reset the i2c controller when timeout occurs (Tommy Huang)
    - tracefs: Add missing lockdown check to tracefs_create_dir() (Steven Rostedt (Google))
    - nfsd: fix change_info in NFSv4 RENAME replies (Jeff Layton)
    - tracing: Have option files inc the trace array ref count (Steven Rostedt (Google))
    - tracing: Have current_trace inc the trace array ref count (Steven Rostedt (Google))
    - btrfs: fix lockdep splat and potential deadlock after failure running delayed items (Filipe Manana)
    - attr: block mode changes of symlinks (Christian Brauner)
    - md/raid1: fix error: ISO C90 forbids mixed declarations (Nigel Croxon)
    - selftests: tracing: Fix to unmount tracefs for recovering environment (Masami Hiramatsu (Google))
    - btrfs: compare the correct fsid/metadata_uuid in btrfs_validate_super (Anand Jain)
    - btrfs: add a helper to read the superblock metadata_uuid (Anand Jain)
    - btrfs: move btrfs_pinned_by_swapfile prototype into volumes.h (Josef Bacik)
    - perf tools: Add an option to build without libbfd (Ian Rogers)
    - perf jevents: Make build dependency on test JSONs (John Garry)
    - tools features: Add feature test to check if libbfd has buildid support (Arnaldo Carvalho de Melo)
    - kobject: Add sanity check for kset->kobj.ktype in kset_register() (Zhen Lei)
    - media: pci: ipu3-cio2: Initialise timing struct to avoid a compiler warning (Sakari Ailus)
    - serial: cpm_uart: Avoid suspicious locking (Christophe Leroy)
    - scsi: target: iscsi: Fix buffer overflow in lio_target_nacl_info_show() (Konstantin Shelekhin)
    - usb: gadget: fsl_qe_udc: validate endpoint index for ch9 udc (Ma Ke)
    - media: pci: cx23885: replace BUG with error return (Hans Verkuil)
    - media: tuners: qt1010: replace BUG_ON with a regular error (Hans Verkuil)
    - media: az6007: Fix null-ptr-deref in az6007_i2c_xfer() (Zhang Shurong)
    - media: anysee: fix null-ptr-deref in anysee_master_xfer (Zhang Shurong)
    - media: af9005: Fix null-ptr-deref in af9005_i2c_xfer (Zhang Shurong)
    - media: dw2102: Fix null-ptr-deref in dw2102_i2c_transfer() (Zhang Shurong)
    - media: dvb-usb-v2: af9035: Fix null-ptr-deref in af9035_i2c_master_xfer (Zhang Shurong)
    - powerpc/pseries: fix possible memory leak in ibmebus_bus_init() (ruanjinjie)
    - jfs: fix invalid free of JFS_IP(ipimap)->i_imap in diUnmount (Liu Shixin via Jfs-discussion)
    - fs/jfs: prevent double-free in dbUnmount() after failed jfs_remount() (Andrew Kanner)
    - ext2: fix datatype of block number in ext2_xattr_set2() (Georg Ottinger)
    - md: raid1: fix potential OOB in raid1_remove_disk() (Zhang Shurong)
    - bus: ti-sysc: Configure uart quirks for k3 SoC (Tony Lindgren)
    - drm/exynos: fix a possible null-pointer dereference due to data race in exynos_drm_crtc_atomic_disable()
    (Tuo Li)
    - wifi: mac80211_hwsim: drop short frames (Johannes Berg)
    - alx: fix OOB-read compiler warning (GONG, Ruiqi)
    - mmc: sdhci-esdhc-imx: improve ESDHC_FLAG_ERR010450 (Giulio Benetti)
    - tpm_tis: Resend command to recover from data transfer errors (Alexander Steffen)
    - crypto: lib/mpi - avoid null pointer deref in mpi_cmp_ui() (Mark O'Donovan)
    - wifi: mwifiex: fix fortify warning (Dmitry Antipov)
    - wifi: ath9k: fix printk specifier (Dongliang Mu)
    - devlink: remove reload failed checks in params get/set callbacks (Jiri Pirko)
    - hw_breakpoint: fix single-stepping when using bpf_overflow_handler (Tomislav Novak)
    - perf/smmuv3: Enable HiSilicon Erratum 162001900 quirk for HIP08/09 (Yicong Yang)
    - ACPI: video: Add backlight=native DMI quirk for Lenovo Ideapad Z470 (Jiri Slaby (SUSE))
    - kernel/fork: beware of __put_task_struct() calling context (Wander Lairson Costa)
    - ACPICA: Add AML_NO_OPERAND_RESOLVE flag to Timer (Abhishek Mainkar)
    - locks: fix KASAN: use-after-free in trace_event_raw_event_filelock_lock (Will Shiu)
    - btrfs: output extra debug info if we failed to find an inline backref (Qu Wenruo)
    - autofs: fix memory leak of waitqueues in autofs_catatonic_mode (Fedor Pchelkin)
    - parisc: Drop loops_per_jiffy from per_cpu struct (Helge Deller)
    - drm/amd/display: Fix a bug when searching for insert_above_mpcc (Wesley Chalmers)
    - kcm: Fix error handling for SOCK_DGRAM in kcm_sendmsg(). (Kuniyuki Iwashima)
    - ixgbe: fix timestamp configuration code (Vadim Fedorenko)
    - net/tls: do not free tls_rec on async operation in bpf_exec_tx_verdict() (Liu Jian)
    - platform/mellanox: mlxbf-tmfifo: Drop jumbo frames (Liming Sun)
    - platform/mellanox: mlxbf-tmfifo: Drop the Rx packet if no more descriptors (Liming Sun)
    - kcm: Fix memory leak in error path of kcm_sendmsg() (Shigeru Yoshida)
    - r8152: check budget for r8152_poll() (Hayes Wang)
    - net: ethernet: mtk_eth_soc: fix possible NULL pointer dereference in mtk_hwlro_get_fdir_all() (Hangyu
    Hua)
    - net: ethernet: mvpp2_main: fix possible OOB write in mvpp2_ethtool_get_rxnfc() (Hangyu Hua)
    - net: ipv4: fix one memleak in __inet_del_ifa() (Liu Jian)
    - clk: imx8mm: Move 1443X/1416X PLL clock structure to common place (Anson Huang)
    - ARM: dts: BCM5301X: Extend RAM to full 256MB for Linksys EA6500 V2 (Aleksey Nasibulin)
    - usb: typec: bus: verify partner exists in typec_altmode_attention (RD Babiera)
    - usb: typec: tcpm: Refactor tcpm_handle_vdm_request (Hans de Goede)
    - usb: typec: tcpm: Refactor tcpm_handle_vdm_request payload handling (Hans de Goede)
    - perf tools: Handle old data in PERF_RECORD_ATTR (Namhyung Kim)
    - perf hists browser: Fix hierarchy mode header (Namhyung Kim)
    - mtd: rawnand: brcmnand: Fix potential false time out warning (William Zhang)
    - mtd: rawnand: brcmnand: Fix potential out-of-bounds access in oob write (William Zhang)
    - mtd: rawnand: brcmnand: Fix crash during the panic_write (William Zhang)
    - btrfs: use the correct superblock to compare fsid in btrfs_validate_super (Anand Jain)
    - btrfs: don't start transaction when joining with TRANS_JOIN_NOSTART (Filipe Manana)
    - fuse: nlookup missing decrement in fuse_direntplus_link (ruanmeisi)
    - ata: pata_ftide010: Add missing MODULE_DESCRIPTION (Damien Le Moal)
    - ata: sata_gemini: Add missing MODULE_DESCRIPTION (Damien Le Moal)
    - sh: boards: Fix CEU buffer size passed to dma_declare_coherent_memory() (Petr Tesarik)
    - net: hns3: fix the port information display when sfp is absent (Yisen Zhuang)
    - ip_tunnels: use DEV_STATS_INC() (Eric Dumazet)
    - idr: fix param name in idr_alloc_cyclic() doc (Ariel Marcovitch)
    - s390/zcrypt: don't leak memory if dev_set_name() fails (Andy Shevchenko)
    - igb: Change IGB_MIN to allow set rx/tx value between 64 and 80 (Olga Zaborska)
    - igbvf: Change IGBVF_MIN to allow set rx/tx value between 64 and 80 (Olga Zaborska)
    - igc: Change IGC_MIN to allow set rx/tx value between 64 and 80 (Olga Zaborska)
    - kcm: Destroy mutex in kcm_exit_net() (Shigeru Yoshida)
    - net: sched: sch_qfq: Fix UAF in qfq_dequeue() (valis)
    - af_unix: Fix data race around sk->sk_err. (Kuniyuki Iwashima)
    - af_unix: Fix data-races around sk->sk_shutdown. (Kuniyuki Iwashima)
    - af_unix: Fix data-race around unix_tot_inflight. (Kuniyuki Iwashima)
    - af_unix: Fix data-races around user->unix_inflight. (Kuniyuki Iwashima)
    - net: ipv6/addrconf: avoid integer underflow in ipv6_create_tempaddr (Alex Henrie)
    - veth: Fixing transmit return status for dropped packets (Liang Chen)
    - igb: disable virtualization features on 82580 (Corinna Vinschen)
    - net: read sk->sk_family once in sk_mc_loop() (Eric Dumazet)
    - ipv4: annotate data-races around fi->fib_dead (Eric Dumazet)
    - sctp: annotate data-races around sk->sk_wmem_queued (Eric Dumazet)
    - pwm: lpc32xx: Remove handling of PWM channels (Vladimir Zapolskiy)
    - watchdog: intel-mid_wdt: add MODULE_ALIAS() to allow auto-load (Raag Jadav)
    - perf top: Don't pass an ERR_PTR() directly to perf_session__delete() (Arnaldo Carvalho de Melo)
    - x86/virt: Drop unnecessary check on extended CPUID level in cpu_has_svm() (Sean Christopherson)
    - perf annotate bpf: Don't enclose non-debug code with an assert() (Arnaldo Carvalho de Melo)
    - kconfig: fix possible buffer overflow (Konstantin Meskhidze)
    - NFSv4/pnfs: minor fix for cleanup path in nfs4_get_device_info (Fedor Pchelkin)
    - soc: qcom: qmi_encdec: Restrict string length in decode (Chris Lew)
    - clk: qcom: gcc-mdm9615: use proper parent for pll0_vote clock (Dmitry Baryshkov)
    - parisc: led: Reduce CPU overhead for disk & lan LED computation (Helge Deller)
    - parisc: led: Fix LAN receive and transmit LEDs (Helge Deller)
    - lib/test_meminit: allocate pages up to order MAX_ORDER (Andrew Donnellan)
    - drm/ast: Fix DRAM init on AST2200 (Thomas Zimmermann)
    - fbdev/ep93xx-fb: Do not assign to struct fb_info.dev (Thomas Zimmermann)
    - scsi: qla2xxx: Remove unsupported ql2xenabledif option (Manish Rangankar)
    - scsi: qla2xxx: Turn off noisy message log (Quinn Tran)
    - scsi: qla2xxx: Fix erroneous link up failure (Quinn Tran)
    - scsi: qla2xxx: fix inconsistent TMF timeout (Quinn Tran)
    - net/ipv6: SKB symmetric hash should incorporate transport ports (Quan Tian)
    - drm: fix double free for gbo in drm_gem_vram_init and drm_gem_vram_create (Jia Yang)
    - udf: initialize newblock to 0 (Tom Rix)
    - usb: typec: tcpci: clear the fault status bit (Marco Felsch)
    - serial: sc16is7xx: fix broken port 0 uart init (Hugo Villeneuve)
    - sc16is7xx: Set iobase to device index (Daniel Mack)
    - cpufreq: brcmstb-avs-cpufreq: Fix -Warray-bounds bug (Gustavo A. R. Silva)
    - crypto: stm32 - fix loop iterating through scatterlist for DMA (Thomas Bourgoin)
    - s390/ipl: add missing secure/has_secure file to ipl type 'unknown' (Sven Schnelle)
    - pstore/ram: Check start of empty przs during init (Enlin Mu)
    - fsverity: skip PKCS#7 parser when keyring is empty (Eric Biggers)
    - net: handle ARPHRD_PPP in dev_is_mac_header_xmit() (Nicolas Dichtel)
    - X.509: if signature is unsupported skip validation (Thore Sommer)
    - dccp: Fix out of bounds access in DCCP error handler (Jann Horn)
    - parisc: Fix /proc/cpuinfo output for lscpu (Helge Deller)
    - procfs: block chmod on /proc/thread-self/comm (Aleksa Sarai)
    - Revert 'PCI: Mark NVIDIA T4 GPUs to avoid bus reset' (Bjorn Helgaas)
    - ntb: Fix calculation ntb_transport_tx_free_entry() (Dave Jiang)
    - ntb: Clean up tx tail index on link down (Dave Jiang)
    - ntb: Drop packets when qp link is down (Dave Jiang)
    - media: dvb: symbol fixup for dvb_attach() (Greg Kroah-Hartman)
    - xtensa: PMU: fix base address for the newer hardware (Max Filippov)
    - backlight/lv5207lp: Compare against struct fb_info.device (Thomas Zimmermann)
    - backlight/bd6107: Compare against struct fb_info.device (Thomas Zimmermann)
    - backlight/gpio_backlight: Compare against struct fb_info.device (Thomas Zimmermann)
    - ARM: OMAP2+: Fix -Warray-bounds warning in _pwrdm_state_switch() (Gustavo A. R. Silva)
    - ipmi_si: fix a memleak in try_smi_init() (Yi Yang)
    - ALSA: pcm: Fix missing fixup call in compat hw_refine ioctl (Takashi Iwai)
    - PM / devfreq: Fix leak in devfreq_dev_release() (Boris Brezillon)
    - igb: set max size RX buffer when store bad packet is enabled (Radoslaw Tyl)
    - skbuff: skb_segment, Call zero copy functions before using skbuff frags (Mohamed Khalfella)
    - igmp: limit igmpv3_newpack() packet size to IP_MAX_MTU (Eric Dumazet)
    - virtio_ring: fix avail_wrap_counter in virtqueue_add_packed (Yuan Yao)
    - cpufreq: Fix the race condition while updating the transition_task of policy (Liao Chang)
    - dmaengine: ste_dma40: Add missing IRQ check in d40_probe (ruanjinjie)
    - um: Fix hostaudio build errors (Randy Dunlap)
    - mtd: rawnand: fsmc: handle clk prepare error in fsmc_nand_resume() (Yi Yang)
    - rpmsg: glink: Add check for kstrdup (Jiasheng Jiang)
    - phy/rockchip: inno-hdmi: do not power on rk3328 post pll on reg write (Jonas Karlman)
    - phy/rockchip: inno-hdmi: round fractal pixclock in rk3328 recalc_rate (Zheng Yang)
    - phy/rockchip: inno-hdmi: use correct vco_div_5 macro on rk3328 (Jonas Karlman)
    - tracing: Fix race issue between cpu buffer write and swap (Zheng Yejian)
    - HID: multitouch: Correct devm device reference for hidinput input_dev name (Rahul Rameshbabu)
    - HID: logitech-dj: Fix error handling in logi_dj_recv_switch_to_dj_mode() (Nikita Zhandarovich)
    - RDMA/siw: Correct wrong debug message (Guoqing Jiang)
    - RDMA/siw: Balance the reference of cep->kref in the error path (Guoqing Jiang)
    - amba: bus: fix refcount leak (Peng Fan)
    - serial: tegra: handle clk prepare error in tegra_uart_hw_init() (Yi Yang)
    - scsi: fcoe: Fix potential deadlock on &fip->ctlr_lock (Chengfeng Ye)
    - scsi: core: Use 32-bit hostnum in scsi_host_lookup() (Tony Battersby)
    - media: ov2680: Fix regulators being left enabled on ov2680_power_on() errors (Hans de Goede)
    - media: ov2680: Fix vflip / hflip set functions (Hans de Goede)
    - media: ov2680: Fix ov2680_bayer_order() (Hans de Goede)
    - media: ov2680: Remove auto-gain and auto-exposure controls (Hans de Goede)
    - media: i2c: ov2680: Set V4L2_CTRL_FLAG_MODIFY_LAYOUT on flips (Dave Stevenson)
    - media: ov5640: Enable MIPI interface in ov5640_set_power_mipi() (Marek Vasut)
    - media: i2c: ov5640: Configure HVP lines in s_power callback (Lad Prabhakar)
    - USB: gadget: f_mass_storage: Fix unused variable warning (Alan Stern)
    - media: go7007: Remove redundant if statement (Colin Ian King)
    - iommu/vt-d: Fix to flush cache of PASID directory table (Yanfei Xu)
    - IB/uverbs: Fix an potential error pointer dereference (Xiang Yang)
    - driver core: test_async: fix an error code (Dan Carpenter)
    - dma-buf/sync_file: Fix docs syntax (Rob Clark)
    - coresight: tmc: Explicit type conversions to prevent integer overflow (Ruidong Tian)
    - scsi: qedf: Do not touch __user pointer in qedf_dbg_fp_int_cmd_read() directly (Oleksandr Natalenko)
    - scsi: qedf: Do not touch __user pointer in qedf_dbg_debug_cmd_read() directly (Oleksandr Natalenko)
    - scsi: qedf: Do not touch __user pointer in qedf_dbg_stop_io_on_error_cmd_read() directly (Oleksandr
    Natalenko)
    - x86/APM: drop the duplicate APM_MINOR_DEV macro (Randy Dunlap)
    - serial: sprd: Fix DMA buffer leak issue (Chunyan Zhang)
    - serial: sprd: Assign sprd_port after initialized to avoid wrong access (Chunyan Zhang)
    - serial: sprd: remove redundant sprd_port cleanup (Chunyan Zhang)
    - serial: sprd: getting port index via serial aliases only (Chunyan Zhang)
    - scsi: qla4xxx: Add length check when parsing nlattrs (Lin Ma)
    - scsi: be2iscsi: Add length check when parsing nlattrs (Lin Ma)
    - scsi: iscsi: Add strlen() check in iscsi_if_set{_host}_param() (Lin Ma)
    - usb: phy: mxs: fix getting wrong state with mxs_phy_is_otg_host() (Xu Yang)
    - media: mediatek: vcodec: Return NULL if no vdec_fb is found (Irui Wang)
    - media: cx24120: Add retval check for cx24120_message_send() (Daniil Dulov)
    - media: dvb-usb: m920x: Fix a potential memory leak in m920x_i2c_xfer() (Christophe JAILLET)
    - media: dib7000p: Fix potential division by zero (Daniil Dulov)
    - drivers: usb: smsusb: fix error handling code in smsusb_init_device (Dongliang Mu)
    - media: v4l2-core: Fix a potential resource leak in v4l2_fwnode_parse_link() (Christophe JAILLET)
    - media: v4l2-fwnode: simplify v4l2_fwnode_parse_link (Marco Felsch)
    - media: v4l2-fwnode: fix v4l2_fwnode_parse_link handling (Marco Felsch)
    - NFS: Guard against READDIR loop when entry names exceed MAXNAMELEN (Benjamin Coddington)
    - NFSD: da_addr_body field missing in some GETDEVICEINFO replies (Chuck Lever)
    - fs: lockd: avoid possible wrong NULL parameter (Su Hui)
    - jfs: validate max amount of blocks before allocation. (Alexei Filippov)
    - powerpc/iommu: Fix notifiers being shared by PCI and VIO buses (Russell Currey)
    - nfs/blocklayout: Use the passed in gfp flags (Dan Carpenter)
    - wifi: ath10k: Use RMW accessors for changing LNKCTL (Ilpo Jarvinen)
    - drm/radeon: Use RMW accessors for changing LNKCTL (Ilpo Jarvinen)
    - drm/radeon: Prefer pcie_capability_read_word() (Frederick Lawler)
    - drm/radeon: Replace numbers with PCI_EXP_LNKCTL2 definitions (Bjorn Helgaas)
    - drm/radeon: Correct Transmit Margin masks (Bjorn Helgaas)
    - drm/amdgpu: Use RMW accessors for changing LNKCTL (Ilpo Jarvinen)
    - drm/amdgpu: Prefer pcie_capability_read_word() (Frederick Lawler)
    - drm/amdgpu: Replace numbers with PCI_EXP_LNKCTL2 definitions (Bjorn Helgaas)
    - drm/amdgpu: Correct Transmit Margin masks (Bjorn Helgaas)
    - PCI: Add #defines for Enter Compliance, Transmit Margin (Bjorn Helgaas)
    - powerpc/fadump: reset dump area size if fadump memory reserve fails (Sourabh Jain)
    - clk: imx: composite-8m: fix clock pauses when set_rate would be a no-op (Ahmad Fatoum)
    - PCI/ASPM: Use RMW accessors for changing LNKCTL (Ilpo Jarvinen)
    - PCI: pciehp: Use RMW accessors for changing LNKCTL (Ilpo Jarvinen)
    - PCI: Mark NVIDIA T4 GPUs to avoid bus reset (Wu Zongyong)
    - clk: sunxi-ng: Modify mismatched function name (Zhang Jianhua)
    - drivers: clk: keystone: Fix parameter judgment in _of_pll_clk_init() (Minjie Du)
    - ipmi:ssif: Fix a memory leak when scanning for an adapter (Corey Minyard)
    - ipmi:ssif: Add check for kstrdup (Jiasheng Jiang)
    - of: unittest: Fix overlay type in apply/revert check (Geert Uytterhoeven)
    - drm/mediatek: Fix potential memory leak if vmap() fail (Sui Jingfeng)
    - audit: fix possible soft lockup in __audit_inode_child() (Gaosheng Cui)
    - smackfs: Prevent underflow in smk_set_cipso() (Dan Carpenter)
    - drm/msm/mdp5: Don't leak some plane state (Daniel Vetter)
    - ima: Remove deprecated IMA_TRUSTED_KEYRING Kconfig (Nayna Jain)
    - drm/panel: simple: Add missing connector type and pixel format for AUO T215HVN01 (Marek Vasut)
    - drm/armada: Fix off-by-one error in armada_overlay_get_property() (Geert Uytterhoeven)
    - of: unittest: fix null pointer dereferencing in of_unittest_find_node_by_name() (Ruan Jinjie)
    - drm/tegra: dpaux: Fix incorrect return value of platform_get_irq (Yangtao Li)
    - drm/tegra: Remove superfluous error messages around platform_get_irq() (Tan Zhongjun)
    - md/md-bitmap: hold 'reconfig_mutex' in backlog_store() (Yu Kuai)
    - md/bitmap: don't set max_write_behind if there is no write mostly device (Guoqing Jiang)
    - drm/amdgpu: Update min() to min_t() in 'amdgpu_info_ioctl' (Srinivasan Shanmugam)
    - arm64: dts: qcom: sdm845: Add missing RPMh power domain to GCC (Manivannan Sadhasivam)
    - ARM: dts: BCM53573: Fix Ethernet info for Luxul devices (Rafal Milecki)
    - drm: adv7511: Fix low refresh rate register for ADV7533/5 (Bogdan Togorean)
    - ARM: dts: samsung: s5pv210-smdkv210: correct ethernet reg addresses (split) (Krzysztof Kozlowski)
    - ARM: dts: s5pv210: add dummy 5V regulator for backlight on SMDKv210 (Krzysztof Kozlowski)
    - ARM: dts: s5pv210: correct ethernet unit address in SMDKV210 (Krzysztof Kozlowski)
    - ARM: dts: s5pv210: use defines for IRQ flags in SMDKV210 (Krzysztof Kozlowski)
    - ARM: dts: s5pv210: add RTC 32 KHz clock in SMDKV210 (Krzysztof Kozlowski)
    - ARM: dts: samsung: s3c6410-mini6410: correct ethernet reg addresses (split) (Krzysztof Kozlowski)
    - ARM: dts: s3c64xx: align pinctrl with dtschema (Krzysztof Kozlowski)
    - ARM: dts: s3c6410: align node SROM bus node name with dtschema in Mini6410 (Krzysztof Kozlowski)
    - ARM: dts: s3c6410: move fixed clocks under root node in Mini6410 (Krzysztof Kozlowski)
    - drm/etnaviv: fix dumping of active MMU context (Lucas Stach)
    - ARM: dts: BCM53573: Use updated 'spi-gpio' binding properties (Rafal Milecki)
    - ARM: dts: BCM53573: Add cells sizes to PCIe node (Rafal Milecki)
    - ARM: dts: BCM53573: Drop nonexistent 'default-off' LED trigger (Rafal Milecki)
    - drm/amdgpu: avoid integer overflow warning in amdgpu_device_resize_fb_bar() (Arnd Bergmann)
    - quota: fix dqput() to follow the guarantees dquot_srcu should provide (Baokun Li)
    - quota: add new helper dquot_active() (Baokun Li)
    - quota: rename dquot_active() to inode_quota_active() (Baokun Li)
    - quota: factor out dquot_write_dquot() (Baokun Li)
    - quota: avoid increasing DQST_LOOKUPS when iterating over dirty/inuse list (Chengguang Xu)
    - drm/bridge: tc358764: Fix debug print parameter order (Marek Vasut)
    - netrom: Deny concurrent connect(). (Kuniyuki Iwashima)
    - net/sched: sch_hfsc: Ensure inner classes have fsc curve (Budimir Markovic)
    - mlxsw: i2c: Limit single transaction buffer size (Vadim Pasternak)
    - mlxsw: i2c: Fix chunk size setting in output mailbox buffer (Vadim Pasternak)
    - net: arcnet: Do not call kfree_skb() under local_irq_disable() (Jinjie Ruan)
    - wifi: ath9k: use IS_ERR() with debugfs_create_dir() (Wang Ming)
    - wifi: mwifiex: avoid possible NULL skb pointer dereference (Dmitry Antipov)
    - wifi: ath9k: protect WMI command response buffer replacement with a lock (Fedor Pchelkin)
    - wifi: ath9k: fix races between ath9k_wmi_cmd and ath9k_wmi_ctrl_rx (Fedor Pchelkin)
    - wifi: mwifiex: Fix missed return in oob checks failed path (Polaris Pi)
    - wifi: mwifiex: fix memory leak in mwifiex_histogram_read() (Dmitry Antipov)
    - fs: ocfs2: namei: check return value of ocfs2_add_entry() (Artem Chernyshev)
    - lwt: Check LWTUNNEL_XMIT_CONTINUE strictly (Yan Zhai)
    - lwt: Fix return values of BPF xmit ops (Yan Zhai)
    - hwrng: iproc-rng200 - Implement suspend and resume calls (Florian Fainelli)
    - hwrng: iproc-rng200 - use semicolons rather than commas to separate statements (Julia Lawall)
    - crypto: caam - fix unchecked return value error (Gaurav Jain)
    - Bluetooth: nokia: fix value check in nokia_bluetooth_serdev_probe() (Yuanjun Gong)
    - crypto: stm32 - Properly handle pm_runtime_get failing (Uwe Kleine-Konig)
    - wifi: mwifiex: fix error recovery in PCIE buffer descriptor management (Dmitry Antipov)
    - mwifiex: switch from 'pci_' to 'dma_' API (Christophe JAILLET)
    - wifi: mwifiex: Fix OOB and integer underflow when rx packets (Polaris Pi)
    - can: gs_usb: gs_usb_receive_bulk_callback(): count RX overflow errors also in case of OOM (Marc Kleine-
    Budde)
    - spi: tegra20-sflash: fix to check return value of platform_get_irq() in tegra_sflash_probe() (Zhang
    Shurong)
    - regmap: rbtree: Use alloc_flags for memory allocations (Dan Carpenter)
    - tcp: tcp_enter_quickack_mode() should be static (Eric Dumazet)
    - bpf: Clear the probe_addr for uprobe (Yafang Shao)
    - cpufreq: powernow-k8: Use related_cpus instead of cpus in driver.exit() (Liao Chang)
    - perf/imx_ddr: don't enable counter0 if none of 4 counters are used (Xu Yang)
    - x86/decompressor: Don't rely on upper 32 bits of GPRs being preserved (Ard Biesheuvel)
    - x86/boot: Annotate local functions (Jiri Slaby)
    - x86/asm: Make more symbols local (Jiri Slaby)
    - OPP: Fix passing 0 to PTR_ERR in _opp_attach_genpd() (Manivannan Sadhasivam)
    - tmpfs: verify {g,u}id mount options correctly (Christian Brauner)
    - fs: Fix error checking for d_hash_and_lookup() (Wang Ming)
    - new helper: lookup_positive_unlocked() (Al Viro)
    - eventfd: prevent underflow for eventfd semaphores (Wen Yang)
    - eventfd: Export eventfd_ctx_do_read() (David Woodhouse)
    - reiserfs: Check the return value from __getblk() (Matthew Wilcox)
    - Revert 'net: macsec: preserve ingress frame ordering' (Sabrina Dubroca)
    - Revert 'net: macsec: Severe performance regression in '...preserve ordering'' (Sherry Yang)
    - udf: Handle error when adding extent to a file (Jan Kara)
    - udf: Check consistency of Space Bitmap Descriptor (Vladislav Efanov)
    - powerpc/32s: Fix assembler warning about r0 (Christophe Leroy)
    - net: Avoid address overwrite in kernel_connect (Jordan Rife)
    - platform/mellanox: Fix mlxbf-tmfifo not handling all virtio CONSOLE notifications (Shih-Yi Chen)
    - ALSA: seq: oss: Fix racy open/close of MIDI devices (Takashi Iwai)
    - scsi: storvsc: Always set no_report_opcodes (Michael Kelley)
    - cifs: add a warning when the in-flight count goes negative (Shyam Prasad N)
    - sctp: handle invalid error codes without calling BUG() (Dan Carpenter)
    - bnx2x: fix page fault following EEH recovery (David Christensen)
    - netlabel: fix shift wrapping bug in netlbl_catmap_setlong() (Dmitry Mastykin)
    - scsi: qedi: Fix potential deadlock on &qedi_percpu->p_work_lock (Chengfeng Ye)
    - idmaengine: make FSL_EDMA and INTEL_IDMA64 depends on HAS_IOMEM (Baoquan He)
    - net: usb: qmi_wwan: add Quectel EM05GV2 (Martin Kohn)
    - clk: fixed-mmio: make COMMON_CLK_FIXED_MMIO depend on HAS_IOMEM (Baoquan He)
    - security: keys: perform capable check only on privileged operations (Christian Gottsche)
    - platform/x86: huawei-wmi: Silence ambient light sensor (Konstantin Shelekhin)
    - platform/x86: intel: hid: Always call BTNL ACPI method (Hans de Goede)
    - ASoC: atmel: Fix the 8K sample parameter in I2SC master (Guiting Shen)
    - ASoc: codecs: ES8316: Fix DMIC config (Edgar)
    - fs/nls: make load_nls() take a const parameter (Winston Wen)
    - s390/dasd: fix hanging device after request requeue (Stefan Haberland)
    - s390/dasd: use correct number of retries for ERP requests (Stefan Haberland)
    - m68k: Fix invalid .section syntax (Ben Hutchings)
    - vxlan: generalize vxlan_parse_gpe_hdr and remove unused args (Jiri Benc)
    - ethernet: atheros: fix return value check in atl1c_tso_csum() (Yuanjun Gong)
    - ASoC: da7219: Check for failure reading AAD IRQ events (Dmytro Maluka)
    - ASoC: da7219: Flush pending AAD IRQ when suspending (Dmytro Maluka)
    - 9p: virtio: make sure 'offs' is initialized in zc_request (Dominique Martinet)
    - nilfs2: fix WARNING in mark_buffer_dirty due to discarded buffer reuse (Ryusuke Konishi)
    - nilfs2: fix general protection fault in nilfs_lookup_dirty_data_buffers() (Ryusuke Konishi)
    - fsi: master-ast-cf: Add MODULE_FIRMWARE macro (Juerg Haefliger)
    - firmware: stratix10-svc: Fix an NULL vs IS_ERR() bug in probe (Wang Ming)
    - serial: sc16is7xx: fix bug when first setting GPIO direction (Hugo Villeneuve)
    - Bluetooth: btsdio: fix use after free bug in btsdio_remove due to race condition (Zheng Wang)
    - staging: rtl8712: fix race condition (Nam Cao)
    - HID: wacom: remove the battery when the EKR is off (Aaron Armstrong Skomra)
    - USB: serial: option: add FOXCONN T99W368/T99W373 product (Slark Xiao)
    - USB: serial: option: add Quectel EM05G variant (0x030e) (Martin Kohn)
    - modules: only allow symbol_get of EXPORT_SYMBOL_GPL modules (Christoph Hellwig)
    - rtc: ds1685: use EXPORT_SYMBOL_GPL for ds1685_rtc_poweroff (Christoph Hellwig)
    - net: enetc: use EXPORT_SYMBOL_GPL for enetc_phc_index (Christoph Hellwig)
    - mmc: au1xmmc: force non-modular build and remove symbol_get usage (Christoph Hellwig)
    - ARM: pxa: remove use of symbol_get() (Arnd Bergmann)
    - erofs: ensure that the post-EOF tails are all zeroed (Gao Xiang)

    [5.4.17-2136.325.2]
    - Pensando: kpcimgr: Decouple kstate addr from shmem addr (Rob Gardner)  [Orabug: 35842998]
    - bnxt_en: fix NULL dereference in bnxt_flash_package_from_file() (Samasth Norway Ananda)  [Orabug:
    35844212]
    - uek-rpm: aarch64: embedded: Fix a typo when enabling CONFIG_STACKTRACE (Thomas Tai)  [Orabug: 35858089]
    - ocfs2: ocfs2 crash due to invalid h_next_leaf_blk value in extent block (Gautham Ananthakrishna)
    [Orabug: 35859331]

    [5.4.17-2136.325.1]
    - uek-rpm: aarch64: embedded: Enable CONFIG_STACKTRACE and CONFIG_FTRACE (Thomas Tai)  [Orabug: 35818484]
    - io_uring: add a sysctl to disable io_uring system-wide (Matteo Rizzo)  [Orabug: 35819375]
    - KVM: SVM: Set target pCPU during IRTE update if target vCPU is running (Sean Christopherson)  [Orabug:
    35827614]
    - KVM: SVM: Take and hold ir_list_lock when updating vCPU's Physical ID entry (Sean Christopherson)
    [Orabug: 35827614]
    - Pensando: kpcimgr: Zero out mod pointer unconditionally (Rob Gardner)  [Orabug: 35842963]
    - pensando: kpcimgr: Flush i-cache before calling any pciesvc code (Rob Gardner)  [Orabug: 35842972]

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-12974.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1989");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::developer_UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::developer_UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8:8:baseos_patch");
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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var fixed_uptrack_levels = ['5.4.17-2136.325.5.el7uek', '5.4.17-2136.325.5.el8uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2023-12974');
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
    {'reference':'kernel-uek-5.4.17-2136.325.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.325.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.325.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.325.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.325.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2136.325.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-tools-libs-5.4.17-2136.325.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-5.4.17'},
    {'reference':'perf-5.4.17-2136.325.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-5.4.17'},
    {'reference':'python-perf-5.4.17-2136.325.5.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.325.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.325.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.325.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.325.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.325.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2136.325.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-tools-libs-5.4.17-2136.325.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-5.4.17'},
    {'reference':'perf-5.4.17-2136.325.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-5.4.17'},
    {'reference':'python-perf-5.4.17-2136.325.5.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.325.5.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.325.5.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.325.5.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.325.5.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.325.5.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.325.5.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.325.5.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.325.5.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.325.5.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.325.5.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'}
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
