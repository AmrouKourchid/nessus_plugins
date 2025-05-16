#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12612.
##

include('compat.inc');

if (description)
{
  script_id(207001);
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

  script_name(english:"Oracle Linux 7 / 8 : Unbreakable Enterprise kernel-container (ELSA-2024-12612)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2024-12612 advisory.

    [5.4.17-2136.335.4.el8]
    - mm: memcg/slab: enable kmalloc-cg-<n> caches for x86_64. (Imran Khan)  [Orabug: 36951041]
    - printk: add kthread for long-running print (Stephen Brennan)  [Orabug: 36456582]
    - kdb: Use the passed prompt in kdb_position_cursor() (Douglas Anderson)
    - driver core: Fix uevent_show() vs driver detach race (Dan Williams)
    - pinctrl: ti: ti-iodelay: fix possible memory leak when pinctrl_enable() fails (Yang Yingliang)
    - pinctrl: ti: ti-iodelay: Drop if block with always false condition (Uwe Kleine-Konig)
    - pinctrl: single: fix possible memory leak when pinctrl_enable() fails (Yang Yingliang)
    - pinctrl: core: fix possible memory leak when pinctrl_enable() fails (Yang Yingliang)
    - ipvs: Avoid unnecessary calls to skb_is_gso_sctp (Ismael Luceno)

    [5.4.17-2136.335.3.el8]
    - MIPS: Octeon: Add PCIe link status check (Dave Kleikamp)  [Orabug: 36947196]

    [5.4.17-2136.335.2.el8]
    - drm/amdgpu: Fix signedness bug in sdma_v4_0_process_trap_irq() (Dan Carpenter)
    - net: relax socket state check at accept time. (Paolo Abeni)
    - fsnotify: clear PARENT_WATCHED flags lazily (Amir Goldstein)  [Orabug: 36922241]
    - NFSD: Increase NFSD_MAX_OPS_PER_COMPOUND (Chuck Lever)  [Orabug: 36908594]
    - x86/cpu: Avoid cpuinfo-induced IPI pileups (Paul E. McKenney)  [Orabug: 35773811]

    [5.4.17-2136.335.1.el8]
    - LTS tag: v5.4.280 (Alok Tiwari)
    - i2c: rcar: bring hardware to known state when probing (Wolfram Sang)
    - nilfs2: fix kernel bug on rename operation of broken directory (Ryusuke Konishi)
    - tcp: avoid too many retransmit packets (Eric Dumazet)
    - tcp: use signed arithmetic in tcp_rtx_probe0_timed_out() (Eric Dumazet)
    - net: tcp: fix unexcepted socket die when snd_wnd is 0 (Menglong Dong)
    - tcp: refactor tcp_retransmit_timer() (Eric Dumazet)
    - SUNRPC: Fix RPC client cleaned up the freed pipefs dentries (felix)
    - libceph: fix race between delayed_work() and ceph_monc_stop() (Ilya Dryomov)
    - ALSA: hda/realtek: Limit mic boost on VAIO PRO PX (Edson Juliano Drosdeck)
    - nvmem: meson-efuse: Fix return value of nvmem callbacks (Joy Chakraborty)
    - hpet: Support 32-bit userspace (He Zhe)
    - USB: core: Fix duplicate endpoint bug by clearing reserved bits in the descriptor (Alan Stern)
    - usb: gadget: configfs: Prevent OOB read/write in usb_string_copy() (Lee Jones)
    - USB: Add USB_QUIRK_NO_SET_INTF quirk for START BP-850k (WangYuli)
    - USB: serial: option: add Rolling RW350-GL variants (Vanillan Wang)
    - USB: serial: option: add Netprisma LCUK54 series modules (Mank Wang)
    - USB: serial: option: add support for Foxconn T99W651 (Slark Xiao)
    - USB: serial: option: add Fibocom FM350-GL (Bjorn Mork)
    - USB: serial: option: add Telit FN912 rmnet compositions (Daniele Palmas)
    - USB: serial: option: add Telit generic core-dump composition (Daniele Palmas)
    - ARM: davinci: Convert comma to semicolon (Chen Ni)
    - s390: Mark psw in __load_psw_mask() as __unitialized (Sven Schnelle)
    - udp: Set SOCK_RCU_FREE earlier in udp_lib_get_port(). (Kuniyuki Iwashima)
    - ppp: reject claimed-as-LCP but actually malformed packets (Dmitry Antipov)
    - net: ethernet: lantiq_etop: fix double free in detach (Aleksander Jan Bajkowski)
    - net: lantiq_etop: add blank line after declaration (Aleksander Jan Bajkowski)
    - octeontx2-af: Fix incorrect value output on error path in rvu_check_rsrc_availability() (Aleksandr
    Mishin)
    - tcp: fix incorrect undo caused by DSACK of TLP retransmit (Neal Cardwell)
    - tcp: add TCP_INFO status for failed client TFO (Jason Baron)
    - vfs: don't mod negative dentry count when on shrinker list (Brian Foster)
    - fs/dcache: Re-use value stored to dentry->d_flags instead of re-reading (linke li)
    - filelock: fix potential use-after-free in posix_lock_inode (Jeff Layton)
    - nilfs2: fix incorrect inode allocation from reserved inodes (Ryusuke Konishi)
    - nvme-multipath: find NUMA path only for online numa-node (Nilay Shroff)
    - ALSA: hda/realtek: Enable headset mic of JP-IK LEAP W502 with ALC897 (Jian-Hong Pan)
    - i2c: pnx: Fix potential deadlock warning from del_timer_sync() call in isr (Piotr Wojtaszczyk)
    - media: dw2102: fix a potential buffer overflow (Mauro Carvalho Chehab)
    - bnx2x: Fix multiple UBSAN array-index-out-of-bounds (Ghadi Elie Rahme)
    - drm/amdgpu/atomfirmware: silence UBSAN warning (Alex Deucher)
    - drm/nouveau: fix null pointer dereference in nouveau_connector_get_modes (Ma Ke)
    - Revert 'mm/writeback: fix possible divide-by-zero in wb_dirty_limits(), again' (Jan Kara)
    - fsnotify: Do not generate events for O_PATH file descriptors (Jan Kara)
    - can: kvaser_usb: Explicitly initialize family in leafimx driver_info struct (Jimmy Assarsson)
    - mm: optimize the redundant loop of mm_update_owner_next() (Jinliang Zheng)
    - nilfs2: add missing check for inode numbers on directory entries (Ryusuke Konishi)
    - nilfs2: fix inode number range checks (Ryusuke Konishi)
    - inet_diag: Initialize pad field in struct inet_diag_req_v2 (Shigeru Yoshida)
    - selftests: make order checking verbose in msg_zerocopy selftest (Zijian Zhang)
    - selftests: fix OOM in msg_zerocopy selftest (Zijian Zhang)
    - bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set() (Sam Sun)
    - tcp_metrics: validate source addr length (Jakub Kicinski)
    - UPSTREAM: tcp: fix DSACK undo in fast recovery to call tcp_try_to_open() (Neal Cardwell)
    - net: tcp better handling of reordering then loss cases (Yuchung Cheng)
    - tcp: add ece_ack flag to reno sack functions (Yousuk Seung)
    - tcp: tcp_mark_head_lost is only valid for sack-tcp (zhang kai)
    - s390/pkey: Wipe sensitive data on failure (Holger Dengler)
    - jffs2: Fix potential illegal address access in jffs2_free_inode (Wang Yong)
    - powerpc/xmon: Check cpu id in commands 'c#', 'dp#' and 'dx#' (Greg Kurz)
    - orangefs: fix out-of-bounds fsid access (Mike Marshall)
    - powerpc/64: Set _IO_BASE to POISON_POINTER_DELTA not 0 for CONFIG_PCI=n (Michael Ellerman)
    - i2c: i801: Annotate apanel_addr as __ro_after_init (Heiner Kallweit)
    - media: dvb-frontends: tda10048: Fix integer overflow (Ricardo Ribalda)
    - media: s2255: Use refcount_t instead of atomic_t for num_channels (Ricardo Ribalda)
    - media: dvb-frontends: tda18271c2dd: Remove casting during div (Ricardo Ribalda)
    - net: dsa: mv88e6xxx: Correct check for empty list (Simon Horman)
    - Input: ff-core - prefer struct_size over open coded arithmetic (Erick Archer)
    - firmware: dmi: Stop decoding on broken entry (Jean Delvare)
    - sctp: prefer struct_size over open coded arithmetic (Erick Archer)
    - media: dw2102: Don't translate i2c read into write (Michael Bunk)
    - drm/amd/display: Skip finding free audio for unknown engine_id (Alex Hung)
    - drm/amdgpu: Initialize timestamp for some legacy SOCs (Ma Jun)
    - scsi: qedf: Make qedf_execute_tmf() non-preemptible (John Meneghini)
    - IB/core: Implement a limit on UMAD receive List (Michael Guralnik)
    - media: dvb-usb: dib0700_devices: Add missing release_firmware() (Ricardo Ribalda)
    - media: dvb: as102-fe: Fix as10x_register_addr packing (Ricardo Ribalda)
    - drm/lima: fix shared irq handling on driver remove (Erico Nunes)
    - LTS tag: v5.4.279 (Alok Tiwari)
    - arm64: dts: rockchip: Add sound-dai-cells for RK3368 (Alex Bee)
    - ARM: dts: rockchip: rk3066a: add #sound-dai-cells to hdmi node (Johan Jonker)
    - tcp: Fix data races around icsk->icsk_af_ops. (Kuniyuki Iwashima)
    - ipv6: Fix data races around sk->sk_prot. (Kuniyuki Iwashima)
    - ipv6: annotate some data-races around sk->sk_prot (Eric Dumazet)
    - nfs: Leave pages in the pagecache if readpage failed (Matthew Wilcox (Oracle))
    - pwm: stm32: Refuse too small period requests (Uwe Kleine-Konig)
    - mtd: spinand: macronix: Add support for serial NAND flash (Jaime Liao)
    - ftruncate: pass a signed offset (Arnd Bergmann)
    - ata: libata-core: Fix double free on error (Niklas Cassel)
    - batman-adv: Don't accept TT entries for out-of-spec VIDs (Sven Eckelmann)
    - drm/nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_hd_modes (Ma Ke)
    - drm/nouveau/dispnv04: fix null pointer dereference in nv17_tv_get_ld_modes (Ma Ke)
    - hexagon: fix fadvise64_64 calling conventions (Arnd Bergmann)
    - csky, hexagon: fix broken sys_sync_file_range (Arnd Bergmann)
    - net: can: j1939: enhanced error handling for tightly received RTS messages in xtp_rx_rts_session_new
    (Oleksij Rempel)
    - net: can: j1939: recover socket queue on CAN bus error during BAM transmission (Oleksij Rempel)
    - net: can: j1939: Initialize unused data in j1939_send_one() (Shigeru Yoshida)
    - tty: mcf: MCF54418 has 10 UARTS (Jean-Michel Hautbois)
    - usb: atm: cxacru: fix endpoint checking in cxacru_bind() (Nikita Zhandarovich)
    - usb: musb: da8xx: fix a resource leak in probe() (Dan Carpenter)
    - usb: gadget: printer: SS+ support (Oliver Neukum)
    - net: usb: ax88179_178a: improve link status logs (Jose Ignacio Tornos Martinez)
    - iio: chemical: bme680: Fix sensor data read operation (Vasileios Amoiridis)
    - iio: chemical: bme680: Fix overflows in compensate() functions (Vasileios Amoiridis)
    - iio: chemical: bme680: Fix calibration data variable (Vasileios Amoiridis)
    - iio: chemical: bme680: Fix pressure value output (Vasileios Amoiridis)
    - iio: adc: ad7266: Fix variable checking bug (Fernando Yang)
    - mmc: sdhci: Do not lock spinlock around mmc_gpio_get_ro() (Adrian Hunter)
    - mmc: sdhci: Do not invert write-protect twice (Adrian Hunter)
    - mmc: sdhci-pci: Convert PCIBIOS_* return codes to errnos (Ilpo Jarvinen)
    - x86: stop playing stack games in profile_pc() (Linus Torvalds)
    - gpio: davinci: Validate the obtained number of IRQs (Aleksandr Mishin)
    - nvme: fixup comment for nvme RDMA Provider Type (Hannes Reinecke)
    - soc: ti: wkup_m3_ipc: Send NULL dummy message instead of pointer message (Andrew Davis)
    - media: dvbdev: Initialize sbuf (Ricardo Ribalda)
    - ALSA: emux: improve patch ioctl data validation (Oswald Buddenhagen)
    - net/dpaa2: Avoid explicit cpumask var allocation on stack (Dawei Li)
    - net/iucv: Avoid explicit cpumask var allocation on stack (Dawei Li)
    - mtd: partitions: redboot: Added conversion of operands to a larger type (Denis Arefev)
    - drm/panel: ilitek-ili9881c: Fix warning with GPIO controllers that sleep (Laurent Pinchart)
    - netfilter: nf_tables: fully validate NFT_DATA_VALUE on store to data registers (Pablo Neira Ayuso)
    - parisc: use correct compat recv/recvfrom syscalls (Arnd Bergmann)
    - sparc: fix old compat_sys_select() (Arnd Bergmann)
    - net: phy: micrel: add Microchip KSZ 9477 to the device table (Enguerrand de Ribaucourt)
    - net: phy: mchp: Add support for LAN8814 QUAD PHY (Divya Koppera)
    - net: dsa: microchip: fix initial port flush problem (Tristram Ha)
    - ASoC: fsl-asoc-card: set priv->pdev before using it (Elinor Montmasson)
    - netfilter: nf_tables: validate family when identifying table via handle (Pablo Neira Ayuso)
    - drm/amdgpu: fix UBSAN warning in kv_dpm.c (Alex Deucher)
    - pinctrl: rockchip: fix pinmux reset in rockchip_pmx_set (Huang-Huang Bao)
    - pinctrl: rockchip: fix pinmux bits for RK3328 GPIO3-B pins (Huang-Huang Bao)
    - pinctrl: rockchip: fix pinmux bits for RK3328 GPIO2-B pins (Huang-Huang Bao)
    - pinctrl: fix deadlock in create_pinctrl() when handling -EPROBE_DEFER (Hagar Hemdan)
    - iio: dac: ad5592r: fix temperature channel scaling value (Marc Ferland)
    - iio: dac: ad5592r: un-indent code-block for scale read (Alexandru Ardelean)
    - iio: dac: ad5592r-base: Replace indio_dev->mlock with own device lock (Sergiu Cuciurean)
    - x86/amd_nb: Check for invalid SMN reads (Yazen Ghannam)
    - PCI: Add PCI_ERROR_RESPONSE and related definitions (Naveen Naidu)
    - perf/core: Fix missing wakeup when waiting for context reference (Haifeng Xu)
    - tracing: Add MODULE_DESCRIPTION() to preemptirq_delay_test (Jeff Johnson)
    - arm64: dts: qcom: qcs404: fix bluetooth device address (Johan Hovold)
    - ARM: dts: samsung: smdk4412: fix keypad no-autorepeat (Krzysztof Kozlowski)
    - ARM: dts: samsung: exynos4412-origen: fix keypad no-autorepeat (Krzysztof Kozlowski)
    - ARM: dts: samsung: smdkv310: fix keypad no-autorepeat (Krzysztof Kozlowski)
    - i2c: ocores: set IACK bit after core is enabled (Grygorii Tertychnyi)
    - gcov: add support for GCC 14 (Peter Oberparleiter)
    - drm/radeon: fix UBSAN warning in kv_dpm.c (Alex Deucher)
    - ACPICA: Revert 'ACPICA: avoid Info: mapping multiple BARs. Your kernel is fine.' (Raju Rangoju)
    - dmaengine: ioatdma: Fix missing kmem_cache_destroy() (Nikita Shubin)
    - regulator: core: Fix modpost error 'regulator_get_regmap' undefined (Biju Das)
    - net: usb: rtl8150 fix unintiatilzed variables in rtl8150_get_link_ksettings (Oliver Neukum)
    - netfilter: ipset: Fix suspicious rcu_dereference_protected() (Jozsef Kadlecsik)
    - virtio_net: checksum offloading handling fix (Heng Qi)
    - net/sched: act_api: fix possible infinite loop in tcf_idr_check_alloc() (David Ruth)
    - net/sched: act_api: rely on rcu in tcf_idr_check_alloc (Pedro Tammela)
    - netns: Make get_net_ns() handle zero refcount net (Yue Haibing)
    - xfrm6: check ip6_dst_idev() return value in xfrm6_get_saddr() (Eric Dumazet)
    - ipv6: prevent possible NULL dereference in rt6_probe() (Eric Dumazet)
    - ipv6: prevent possible NULL deref in fib6_nh_init() (Eric Dumazet)
    - netrom: Fix a memory leak in nr_heartbeat_expiry() (Gavrilov Ilia)
    - cipso: fix total option length computation (Ondrej Mosnacek)
    - mips: bmips: BCM6358: make sure CBR is correctly set (Christian Marangi)
    - MIPS: Routerboard 532: Fix vendor retry check code (Ilpo Jarvinen)
    - PCI/PM: Avoid D3cold for HP Pavilion 17 PC/1972 PCIe Ports (Mario Limonciello)
    - udf: udftime: prevent overflow in udf_disk_stamp_to_time() (Roman Smirnov)
    - usb: misc: uss720: check for incompatible versions of the Belkin F5U002 (Alex Henrie)
    - powerpc/io: Avoid clang null pointer arithmetic warnings (Michael Ellerman)
    - powerpc/pseries: Enforce hcall result buffer validity and size (Nathan Lynch)
    - Bluetooth: ath3k: Fix multiple issues reported by checkpatch.pl (Uri Arev)
    - scsi: qedi: Fix crash while reading debugfs attribute (Manish Rangankar)
    - drop_monitor: replace spin_lock by raw_spin_lock (Wander Lairson Costa)
    - batman-adv: bypass empty buckets in batadv_purge_orig_ref() (Eric Dumazet)
    - selftests/bpf: Prevent client connect before server bind in test_tc_tunnel.sh (Alessandro Carminati (Red
    Hat))
    - rcutorture: Fix rcu_torture_one_read() pipe_count overflow comment (Paul E. McKenney)
    - i2c: at91: Fix the functionality flags of the slave-only interface (Jean Delvare)
    - usb-storage: alauda: Check whether the media is initialized (Shichao Lai)
    - greybus: Fix use-after-free bug in gb_interface_release due to race condition. (Sicong Huang)
    - netfilter: nftables: exthdr: fix 4-byte stack OOB write (Florian Westphal)
    - hugetlb_encode.h: fix undefined behaviour (34 << 26) (Matthias Goergens)
    - tick/nohz_full: Don't abuse smp_call_function_single() in tick_setup_device() (Oleg Nesterov)
    - nilfs2: fix potential kernel bug due to lack of writeback flag waiting (Ryusuke Konishi)
    - intel_th: pci: Add Lunar Lake support (Alexander Shishkin)
    - intel_th: pci: Add Meteor Lake-S support (Alexander Shishkin)
    - intel_th: pci: Add Sapphire Rapids SOC support (Alexander Shishkin)
    - intel_th: pci: Add Granite Rapids SOC support (Alexander Shishkin)
    - intel_th: pci: Add Granite Rapids support (Alexander Shishkin)
    - dmaengine: axi-dmac: fix possible race in remove() (Nuno Sa)
    - PCI: rockchip-ep: Remove wrong mask on subsys_vendor_id (Rick Wertenbroek)
    - ocfs2: fix races between hole punching and AIO+DIO (Su Yue)
    - ocfs2: use coarse time for new created files (Su Yue)
    - fs/proc: fix softlockup in __read_vmcore (Rik van Riel)
    - vmci: prevent speculation leaks by sanitizing event in event_deliver() (Hagar Gamal Halim Hemdan)
    - tracing/selftests: Fix kprobe event name test for .isra. functions (Steven Rostedt (Google))
    - drm/exynos/vidi: fix memory leak in .get_modes() (Jani Nikula)
    - drivers: core: synchronize really_probe() and dev_uevent() (Dirk Behme)
    - ionic: fix use after netif_napi_del() (Taehee Yoo)
    - net/ipv6: Fix the RT cache flush via sysctl using a previous delay (Petr Pavlu)
    - net/mlx5e: Fix features validation check for tunneled UDP (non-VXLAN) packets (Gal Pressman)
    - tcp: fix race in tcp_v6_syn_recv_sock() (Eric Dumazet)
    - drm/bridge/panel: Fix runtime warning on panel bridge release (Adam Miotk)
    - drm/komeda: check for error-valued pointer (Amjad Ouled-Ameur)
    - liquidio: Adjust a NULL pointer handling path in lio_vf_rep_copy_packet (Aleksandr Mishin)
    - HID: logitech-dj: Fix memory leak in logi_dj_recv_switch_to_dj_mode() (Jose Exposito)
    - iommu: Return right value in iommu_sva_bind_device() (Lu Baolu)
    - iommu/amd: Fix sysfs leak in iommu init (Kun(llfl))
    - HID: core: remove unnecessary WARN_ON() in implement() (Nikita Zhandarovich)
    - gpio: tqmx86: fix typo in Kconfig label (Gregor Herburger)
    - SUNRPC: return proper error from gss_wrap_req_priv (Chen Hanxiao)
    - Input: try trimming too long modalias strings (Dmitry Torokhov)
    - scsi: mpt3sas: Avoid test/set_bit() operating in non-allocated memory (Breno Leitao)
    - xhci: Apply broken streams quirk to Etron EJ188 xHCI host (Kuangyi Chiang)
    - xhci: Apply reset resume quirk to Etron EJ188 xHCI host (Kuangyi Chiang)
    - xhci: Set correct transferred length for cancelled bulk transfers (Mathias Nyman)
    - jfs: xattr: fix buffer overflow for invalid xattr (Greg Kroah-Hartman)
    - mei: me: release irq in mei_me_pci_resume error path (Tomas Winkler)
    - USB: class: cdc-wdm: Fix CPU lockup caused by excessive log messages (Alan Stern)
    - nilfs2: fix nilfs_empty_dir() misjudgment and long loop on I/O errors (Ryusuke Konishi)
    - nilfs2: return the mapped address from nilfs_get_page() (Matthew Wilcox (Oracle))
    - nilfs2: Remove check for PageError (Matthew Wilcox (Oracle))
    - selftests/mm: compaction_test: fix bogus test success on Aarch64 (Dev Jain)
    - selftests/mm: conform test to TAP format output (Muhammad Usama Anjum)
    - selftests/mm: compaction_test: fix incorrect write of zero to nr_hugepages (Dev Jain)
    - serial: sc16is7xx: fix bug in sc16is7xx_set_baud() when using prescaler (Hugo Villeneuve)
    - serial: sc16is7xx: replace hardcoded divisor value with BIT() macro (Hugo Villeneuve)
    - drm/amd/display: Handle Y carry-over in VCP X.Y calculation (George Shen)
    - ASoC: ti: davinci-mcasp: Fix race condition during probe (Joao Paulo Goncalves)
    - ASoC: ti: davinci-mcasp: Handle missing required DT properties (Peter Ujfalusi)
    - ASoC: ti: davinci-mcasp: Simplify the configuration parameter handling (Peter Ujfalusi)
    - ASoC: ti: davinci-mcasp: Remove legacy dma_request parsing (Peter Ujfalusi)
    - ASoC: ti: davinci-mcasp: Use platform_get_irq_byname_optional (Peter Ujfalusi)
    - ASoC: ti: davinci-mcasp: remove always zero of davinci_mcasp_get_dt_params (Zhang Qilong)
    - ASoC: ti: davinci-mcasp: remove redundant assignment to variable ret (Colin Ian King)
    - usb: gadget: f_fs: Fix race between aio_cancel() and AIO request complete (Wesley Cheng)
    - ipv6: fix possible race in __fib6_drop_pcpu_from() (Eric Dumazet)
    - af_unix: Annotate data-race of sk->sk_shutdown in sk_diag_fill(). (Kuniyuki Iwashima)
    - af_unix: Use skb_queue_len_lockless() in sk_diag_show_rqlen(). (Kuniyuki Iwashima)
    - af_unix: Use unix_recvq_full_lockless() in unix_stream_connect(). (Kuniyuki Iwashima)
    - af_unix: Annotate data-race of net->unx.sysctl_max_dgram_qlen. (Kuniyuki Iwashima)
    - af_unix: Annotate data-races around sk->sk_state in UNIX_DIAG. (Kuniyuki Iwashima)
    - af_unix: Annotate data-races around sk->sk_state in sendmsg() and recvmsg(). (Kuniyuki Iwashima)
    - af_unix: Annotate data-races around sk->sk_state in unix_write_space() and poll(). (Kuniyuki Iwashima)
    - af_unix: Annotate data-race of sk->sk_state in unix_inq_len(). (Kuniyuki Iwashima)
    - ptp: Fix error message on failed pin verification (Karol Kolacinski)
    - net/sched: taprio: always validate TCA_TAPRIO_ATTR_PRIOMAP (Eric Dumazet)
    - tcp: count CLOSE-WAIT sockets for TCP_MIB_CURRESTAB (Jason Xing)
    - net: sched: sch_multiq: fix possible OOB write in multiq_tune() (Hangyu Hua)
    - ipv6: sr: block BH in seg6_output_core() and seg6_input_core() (Eric Dumazet)
    - wifi: iwlwifi: mvm: don't read past the mfuart notifcation (Emmanuel Grumbach)
    - wifi: iwlwifi: dbg_ini: move iwl_dbg_tlv_free outside of debugfs ifdef (Shahar S Matityahu)
    - wifi: iwlwifi: mvm: revert gen2 TX A-MPDU size to 64 (Johannes Berg)
    - wifi: cfg80211: pmsr: use correct nla_get_uX functions (Lin Ma)
    - wifi: mac80211: Fix deadlock in ieee80211_sta_ps_deliver_wakeup() (Remi Pommarel)
    - wifi: mac80211: mesh: Fix leak of mesh_preq_queue objects (Nicolas Escande)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12612.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek-container and / or kernel-uek-container-debug packages.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container-debug");
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
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.4.17-2136.335.4.el7', '5.4.17-2136.335.4.el8'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-12612');
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
    {'reference':'kernel-uek-container-5.4.17-2136.335.4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.335.4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'},
    {'reference':'kernel-uek-container-5.4.17-2136.335.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.335.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek-container / kernel-uek-container-debug');
}
