#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12151.
##

include('compat.inc');

if (description)
{
  script_id(190434);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/21");

  script_cve_id(
    "CVE-2022-29900",
    "CVE-2022-29901",
    "CVE-2023-4244",
    "CVE-2023-25775",
    "CVE-2023-45863"
  );

  script_name(english:"Oracle Linux 7 / 8 : Unbreakable Enterprise kernel (ELSA-2024-12151)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as referenced in
the ELSA-2024-12151 advisory.

    [5.4.17-2136.328.3]
    - IB/cm: Cancel mad on the DREQ event when the state is MRA_REP_RCVD (Mark Zhang)  [Orabug: 36143228]
    - KSPLICE: make sure the stack is zeroed. (Gregory Herrero)  [Orabug: 36154654]
    - sched/fair: Fix tg->load when offlining a CPU (Vincent Guittot)  [Orabug: 36185207]
    - i2c: core: Fix atomic xfer check for non-preempt config (Benjamin Bara)
    - net: Save and restore msg_namelen in sock_sendmsg (Marc Dionne)

    [5.4.17-2136.328.2]
    - LTS tag: v5.4.266 (Sherry Yang)
    - block: Don't invalidate pagecache for invalid falloc modes (Sarthak Kukreti)
    - smb: client: fix OOB in smbCalcSize() (Paulo Alcantara)
    - usb: fotg210-hcd: delete an incorrect bounds test (Dan Carpenter)
    - x86/alternatives: Sync core before enabling interrupts (Thomas Gleixner)
    - net: rfkill: gpio: set GPIO direction (Rouven Czerwinski)
    - net: 9p: avoid freeing uninit memory in p9pdu_vreadf (Fedor Pchelkin)
    - Bluetooth: hci_event: Fix not checking if HCI_OP_INQUIRY has been sent (Luiz Augusto von Dentz)
    - USB: serial: option: add Quectel RM500Q R13 firmware support (Reinhard Speyerer)
    - USB: serial: option: add Foxconn T99W265 with new baseline (Slark Xiao)
    - USB: serial: option: add Quectel EG912Y module support (Alper Ak)
    - USB: serial: ftdi_sio: update Actisense PIDs constant names (Mark Glover)
    - wifi: cfg80211: fix certs build to not depend on file order (Johannes Berg)
    - wifi: cfg80211: Add my certificate (Chen-Yu Tsai)
    - iio: adc: ti_am335x_adc: Fix return value check of tiadc_request_dma() (Wadim Egorov)
    - iio: common: ms_sensors: ms_sensors_i2c: fix humidity conversion time table (Javier Carrasco)
    - scsi: bnx2fc: Fix skb double free in bnx2fc_rcv() (Wei Yongjun)
    - Input: ipaq-micro-keys - add error handling for devm_kmemdup (Haoran Liu)
    - iio: imu: inv_mpu6050: fix an error code problem in inv_mpu6050_read_raw (Su Hui)
    - interconnect: Treat xlate() returning NULL node as an error (Mike Tipton)
    - btrfs: do not allow non subvolume root targets for snapshot (Josef Bacik)
    - smb: client: fix NULL deref in asn1_ber_decoder() (Paulo Alcantara)
    - ALSA: hda/hdmi: add force-connect quirk for NUC5CPYB (Kai Vehmanen)
    - ALSA: hda/hdmi: Add quirk to force pin connectivity on NUC10 (Kai Vehmanen)
    - pinctrl: at91-pio4: use dedicated lock class for IRQ (Alexis Lothore)
    - i2c: aspeed: Handle the coalesced stop conditions with the start conditions. (Quan Nguyen)
    - afs: Fix overwriting of result of DNS query (David Howells)
    - net: check dev->gso_max_size in gso_features_check() (Eric Dumazet)
    - net: warn if gso_type isn't set for a GSO SKB (Heiner Kallweit)
    - afs: Fix dynamic root lookup DNS check (David Howells)
    - afs: Fix the dynamic root's d_delete to always delete unused dentries (David Howells)
    - net: check vlan filter feature in vlan_vids_add_by_dev() and vlan_vids_del_by_dev() (Liu Jian)
    - net/rose: fix races in rose_kill_by_device() (Eric Dumazet)
    - ethernet: atheros: fix a memleak in atl1e_setup_ring_resources (Zhipeng Lu)
    - net: sched: ife: fix potential use-after-free (Eric Dumazet)
    - net/mlx5e: Correct snprintf truncation handling for fw_version buffer used by representors (Rahul
    Rameshbabu)
    - net/mlx5: Fix fw tracer first block check (Moshe Shemesh)
    - net/mlx5: improve some comments (Hu Haowen)
    - Revert 'net/mlx5e: fix double free of encap_header' (Vlad Buslov)
    - wifi: mac80211: mesh_plink: fix matches_local logic (Johannes Berg)
    - s390/vx: fix save/restore of fpu kernel context (Heiko Carstens)
    - reset: Fix crash when freeing non-existent optional resets (Geert Uytterhoeven)
    - ARM: OMAP2+: Fix null pointer dereference and memory leak in omap_soc_device_init (Kunwu Chan)
    - ksmbd: fix wrong name of SMB2_CREATE_ALLOCATION_SIZE (Namjae Jeon)
    - ALSA: hda/realtek: Enable headset on Lenovo M90 Gen5 (Bin Li)
    - LTS tag: v5.4.265 (Sherry Yang)
    - powerpc/ftrace: Fix stack teardown in ftrace_no_trace (Naveen N Rao)
    - powerpc/ftrace: Create a dummy stackframe to fix stack unwind (Naveen N Rao)
    - mmc: block: Be sure to wait while busy in CQE error recovery (Adrian Hunter)
    - ring-buffer: Fix memory leak of free page (Steven Rostedt (Google))
    - team: Fix use-after-free when an option instance allocation fails (Florent Revest)
    - arm64: mm: Always make sw-dirty PTEs hw-dirty in pte_modify (James Houghton)
    - ext4: prevent the normalized size from exceeding EXT_MAX_BLOCKS (Baokun Li)
    - soundwire: stream: fix NULL pointer dereference for multi_link (Krzysztof Kozlowski)
    - HID: hid-asus: add const to read-only outgoing usb buffer (Denis Benato)
    - net: usb: qmi_wwan: claim interface 4 for ZTE MF290 (Lech Perczak)
    - asm-generic: qspinlock: fix queued_spin_value_unlocked() implementation (Linus Torvalds)
    - HID: multitouch: Add quirk for HONOR GLO-GXXX touchpad (Aoba K)
    - HID: hid-asus: reset the backlight brightness level on resume (Denis Benato)
    - HID: add ALWAYS_POLL quirk for Apple kb (Oliver Neukum)
    - platform/x86: intel_telemetry: Fix kernel doc descriptions (Andy Shevchenko)
    - bcache: avoid NULL checking to c->root in run_cache_set() (Coly Li)
    - bcache: add code comments for bch_btree_node_get() and __bch_btree_node_alloc() (Coly Li)
    - bcache: avoid oversize memory allocation by small stripe_size (Coly Li)
    - blk-throttle: fix lockdep warning of 'cgroup_mutex or RCU read lock required!' (Ming Lei)
    - usb: aqc111: check packet for fixup for true limit (Oliver Neukum)
    - ALSA: hda/hdmi: add force-connect quirks for ASUSTeK Z170 variants (Kai Vehmanen)
    - appletalk: Fix Use-After-Free in atalk_ioctl (Hyunwoo Kim)
    - net: stmmac: Handle disabled MDIO busses from devicetree (Andrew Halaney)
    - net: stmmac: use dev_err_probe() for reporting mdio bus registration failure (Rasmus Villemoes)
    - vsock/virtio: Fix unsigned integer wrap around in virtio_transport_has_space() (Nikolay Kuratov)
    - sign-file: Fix incorrect return values check (Yusong Gao)
    - net: Remove acked SYN flag from packet in the transmit queue correctly (Dong Chenchen)
    - qed: Fix a potential use-after-free in qed_cxt_tables_alloc (Dinghao Liu)
    - net/rose: Fix Use-After-Free in rose_ioctl (Hyunwoo Kim)
    - atm: Fix Use-After-Free in do_vcc_ioctl (Hyunwoo Kim)
    - atm: solos-pci: Fix potential deadlock on &tx_queue_lock (Chengfeng Ye)
    - atm: solos-pci: Fix potential deadlock on &cli_queue_lock (Chengfeng Ye)
    - qca_spi: Fix reset behavior (Stefan Wahren)
    - qca_debug: Fix ethtool -G iface tx behavior (Stefan Wahren)
    - qca_debug: Prevent crash on TX ring changes (Stefan Wahren)
    - net: ipv6: support reporting otherwise unknown prefix flags in RTM_NEWPREFIX (Maciej Zenczykowski)
    - afs: Fix refcount underflow from error handling race (David Howells)
    - LTS tag: v5.4.264 (Sherry Yang)
    - devcoredump: Send uevent once devcd is ready (Mukesh Ojha)
    - devcoredump : Serialize devcd_del work (Mukesh Ojha)
    - smb: client: fix potential NULL deref in parse_dfs_referrals() (Paulo Alcantara)
    - cifs: Fix non-availability of dedup breaking generic/304 (David Howells)
    - Revert 'btrfs: add dmesg output for first mount and last unmount of a filesystem' (Greg Kroah-Hartman)
    - drop_monitor: Require 'CAP_SYS_ADMIN' when joining 'events' group (Ido Schimmel)
    - psample: Require 'CAP_NET_ADMIN' when joining 'packets' group (Ido Schimmel)
    - genetlink: add CAP_NET_ADMIN test for multicast bind (Ido Schimmel)
    - netlink: don't call ->netlink_bind with table lock held (Ido Schimmel)
    - io_uring/af_unix: disable sending io_uring over sockets (Pavel Begunkov)
    - nilfs2: fix missing error check for sb_set_blocksize call (Ryusuke Konishi)
    - KVM: s390/mm: Properly reset no-dat (Claudio Imbrenda)
    - x86/CPU/AMD: Check vendor in the AMD microcode callback (Borislav Petkov (AMD))
    - serial: 8250_omap: Add earlycon support for the AM654 UART controller (Ronald Wahl)
    - serial: sc16is7xx: address RX timeout interrupt errata (Daniel Mack)
    - ARM: PL011: Fix DMA support (Arnd Bergmann)
    - usb: typec: class: fix typec_altmode_put_partner to put plugs (RD Babiera)
    - parport: Add support for Brainboxes IX/UC/PX parallel cards (Cameron Williams)
    - usb: gadget: f_hid: fix report descriptor allocation (Konstantin Aladyshev)
    - mmc: sdhci-sprd: Fix vqmmc not shutting down after the card was pulled (Wenchao Chen)
    - mmc: core: add helpers mmc_regulator_enable/disable_vqmmc (Heiner Kallweit)
    - gpiolib: sysfs: Fix error handling on failed export (Boerge Struempfel)
    - arm64: dts: mediatek: mt8173-evb: Fix regulator-fixed node names (AngeloGioacchino Del Regno)
    - arm64: dts: mediatek: mt7622: fix memory node warning check (Eugen Hristev)
    - packet: Move reference count in packet_sock to atomic_long_t (Daniel Borkmann)
    - tracing: Fix a possible race when disabling buffered events (Petr Pavlu)
    - tracing: Fix incomplete locking when disabling buffered events (Petr Pavlu)
    - tracing: Always update snapshot buffer size (Steven Rostedt (Google))
    - nilfs2: prevent WARNING in nilfs_sufile_set_segment_usage() (Ryusuke Konishi)
    - ALSA: pcm: fix out-of-bounds in snd_pcm_state_names (Jason Zhang)
    - ARM: dts: imx7: Declare timers compatible with fsl,imx6dl-gpt (Philipp Zabel)
    - ARM: dts: imx: make gpt node name generic (Anson Huang)
    - ARM: imx: Check return value of devm_kasprintf in imx_mmdc_perf_init (Kunwu Chan)
    - scsi: be2iscsi: Fix a memleak in beiscsi_init_wrb_handle() (Dinghao Liu)
    - tracing: Fix a warning when allocating buffered events fails (Petr Pavlu)
    - ASoC: wm_adsp: fix memleak in wm_adsp_buffer_populate (Dinghao Liu)
    - hwmon: (acpi_power_meter) Fix 4.29 MW bug (Armin Wolf)
    - RDMA/bnxt_re: Correct module description string (Kalesh AP)
    - bpf: sockmap, updating the sg structure should also update curr (John Fastabend)
    - tcp: do not accept ACK of bytes we never sent (Eric Dumazet)
    - netfilter: xt_owner: Fix for unsafe access of sk->sk_socket (Phil Sutter)
    - net: hns: fix fake link up on xge port (Yonglong Liu)
    - ipv4: ip_gre: Avoid skb_pull() failure in ipgre_xmit() (Shigeru Yoshida)
    - arcnet: restoring support for multiple Sohard Arcnet cards (Thomas Reichinger)
    - net: arcnet: com20020 fix error handling (Tong Zhang)
    - net: arcnet: Fix RESET flag handling (Ahmed S. Darwish)
    - hv_netvsc: rndis_filter needs to select NLS (Randy Dunlap)
    - ipv6: fix potential NULL deref in fib6_add() (Eric Dumazet)
    - of: dynamic: Fix of_reconfig_get_state_change() return value documentation (Luca Ceresoli)
    - of: Add missing 'Return' section in kerneldoc comments (Rob Herring)
    - of: Fix kerneldoc output formatting (Rob Herring)
    - of: base: Fix some formatting issues and provide missing descriptions (Lee Jones)
    - of/irq: Make of_msi_map_rid() PCI bus agnostic (Lorenzo Pieralisi)
    - of/irq: make of_msi_map_get_device_domain() bus agnostic (Diana Craciun)
    - of/iommu: Make of_map_rid() PCI agnostic (Lorenzo Pieralisi)
    - ACPI/IORT: Make iort_msi_map_rid() PCI agnostic (Lorenzo Pieralisi)
    - ACPI/IORT: Make iort_get_device_domain IRQ domain agnostic (Lorenzo Pieralisi)
    - of: base: Add of_get_cpu_state_node() to get idle states for a CPU node (Ulf Hansson)
    - drm/amdgpu: correct chunk_ptr to a pointer to chunk. (YuanShang)
    - kconfig: fix memory leak from range properties (Masahiro Yamada)
    - tg3: Increment tx_dropped in tg3_tso_bug() (Alex Pakhunov)
    - tg3: Move the [rt]x_dropped counters to tg3_napi (Alex Pakhunov)
    - netfilter: ipset: fix race condition between swap/destroy and kernel side add/del/test (Jozsef
    Kadlecsik)
    - LTS tag: v5.4.263 (Sherry Yang)
    - mmc: block: Retry commands in CQE error recovery (Adrian Hunter)
    - mmc: core: convert comma to semicolon (Zheng Yongjun)
    - mmc: cqhci: Fix task clearing in CQE error recovery (Adrian Hunter)
    - mmc: cqhci: Warn of halt or task clear failure (Adrian Hunter)
    - mmc: cqhci: Increase recovery halt timeout (Adrian Hunter)
    - cpufreq: imx6q: Don't disable 792 Mhz OPP unnecessarily (Christoph Niedermaier)
    - cpufreq: imx6q: don't warn for disabling a non-existing frequency (Christoph Niedermaier)
    - scsi: qla2xxx: Fix system crash due to bad pointer access (Quinn Tran)
    - scsi: qla2xxx: Use scsi_cmd_to_rq() instead of scsi_cmnd.request (Bart Van Assche)
    - scsi: core: Introduce the scsi_cmd_to_rq() function (Bart Van Assche)
    - ima: detect changes to the backing overlay file (Mimi Zohar)
    - ovl: skip overlayfs superblocks at global sync (Konstantin Khlebnikov)
    - ima: annotate iint mutex to avoid lockdep false positive warnings (Amir Goldstein)
    - fbdev: stifb: Make the STI next font pointer a 32-bit signed offset (Helge Deller)
    - mtd: cfi_cmdset_0001: Byte swap OTP info (Linus Walleij)
    - mtd: cfi_cmdset_0001: Support the absence of protection registers (Jean-Philippe Brucker)
    - s390/cmma: fix detection of DAT pages (Heiko Carstens)
    - s390/mm: fix phys vs virt confusion in mark_kernel_pXd() functions family (Alexander Gordeev)
    - smb3: fix touch -h of symlink (Steve French)
    - net: ravb: Start TX queues after HW initialization succeeded (Claudiu Beznea)
    - net: ravb: Use pm_runtime_resume_and_get() (Claudiu Beznea)
    - ravb: Fix races between ravb_tx_timeout_work() and net related ops (Yoshihiro Shimoda)
    - net: stmmac: xgmac: Disable FPE MMC interrupts (Furong Xu)
    - ipv4: igmp: fix refcnt uaf issue when receiving igmp query packet (Zhengchao Shao)
    - Input: xpad - add HyperX Clutch Gladiate Support (Max Nguyen)
    - btrfs: make error messages more clear when getting a chunk map (Filipe Manana)
    - btrfs: send: ensure send_fd is writable (Jann Horn)
    - btrfs: fix off-by-one when checking chunk map includes logical address (Filipe Manana)
    - btrfs: add dmesg output for first mount and last unmount of a filesystem (Qu Wenruo)
    - powerpc: Don't clobber f0/vs0 during fp|altivec register save (Timothy Pearson)
    - bcache: revert replacing IS_ERR_OR_NULL with IS_ERR (Markus Weippert)
    - dm verity: don't perform FEC for failed readahead IO (Wu Bo)
    - dm-verity: align struct dm_verity_fec_io properly (Mikulas Patocka)
    - ALSA: hda/realtek: Add supported ALC257 for ChromeOS (Kailang Yang)
    - ALSA: hda/realtek: Headset Mic VREF to 100% (Kailang Yang)
    - ALSA: hda: Disable power-save on KONTRON SinglePC (Takashi Iwai)
    - mmc: block: Do not lose cache flush during CQE error recovery (Adrian Hunter)
    - firewire: core: fix possible memory leak in create_units() (Yang Yingliang)
    - pinctrl: avoid reload of p state in list iteration (Maria Yu)
    - io_uring: fix off-by one bvec index (Keith Busch)
    - USB: dwc3: qcom: fix wakeup after probe deferral (Johan Hovold)
    - USB: dwc3: qcom: fix resource leaks on probe deferral (Johan Hovold)
    - usb: dwc3: set the dma max_seg_size (Ricardo Ribalda)
    - USB: dwc2: write HCINT with INTMASK applied (Oliver Neukum)
    - USB: serial: option: don't claim interface 4 for ZTE MF290 (Lech Perczak)
    - USB: serial: option: fix FM101R-GL defines (Puliang Lu)
    - USB: serial: option: add Fibocom L7xx modules (Victor Fragoso)
    - bcache: prevent potential division by zero error (Rand Deeb)
    - bcache: check return value from btree_node_alloc_replacement() (Coly Li)
    - dm-delay: fix a race between delay_presuspend and delay_bio (Mikulas Patocka)
    - hv_netvsc: Mark VF as slave before exposing it to user-mode (Long Li)
    - hv_netvsc: Fix race of register_netdevice_notifier and VF register (Haiyang Zhang)
    - USB: serial: option: add Luat Air72*U series products (Asuna Yang)
    - s390/dasd: protect device queue against concurrent access (Jan Hoppner)
    - bcache: replace a mistaken IS_ERR() by IS_ERR_OR_NULL() in btree_gc_coalesce() (Coly Li)
    - ACPI: resource: Skip IRQ override on ASUS ExpertBook B1402CVA (Hans de Goede)
    - ext4: make sure allocate pending entry not fail (Zhang Yi)
    - ext4: fix slab-use-after-free in ext4_es_insert_extent() (Baokun Li)
    - ext4: using nofail preallocation in ext4_es_insert_extent() (Baokun Li)
    - ext4: using nofail preallocation in ext4_es_insert_delayed_block() (Baokun Li)
    - ext4: using nofail preallocation in ext4_es_remove_extent() (Baokun Li)
    - ext4: use pre-allocated es in __es_remove_extent() (Baokun Li)
    - ext4: use pre-allocated es in __es_insert_extent() (Baokun Li)
    - ext4: factor out __es_alloc_extent() and __es_free_extent() (Baokun Li)
    - ext4: add a new helper to check if es must be kept (Baokun Li)
    - MIPS: KVM: Fix a build warning about variable set but not used (Huacai Chen)
    - nvmet: nul-terminate the NQNs passed in the connect command (Christoph Hellwig)
    - nvmet: remove unnecessary ctrl parameter (Chaitanya Kulkarni)
    - afs: Fix file locking on R/O volumes to operate in local mode (David Howells)
    - afs: Return ENOENT if no cell DNS record can be found (David Howells)
    - net: axienet: Fix check for partial TX checksum (Samuel Holland)
    - amd-xgbe: propagate the correct speed and duplex status (Raju Rangoju)
    - amd-xgbe: handle the corner-case during tx completion (Raju Rangoju)
    - amd-xgbe: handle corner-case during sfp hotplug (Raju Rangoju)
    - arm/xen: fix xen_vcpu_info allocation alignment (Stefano Stabellini)
    - net: usb: ax88179_178a: fix failed operations during ax88179_reset (Jose Ignacio Tornos Martinez)
    - ipv4: Correct/silence an endian warning in __ip_do_redirect (Kunwu Chan)
    - HID: fix HID device resource race between HID core and debugging support (Charles Yi)
    - HID: core: store the unique system identifier in hid_device (Benjamin Tissoires)
    - drm/rockchip: vop: Fix color for RGB888/BGR888 format on VOP full (Jonas Karlman)
    - ata: pata_isapnp: Add missing error check for devm_ioport_map() (Chen Ni)
    - drm/panel: simple: Fix Innolux G101ICE-L01 timings (Marek Vasut)
    - drm/panel: simple: Fix Innolux G101ICE-L01 bus flags (Marek Vasut)
    - afs: Make error on cell lookup failure consistent with OpenAFS (David Howells)
    - PCI: keystone: Drop __init from ks_pcie_add_pcie_{ep,port}() (Nathan Chancellor)
    - RDMA/irdma: Prevent zero-length STAG registration (Christopher Bednarz)
    - driver core: Release all resources during unbind before updating device links (Saravana Kannan)
    - LTS tag: v5.4.262 (Sherry Yang)
    - netfilter: nf_tables: bogus EBUSY when deleting flowtable after flush (for 5.4) (Pablo Neira Ayuso)
    - netfilter: nf_tables: disable toggling dormant table state more than once (Pablo Neira Ayuso)
    - netfilter: nf_tables: fix table flag updates (Pablo Neira Ayuso)
    - netfilter: nftables: update table flags from the commit phase (Pablo Neira Ayuso)
    - netfilter: nf_tables: double hook unregistration in netns path (Pablo Neira Ayuso)
    - netfilter: nf_tables: unregister flowtable hooks on netns exit (Pablo Neira Ayuso)
    - netfilter: nf_tables: fix memleak when more than 255 elements expired (Pablo Neira Ayuso)
    - netfilter: nft_set_hash: try later when GC hits EAGAIN on iteration (Pablo Neira Ayuso)
    - netfilter: nft_set_rbtree: use read spinlock to avoid datapath contention (Pablo Neira Ayuso)
    - netfilter: nft_set_rbtree: skip sync GC for new elements in this transaction (Pablo Neira Ayuso)
    - netfilter: nf_tables: defer gc run if previous batch is still pending (Florian Westphal)
    - netfilter: nf_tables: use correct lock to protect gc_list (Pablo Neira Ayuso)
    - netfilter: nf_tables: GC transaction race with abort path (Pablo Neira Ayuso)
    - netfilter: nf_tables: GC transaction race with netns dismantle (Pablo Neira Ayuso)
    - netfilter: nf_tables: fix GC transaction races with netns and netlink event exit path (Pablo Neira
    Ayuso)
    - netfilter: nf_tables: remove busy mark and gc batch API (Pablo Neira Ayuso)
    - netfilter: nft_set_hash: mark set element as dead when deleting from packet path (Pablo Neira Ayuso)
    - netfilter: nf_tables: adapt set backend to use GC transaction API (Pablo Neira Ayuso)
    - netfilter: nf_tables: GC transaction API to avoid race with control plane (Pablo Neira Ayuso)
    - netfilter: nf_tables: don't skip expired elements during walk (Florian Westphal)
    - netfilter: nft_set_rbtree: fix overlap expiration walk (Florian Westphal)
    - netfilter: nft_set_rbtree: fix null deref on element insertion (Florian Westphal)
    - netfilter: nft_set_rbtree: Switch to node list walk for overlap detection (Pablo Neira Ayuso)
    - netfilter: nf_tables: drop map element references from preparation phase (Pablo Neira Ayuso)
    - netfilter: nftables: rename set element data activation/deactivation functions (Pablo Neira Ayuso)
    - netfilter: nf_tables: pass context to nft_set_destroy() (Pablo Neira Ayuso)
    - drm/amdgpu: fix error handling in amdgpu_bo_list_get() (Christian Konig)
    - ext4: remove gdb backup copy for meta bg in setup_new_flex_group_blocks (Kemeng Shi)
    - ext4: correct the start block of counting reserved clusters (Zhang Yi)
    - ext4: correct return value of ext4_convert_meta_bg (Kemeng Shi)
    - ext4: correct offset of gdb backup in non meta_bg group to update_backups (Kemeng Shi)
    - ext4: apply umask if ACL support is disabled (Max Kellermann)
    - Revert 'net: r8169: Disable multicast filter for RTL8168H and RTL8107E' (Heiner Kallweit)
    - nfsd: fix file memleak on client_opens_release (Mahmoud Adam)
    - media: venus: hfi: add checks to handle capabilities from firmware (Vikash Garodia)
    - media: venus: hfi: fix the check to handle session buffer requirement (Vikash Garodia)
    - media: venus: hfi_parser: Add check to keep the number of codecs within range (Vikash Garodia)
    - media: sharp: fix sharp encoding (Sean Young)
    - media: lirc: drop trailing space from scancode transmit (Sean Young)
    - i2c: i801: fix potential race in i801_block_transaction_byte_by_byte (Heiner Kallweit)
    - net: dsa: lan9303: consequently nested-lock physical MDIO (Alexander Sverdlin)
    - Revert ncsi: Propagate carrier gain/loss events to the NCSI controller (Johnathan Mantey)
    - Bluetooth: btusb: Add 0bda:b85b for Fn-Link RTL8852BE (Guan Wentao)
    - Bluetooth: btusb: Add RTW8852BE device 13d3:3570 to device tables (Masum Reza)
    - bluetooth: Add device 13d3:3571 to device tables (Larry Finger)
    - bluetooth: Add device 0bda:887b to device tables (Larry Finger)
    - Bluetooth: btusb: Add Realtek RTL8852BE support ID 0x0cb8:0xc559 (Artem Lukyanov)
    - Bluetooth: btusb: add Realtek 8822CE to usb_device_id table (Joseph Hwang)
    - Bluetooth: btusb: Add flag to define wideband speech capability (Alain Michaud)
    - tty: serial: meson: fix hard LOCKUP on crtscts mode (Pavel Krasavin)
    - serial: meson: Use platform_get_irq() to get the interrupt (Lad Prabhakar)
    - tty: serial: meson: retrieve port FIFO size from DT (Neil Armstrong)
    - serial: meson: remove redundant initialization of variable id (Colin Ian King)
    - ALSA: hda/realtek - Enable internal speaker of ASUS K6500ZC (Chandradeep Dey)
    - ALSA: info: Fix potential deadlock at disconnection (Takashi Iwai)
    - parisc/pgtable: Do not drop upper 5 address bits of physical address (Helge Deller)
    - parisc: Prevent booting 64-bit kernels on PA1.x machines (Helge Deller)
    - i3c: master: cdns: Fix reading status register (Joshua Yeong)
    - mm/cma: use nth_page() in place of direct struct page manipulation (Zi Yan)
    - dmaengine: stm32-mdma: correct desc prep when channel running (Alain Volmat)
    - mcb: fix error handling for different scenarios when parsing (Sanjuan Garcia, Jorge)
    - i2c: core: Run atomic i2c xfer when !preemptible (Benjamin Bara)
    - kernel/reboot: emergency_restart: Set correct system_state (Benjamin Bara)
    - quota: explicitly forbid quota files from being encrypted (Eric Biggers)
    - jbd2: fix potential data lost in recovering journal raced with synchronizing fs bdev (Zhihao Cheng)
    - btrfs: don't arbitrarily slow down delalloc if we're committing (Josef Bacik)
    - PM: hibernate: Clean up sync_read handling in snapshot_write_next() (Brian Geffon)
    - PM: hibernate: Use __get_safe_page() rather than touching the list (Brian Geffon)
    - mmc: vub300: fix an error code (Dan Carpenter)
    - clk: qcom: ipq8074: drop the CLK_SET_RATE_PARENT flag from PLL clocks (Kathiravan Thirumoorthy)
    - parisc/pdc: Add width field to struct pdc_model (Helge Deller)
    - PCI: keystone: Don't discard .probe() callback (Uwe Kleine-Konig)
    - PCI: keystone: Don't discard .remove() callback (Uwe Kleine-Konig)
    - genirq/generic_chip: Make irq_remove_generic_chip() irqdomain aware (Herve Codina)
    - mmc: meson-gx: Remove setting of CMD_CFG_ERROR (Rong Chen)
    - ACPI: resource: Do IRQ override on TongFang GMxXGxx (Werner Sembach)
    - PCI/sysfs: Protect driver's D3cold preference from user space (Lukas Wunner)
    - hvc/xen: fix error path in xen_hvc_init() to always register frontend driver (David Woodhouse)
    - audit: don't WARN_ON_ONCE(!current->mm) in audit_exe_compare() (Paul Moore)
    - audit: don't take task_lock() in audit_exe_compare() code path (Paul Moore)
    - KVM: x86: Ignore MSR_AMD64_TW_CFG access (Maciej S. Szmigiero)
    - KVM: x86: hyper-v: Don't auto-enable stimer on write from user-space (Nicolas Saenz Julienne)
    - x86/cpu/hygon: Fix the CPU topology evaluation for real (Pu Wen)
    - scsi: megaraid_sas: Increase register read retry rount from 3 to 30 for selected registers (Chandrakanth
    patil)
    - bpf: Fix precision tracking for BPF_ALU | BPF_TO_BE | BPF_END (Shung-Hsi Yu)
    - randstruct: Fix gcc-plugin performance mode to stay in group (Kees Cook)
    - media: venus: hfi: add checks to perform sanity on queue pointers (Vikash Garodia)
    - cifs: spnego: add ';' in HOST_KEY_LEN (Anastasia Belova)
    - tools/power/turbostat: Fix a knl bug (Zhang Rui)
    - macvlan: Don't propagate promisc change to lower dev in passthru (Vlad Buslov)
    - net/mlx5e: Check return value of snprintf writing to fw_version buffer for representors (Rahul
    Rameshbabu)
    - net/mlx5e: fix double free of encap_header (Dust Li)
    - net: stmmac: fix rx budget limit check (Baruch Siach)
    - net: stmmac: Rework stmmac_rx() (Jose Abreu)
    - netfilter: nf_conntrack_bridge: initialize err to 0 (Linkui Xiao)
    - net: ethernet: cortina: Fix MTU max setting (Linus Walleij)
    - net: ethernet: cortina: Handle large frames (Linus Walleij)
    - net: ethernet: cortina: Fix max RX frame define (Linus Walleij)
    - bonding: stop the device in bond_setup_by_slave() (Eric Dumazet)
    - ptp: annotate data-race around q->head and q->tail (Eric Dumazet)
    - xen/events: fix delayed eoi list handling (Juergen Gross)
    - ppp: limit MRU to 64K (Willem de Bruijn)
    - tipc: Fix kernel-infoleak due to uninitialized TLV value (Shigeru Yoshida)
    - net: hns3: fix variable may not initialized problem in hns3_init_mac_addr() (Yonglong Liu)
    - tty: Fix uninit-value access in ppp_sync_receive() (Shigeru Yoshida)
    - ipvlan: add ipvlan_route_v6_outbound() helper (Eric Dumazet)
    - NFSv4.1: fix SP4_MACH_CRED protection for pnfs IO (Olga Kornievskaia)
    - wifi: iwlwifi: Use FW rate for non-data frames (Miri Korenblit)
    - pwm: Fix double shift bug (Dan Carpenter)
    - ASoC: ti: omap-mcbsp: Fix runtime PM underflow warnings (Tony Lindgren)
    - kgdb: Flush console before entering kgdb on panic (Douglas Anderson)
    - drm/amd/display: Avoid NULL dereference of timing generator (Wayne Lin)
    - media: cobalt: Use FIELD_GET() to extract Link Width (Ilpo Jarvinen)
    - gfs2: ignore negated quota changes (Bob Peterson)
    - media: vivid: avoid integer overflow (Hans Verkuil)
    - media: gspca: cpia1: shift-out-of-bounds in set_flicker (Rajeshwar R Shinde)
    - i2c: sun6i-p2wi: Prevent potential division by zero (Axel Lin)
    - usb: gadget: f_ncm: Always set current gadget in ncm_bind() (Hardik Gajjar)
    - tty: vcc: Add check for kstrdup() in vcc_probe() (Yi Yang)
    - HID: Add quirk for Dell Pro Wireless Keyboard and Mouse KM5221W (Jiri Kosina)
    - scsi: libfc: Fix potential NULL pointer dereference in fc_lport_ptp_setup() (Wenchao Hao)
    - atm: iphase: Do PCI error checks on own line (Ilpo Jarvinen)
    - PCI: tegra194: Use FIELD_GET()/FIELD_PREP() with Link Width fields (Ilpo Jarvinen)
    - ALSA: hda: Fix possible null-ptr-deref when assigning a stream (Cezary Rojewski)
    - ARM: 9320/1: fix stack depot IRQ stack filter (Vincent Whitchurch)
    - jfs: fix array-index-out-of-bounds in diAlloc (Manas Ghandat)
    - jfs: fix array-index-out-of-bounds in dbFindLeaf (Manas Ghandat)
    - fs/jfs: Add validity check for db_maxag and db_agpref (Juntong Deng)
    - fs/jfs: Add check for negative db_l2nbperpage (Juntong Deng)
    - RDMA/hfi1: Use FIELD_GET() to extract Link Width (Ilpo Jarvinen)
    - crypto: pcrypt - Fix hungtask for PADATA_RESET (Lu Jialin)
    - selftests/efivarfs: create-read: fix a resource leak (zhujun2)
    - drm/amdgpu: Fix a null pointer access when the smc_rreg pointer is NULL (Qu Huang)
    - drm/amd: Fix UBSAN array-index-out-of-bounds for Polaris and Tonga (Mario Limonciello)
    - drm/amd: Fix UBSAN array-index-out-of-bounds for SMU7 (Mario Limonciello)
    - drm/komeda: drop all currently held locks if deadlock happens (baozhu.liu)
    - platform/x86: thinkpad_acpi: Add battery quirk for Thinkpad X120e (Olli Asikainen)
    - Bluetooth: Fix double free in hci_conn_cleanup (ZhengHan Wang)
    - wifi: ath10k: Don't touch the CE interrupt registers after power up (Douglas Anderson)
    - net: annotate data-races around sk->sk_dst_pending_confirm (Eric Dumazet)
    - net: annotate data-races around sk->sk_tx_queue_mapping (Eric Dumazet)
    - wifi: ath10k: fix clang-specific fortify warning (Dmitry Antipov)
    - wifi: ath9k: fix clang-specific fortify warnings (Dmitry Antipov)
    - wifi: mac80211: don't return unset power in ieee80211_get_tx_power() (Ping-Ke Shih)
    - wifi: mac80211_hwsim: fix clang-specific fortify warning (Dmitry Antipov)
    - x86/mm: Drop the 4 MB restriction on minimal NUMA node memory size (Mike Rapoport (IBM))
    - clocksource/drivers/timer-atmel-tcb: Fix initialization on SAM9 hardware (Ronald Wahl)
    - clocksource/drivers/timer-imx-gpt: Fix potential memory leak (Jacky Bai)
    - perf/core: Bail out early if the request AUX area is out of bound (Shuai Xue)
    - locking/ww_mutex/test: Fix potential workqueue corruption (John Stultz)
    - LTS tag: v5.4.261 (Sherry Yang)
    - btrfs: use u64 for buffer sizes in the tree search ioctls (Filipe Manana)
    - fbdev: fsl-diu-fb: mark wr_reg_wa() static (Arnd Bergmann)
    - fbdev: imsttfb: fix a resource leak in probe (Dan Carpenter)
    - fbdev: imsttfb: Fix error path of imsttfb_probe() (Helge Deller)
    - spi: spi-zynq-qspi: add spi-mem to driver kconfig dependencies (Amit Kumar Mahapatra)
    - drm/syncobj: fix DRM_SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE (Erik Kurzinger)
    - netfilter: nat: fix ipv6 nat redirect with mapped and scoped addresses (Florian Westphal)
    - netfilter: nft_redir: use struct nf_nat_range2 throughout and deduplicate eval call-backs (Jeremy
    Sowden)
    - netfilter: xt_recent: fix (increase) ipv6 literal buffer length (Maciej Zenczykowski)
    - r8169: respect userspace disabling IFF_MULTICAST (Heiner Kallweit)
    - tg3: power down device only on SYSTEM_POWER_OFF (George Shuklin)
    - net/smc: fix dangling sock under state SMC_APPFINCLOSEWAIT (D. Wythe)
    - net: stmmac: xgmac: Enable support for multiple Flexible PPS outputs (Furong Xu)
    - Fix termination state for idr_for_each_entry_ul() (NeilBrown)
    - net: r8169: Disable multicast filter for RTL8168H and RTL8107E (Patrick Thompson)
    - dccp/tcp: Call security_inet_conn_request() after setting IPv6 addresses. (Kuniyuki Iwashima)
    - dccp: Call security_inet_conn_request() after setting IPv4 addresses. (Kuniyuki Iwashima)
    - tipc: Change nla_policy for bearer-related names to NLA_NUL_STRING (Shigeru Yoshida)
    - llc: verify mac len before reading mac header (Willem de Bruijn)
    - Input: synaptics-rmi4 - fix use after free in rmi_unregister_function() (Dan Carpenter)
    - pwm: brcmstb: Utilize appropriate clock APIs in suspend/resume (Florian Fainelli)
    - pwm: sti: Reduce number of allocations and drop usage of chip_data (Uwe Kleine-Konig)
    - pwm: sti: Avoid conditional gotos (Thierry Reding)
    - regmap: prevent noinc writes from clobbering cache (Ben Wolsieffer)
    - media: s3c-camif: Avoid inappropriate kfree() (Katya Orlova)
    - media: bttv: fix use after free error due to btv->timeout timer (Zheng Wang)
    - pcmcia: ds: fix possible name leak in error path in pcmcia_device_add() (Yang Yingliang)
    - pcmcia: ds: fix refcount leak in pcmcia_device_add() (Yang Yingliang)
    - pcmcia: cs: fix possible hung task and memory leak pccardd() (Yang Yingliang)
    - rtc: pcf85363: fix wrong mask/val parameters in regmap_update_bits call (Javier Carrasco)
    - i3c: Fix potential refcount leak in i3c_master_register_new_i3c_devs (Dinghao Liu)
    - powerpc/pseries: fix potential memory leak in init_cpu_associativity() (Wang Yufen)
    - powerpc/imc-pmu: Use the correct spinlock initializer. (Sebastian Andrzej Siewior)
    - powerpc/xive: Fix endian conversion size (Benjamin Gray)
    - modpost: fix tee MODULE_DEVICE_TABLE built on big-endian host (Masahiro Yamada)
    - f2fs: fix to initialize map.m_pblk in f2fs_precache_extents() (Chao Yu)
    - dmaengine: pxa_dma: Remove an erroneous BUG_ON() in pxad_free_desc() (Christophe JAILLET)
    - USB: usbip: fix stub_dev hub disconnect (Jonas Blixt)
    - tools: iio: iio_generic_buffer ensure alignment (Matti Vaittinen)
    - tools: iio: iio_generic_buffer: Fix some integer type and calculation (Chenyuan Mi)
    - tools: iio: privatize globals and functions in iio_generic_buffer.c file (Alexandru Ardelean)
    - misc: st_core: Do not call kfree_skb() under spin_lock_irqsave() (Jinjie Ruan)
    - dmaengine: ti: edma: handle irq_of_parse_and_map() errors (Dan Carpenter)
    - usb: dwc2: fix possible NULL pointer dereference caused by driver concurrency (Jia-Ju Bai)
    - tty: tty_jobctrl: fix pid memleak in disassociate_ctty() (Yi Yang)
    - leds: trigger: ledtrig-cpu:: Fix 'output may be truncated' issue for 'cpu' (Christophe JAILLET)
    - ledtrig-cpu: Limit to 8 CPUs (Pavel Machek)
    - leds: pwm: Don't disable the PWM when the LED should be off (Uwe Kleine-Konig)
    - leds: pwm: convert to atomic PWM API (Uwe Kleine-Konig)
    - leds: pwm: simplify if condition (Uwe Kleine-Konig)
    - mfd: dln2: Fix double put in dln2_probe (Dinghao Liu)
    - ASoC: ams-delta.c: use component after check (Kuninori Morimoto)
    - ASoC: Intel: Skylake: Fix mem leak when parsing UUIDs fails (Cezary Rojewski)
    - sh: bios: Revive earlyprintk support (Geert Uytterhoeven)
    - RDMA/hfi1: Workaround truncation compilation error (Leon Romanovsky)
    - scsi: ufs: core: Leave space for '- ext4: move 'ix' sanity check to corrent position (Gou Hao)
    - ARM: 9321/1: memset: cast the constant byte to unsigned char (Kursad Oney)
    - hid: cp2112: Fix duplicate workqueue initialization (Danny Kaehn)
    - HID: cp2112: Use irqchip template (Linus Walleij)
    - crypto: caam/jr - fix Chacha20 + Poly1305 self test failure (Gaurav Jain)
    - crypto: caam/qi2 - fix Chacha20 + Poly1305 self test failure (Gaurav Jain)
    - nd_btt: Make BTT lanes preemptible (Tomas Glozar)
    - sched/rt: Provide migrate_disable/enable() inlines (Thomas Gleixner)
    - libnvdimm/of_pmem: Use devm_kstrdup instead of kstrdup and check its return value (Chen Ni)
    - hwrng: geode - fix accessing registers (Jonas Gorski)
    - clk: scmi: Free scmi_clk allocated when the clocks with invalid info are skipped (Sudeep Holla)
    - firmware: ti_sci: Mark driver as non removable (Dhruva Gole)
    - firmware: ti_sci: Replace HTTP links with HTTPS ones (Alexander A. Klimov)
    - soc: qcom: llcc: Handle a second device without data corruption (Uwe Kleine-Konig)
    - soc: qcom: Rename llcc-slice to llcc-qcom (Vivek Gautam)
    - soc: qcom: llcc cleanup to get rid of sdm845 specific driver file (Vivek Gautam)
    - ARM: dts: qcom: mdm9615: populate vsdcc fixed regulator (Krzysztof Kozlowski)
    - arm64: dts: qcom: sdm845-mtp: fix WiFi configuration (Dmitry Baryshkov)
    - drm/rockchip: cdn-dp: Fix some error handling paths in cdn_dp_probe() (Christophe JAILLET)
    - drm/radeon: possible buffer overflow (Konstantin Meskhidze)
    - drm/rockchip: vop: Fix call to crtc reset helper (Jonas Karlman)
    - drm/rockchip: vop: Fix reset of state in duplicate state crtc funcs (Jonas Karlman)
    - hwmon: (coretemp) Fix potentially truncated sysfs attribute name (Zhang Rui)
    - platform/x86: wmi: Fix opening of char device (Armin Wolf)
    - platform/x86: wmi: remove unnecessary initializations (Barnabas Pocze)
    - platform/x86: wmi: Fix probe failure when failing to register WMI devices (Armin Wolf)
    - clk: mediatek: clk-mt2701: Add check for mtk_alloc_clk_data (Jiasheng Jiang)
    - clk: mediatek: clk-mt7629: Add check for mtk_alloc_clk_data (Jiasheng Jiang)
    - clk: mediatek: clk-mt7629-eth: Add check for mtk_alloc_clk_data (Jiasheng Jiang)
    - clk: mediatek: clk-mt6797: Add check for mtk_alloc_clk_data (Jiasheng Jiang)
    - clk: mediatek: clk-mt6779: Add check for mtk_alloc_clk_data (Jiasheng Jiang)
    - clk: npcm7xx: Fix incorrect kfree (Jonathan Neuschafer)
    - clk: keystone: pll: fix a couple NULL vs IS_ERR() checks (Dan Carpenter)
    - clk: imx: Select MXC_CLK for CLK_IMX8QXP (Abel Vesa)
    - clk: qcom: gcc-sm8150: Fix gcc_sdcc2_apps_clk_src (Danila Tikhonov)
    - clk: qcom: gcc-sm8150: use ARRAY_SIZE instead of specifying num_parents (Dmitry Baryshkov)
    - clk: qcom: clk-rcg2: Fix clock rate overflow for high parent frequencies (Devi Priya)
    - regmap: debugfs: Fix a erroneous check after snprintf() (Christophe JAILLET)
    - ipvlan: properly track tx_errors (Eric Dumazet)
    - net: add DEV_STATS_READ() helper (Eric Dumazet)
    - ipv6: avoid atomic fragment on GSO packets (Yan Zhai)
    - ACPI: sysfs: Fix create_pnp_modalias() and create_of_modalias() (Christophe JAILLET)
    - tcp: fix cookie_init_timestamp() overflows (Eric Dumazet)
    - tcp: Remove one extra ktime_get_ns() from cookie_init_timestamp (Eric Dumazet)
    - chtls: fix tp->rcv_tstamp initialization (Eric Dumazet)
    - r8169: fix rare issue with broken rx after link-down on RTL8125 (Heiner Kallweit)
    - r8169: use tp_to_dev instead of open code (Juhee Kang)
    - thermal: core: prevent potential string overflow (Dan Carpenter)
    - can: dev: can_restart(): fix race condition between controller restart and netif_carrier_on() (Marc
    Kleine-Budde)
    - can: dev: can_restart(): don't crash kernel if carrier is OK (Marc Kleine-Budde)
    - wifi: rtlwifi: fix EDCA limit set by BT coexistence (Dmitry Antipov)
    - tcp_metrics: do not create an entry from tcp_init_metrics() (Eric Dumazet)
    - tcp_metrics: properly set tp->snd_ssthresh in tcp_init_metrics() (Eric Dumazet)
    - tcp_metrics: add missing barriers on delete (Eric Dumazet)
    - wifi: mt76: mt7603: rework/fix rx pse hang check (Felix Fietkau)
    - wifi: rtw88: debug: Fix the NULL vs IS_ERR() bug for debugfs_create_file() (Jinjie Ruan)
    - tcp: call tcp_try_undo_recovery when an RTOd TFO SYNACK is ACKed (Aananth V)
    - i40e: fix potential memory leaks in i40e_remove() (Andrii Staikov)
    - genirq/matrix: Exclude managed interrupts in irq_matrix_allocated() (Chen Yu)
    - vfs: fix readahead(2) on block devices (Reuben Hawkins)
    - LTS tag: v5.4.260 (Sherry Yang)
    - tty: 8250: Add support for Intashield IS-100 (Cameron Williams)
    - tty: 8250: Add support for Brainboxes UP cards (Cameron Williams)
    - tty: 8250: Add support for additional Brainboxes UC cards (Cameron Williams)
    - tty: 8250: Remove UC-257 and UC-431 (Cameron Williams)
    - usb: storage: set 1.50 as the lower bcdDevice for older 'Super Top' compatibility (LihaSika)
    - PCI: Prevent xHCI driver from claiming AMD VanGogh USB3 DRD device (Vicki Pfau)
    - Revert 'ARM: dts: Move am33xx and am43xx mmc nodes to sdhci-omap driver' (Matthias Schiffer)
    - remove the sx8 block driver (Christoph Hellwig)
    - ata: ahci: fix enum constants for gcc-13 (Arnd Bergmann)
    - net: chelsio: cxgb4: add an error code check in t4_load_phy_fw (Su Hui)
    - platform/mellanox: mlxbf-tmfifo: Fix a warning message (Liming Sun)
    - platform/x86: asus-wmi: Change ASUS_WMI_BRN_DOWN code from 0x20 to 0x2e (Hans de Goede)
    - scsi: mpt3sas: Fix in error path (Tomas Henzl)
    - fbdev: uvesafb: Call cn_del_callback() at the end of uvesafb_exit() (Jorge Maidana)
    - ASoC: rt5650: fix the wrong result of key button (Shuming Fan)
    - netfilter: nfnetlink_log: silence bogus compiler warning (Florian Westphal)
    - spi: npcm-fiu: Fix UMA reads when dummy.nbytes == 0 (William A. Kennington III)
    - fbdev: atyfb: only use ioremap_uc() on i386 and ia64 (Arnd Bergmann)
    - Input: synaptics-rmi4 - handle reset delay when using SMBus trsnsport (Dmitry Torokhov)
    - dmaengine: ste_dma40: Fix PM disable depth imbalance in d40_probe (Zhang Shurong)
    - irqchip/stm32-exti: add missing DT IRQ flag translation (Ben Wolsieffer)
    - Input: i8042 - add Fujitsu Lifebook E5411 to i8042 quirk table (Szilard Fabian)
    - x86: Fix .brk attribute in linker script (Juergen Gross)
    - rpmsg: Fix possible refcount leak in rpmsg_register_device_override() (Hangyu Hua)
    - rpmsg: glink: Release driver_override (Bjorn Andersson)
    - rpmsg: Fix calling device_lock() on non-initialized device (Krzysztof Kozlowski)
    - rpmsg: Fix kfree() of static memory on setting driver_override (Krzysztof Kozlowski)
    - rpmsg: Constify local variable in field store macro (Krzysztof Kozlowski)
    - driver: platform: Add helper for safer setting of driver_override (Krzysztof Kozlowski)
    - ext4: fix BUG in ext4_mb_new_inode_pa() due to overflow (Baokun Li)
    - ext4: avoid overlapping preallocations due to overflow (Baokun Li)
    - ext4: add two helper functions extent_logical_end() and pa_logical_end() (Baokun Li)
    - x86/mm: Fix RESERVE_BRK() for older binutils (Josh Poimboeuf)
    - x86/mm: Simplify RESERVE_BRK() (Josh Poimboeuf)
    - nfsd: lock_rename() needs both directories to live on the same fs (Al Viro)
    - f2fs: fix to do sanity check on inode type during garbage collection (Chao Yu)
    - smbdirect: missing rc checks while waiting for rdma events (Steve French)
    - kobject: Fix slab-out-of-bounds in fill_kobj_path() (Wang Hai)
    - arm64: fix a concurrency issue in emulation_proc_handler() (Jinjie Ruan)
    - drm/dp_mst: Fix NULL deref in get_mst_branch_device_by_guid_helper() (Lukasz Majczak)
    - x86/i8259: Skip probing when ACPI/MADT advertises PCAT compatibility (Thomas Gleixner)
    - i40e: Fix wrong check for I40E_TXR_FLAGS_WB_ON_ITR (Ivan Vecera)
    - clk: Sanitize possible_parent_show to Handle Return Value of of_clk_get_parent_name (Alessandro
    Carminati)
    - nvmem: imx: correct nregs for i.MX6UL (Peng Fan)
    - nvmem: imx: correct nregs for i.MX6SLL (Peng Fan)
    - nvmem: imx: correct nregs for i.MX6ULL (Peng Fan)
    - i2c: stm32f7: Fix PEC handling in case of SMBUS transfers (Alain Volmat)
    - i2c: muxes: i2c-demux-pinctrl: Use of_get_i2c_adapter_by_node() (Herve Codina)
    - i2c: muxes: i2c-mux-gpmux: Use of_get_i2c_adapter_by_node() (Herve Codina)
    - i2c: muxes: i2c-mux-pinctrl: Use of_get_i2c_adapter_by_node() (Herve Codina)
    - iio: exynos-adc: request second interupt only when touchscreen mode is used (Marek Szyprowski)
    - gtp: fix fragmentation needed check with gso (Pablo Neira Ayuso)
    - gtp: uapi: fix GTPA_MAX (Pablo Neira Ayuso)
    - tcp: fix wrong RTO timeout when received SACK reneging (Fred Chen)
    - r8152: Cancel hw_phy_work if we have an error in probe (Douglas Anderson)
    - r8152: Run the unload routine if we have errors during probe (Douglas Anderson)
    - r8152: Increase USB control msg timeout to 5000ms as per spec (Douglas Anderson)
    - net: ieee802154: adf7242: Fix some potential buffer overflow in adf7242_stats_show() (Christophe
    JAILLET)
    - igc: Fix ambiguity in the ethtool advertising (Sasha Neftin)
    - neighbour: fix various data-races (Eric Dumazet)
    - igb: Fix potential memory leak in igb_add_ethtool_nfc_entry (Mateusz Palczewski)
    - treewide: Spelling fix in comment (Kunwu Chan)
    - r8169: fix the KCSAN reported data race in rtl_rx while reading desc->opts1 (Mirsad Goran Todorovac)
    - r8169: fix the KCSAN reported data-race in rtl_tx while reading TxDescArray[entry].opts1 (Mirsad Goran
    Todorovac)
    - virtio_balloon: Fix endless deflation and inflation on arm64 (Gavin Shan)
    - mcb-lpc: Reallocate memory region to avoid memory overlapping (Rodriguez Barbarin, Jose Javier)
    - mcb: Return actual parsed size when reading chameleon table (Rodriguez Barbarin, Jose Javier)
    - selftests/ftrace: Add new test case which checks non unique symbol (Francis Laniel)
    - mtd: rawnand: marvell: Ensure program page operations are successful (Miquel Raynal)

    [5.4.17-2136.328.1]
    - net/mlx5e: Check for NOT_READY flag state after locking (Vlad Buslov)  [Orabug: 36014945]
    - net/mlx5e: fix memory leak in mlx5e_ptp_open (Zhengchao Shao)  [Orabug: 36014945]
    - net/mlx5e: Fix error handling in mlx5e_refresh_tirs (Saeed Mahameed)  [Orabug: 36014945]
    - net/mlx5e: Don't attach netdev profile while handling internal error (Dmytro Linkin)  [Orabug: 36014945]
    - net/mlx5e: Do not update SBCM when prio2buffer command is invalid (Maher Sanalla)  [Orabug: 36014945]
    - mlxsw: pci: Fix possible crash during initialization (Ido Schimmel)  [Orabug: 36014945]
    - net/mlx5: E-Switch, Fix an Oops in error handling code (Dan Carpenter)  [Orabug: 36014945]
    - net/mlx5: E-switch, Fix missing set of split_count when forward to ovs internal port (Maor Dickman)
    [Orabug: 36014945]
    - net/mlx5: fw_tracer, Zero consumer index when reloading the tracer (Shay Drory)  [Orabug: 36014945]
    - net/mlx5: fw_tracer, Clear load bit when freeing string DBs buffers (Shay Drory)  [Orabug: 36014945]
    - net/mlx5: SF: Fix probing active SFs during driver probe phase (Shay Drory)  [Orabug: 36014945]
    - net/mlx5e: Remove WARN_ON when trying to offload an unsupported TLS cipher/version (Gal Pressman)
    [Orabug: 36014945]
    - net/mlx5: Fix mlx5_get_next_dev() peer device matching (Saeed Mahameed)  [Orabug: 36014945]
    - net/mlx5: Drain fw_reset when removing device (Shay Drory)  [Orabug: 36014945]
    - net/mlx5: Lag, filter non compatible devices (Mark Bloch)  [Orabug: 36014945]
    - net/mlx5: Disable SRIOV before PF removal (Yishai Hadas)  [Orabug: 36014945]
    - net/mlx5: Lag, Make mlx5_lag_is_multipath() be static inline (Maor Dickman)  [Orabug: 36014945]
    - net/mlx5: Lag, change multipath and bonding to be mutually exclusive (Maor Dickman)  [Orabug: 36014945]
    - net/mlx5e: Destroy page pool after XDP SQ to fix use-after-free (Maxim Mikityanskiy)  [Orabug: 36014945]
    - net/mlx5: Lag, move lag destruction to a workqueue (Mark Bloch)  [Orabug: 36014945]
    - net/mlx5: Unload device upon firmware fatal error (Aya Levin)  [Orabug: 36014945]
    - net/mlx5: Remove unnecessary spin lock protection (Eli Cohen)  [Orabug: 36014945]
    - net/mlx5e: When changing XDP program without reset, take refs for XSK RQs (Maxim Mikityanskiy)  [Orabug:
    36014945]
    - net/mlx5e: Check tunnel offload is required before setting SWP (Moshe Shemesh)  [Orabug: 36014945]
    - net/mlx5e: Remove unused mlx5e_xsk_first_unused_channel (Maxim Mikityanskiy)  [Orabug: 36014945]
    - net/mlx5e: Fix stats update for matchall classifier (Roi Dayan)  [Orabug: 36014945]
    - net/mlx5e: Set of completion request bit should not clear other adjacent bits (Tariq Toukan)  [Orabug:
    36014945]
    - mlxsw: pci: Wait longer before accessing the device after reset (Amit Cohen)  [Orabug: 36014945]
    - mlxsw: pci: Remove unused values (Ido Schimmel)  [Orabug: 36014945]
    - mlxsw: core: Add validation of hardware device types for MGPIR register (Vadim Pasternak)  [Orabug:
    36014945]
    - netdevsim: fix using uninitialized resources (Taehee Yoo)  [Orabug: 36014945]
    - net/mlx5: Read num_vfs before disabling SR-IOV (Parav Pandit)  [Orabug: 36014945]
    - net/mlx5: DR, Replace CRC32 implementation to use kernel lib (Hamdan Igbaria)  [Orabug: 36014945]
    - mlxsw: pci: Increase PCI reset timeout for SN3800 systems (Ido Schimmel)  [Orabug: 36014945]
    - mlxsw: hwmon: Provide optimization for QSFP modules number detection (Vadim Pasternak)  [Orabug:
    36014945]
    - mlxsw: reg: Extend MGPIR register with new field exposing the number of QSFP modules (Vadim Pasternak)
    [Orabug: 36014945]
    - vhost-scsi: add parentheses to macro of VHOST_SCSI_MAX_VQ (Dongli Zhang)  [Orabug: 36119643]
    - iommu/amd: Do not flush IRTE when only updating isRun and destination fields (Suravee Suthikulpanit)
    [Orabug: 36101189]
    - xfs: try to avoid allocation blocking on busy extents (Mark Tinguely)  [Orabug: 36096908]
    - EDAC/amd64: Add support for AMD family 1Ah models 00h-1Fh and 40h-4Fh (Avadhut Naik)  [Orabug: 36092305]
    - EDAC/amd64: Add get_err_info() to pvt->ops (Muralidhara M K)  [Orabug: 36092305]
    - EDAC/amd64: Split dump_misc_regs() into dct/umc functions (Muralidhara M K)  [Orabug: 36092305]
    - EDAC/amd64: Split init_csrows() into dct/umc functions (Muralidhara M K)  [Orabug: 36092305]
    - EDAC/amd64: Split determine_edac_cap() into dct/umc functions (Muralidhara M K)  [Orabug: 36092305]
    - EDAC/amd64: Rename f17h_determine_edac_ctl_cap() (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Split setup_mci_misc_attrs() into dct/umc functions (Muralidhara M K)  [Orabug: 36092305]
    - EDAC/amd64: Split ecc_enabled() into dct/umc functions (Muralidhara M K)  [Orabug: 36092305]
    - EDAC/amd64: Split read_mc_regs() into dct/umc functions (Muralidhara M K)  [Orabug: 36092305]
    - EDAC/amd64: Split determine_memory_type() into dct/umc functions (Muralidhara M K)  [Orabug: 36092305]
    - EDAC/amd64: Split read_base_mask() into dct/umc functions (Muralidhara M K)  [Orabug: 36092305]
    - EDAC/amd64: Split prep_chip_selects() into dct/umc functions (Muralidhara M K)  [Orabug: 36092305]
    - EDAC/amd64: Rework hw_info_{get,put} (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Merge struct amd64_family_type into struct amd64_pvt (Muralidhara M K)  [Orabug: 36092305]
    - EDAC/amd64: Do not discover ECC symbol size for Family 17h and later (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Drop dbam_to_cs() for Family 17h and later (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Split get_csrow_nr_pages() into dct/umc functions (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Rename debug_display_dimm_sizes() (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Shut up an -Werror,-Wsometimes-uninitialized clang false positive (Yazen Ghannam)  [Orabug:
    36092305]
    - EDAC/amd64: Remove early_channel_count() (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Remove PCI Function 0 (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Remove PCI Function 6 (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Remove scrub rate control for Family 17h and later (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Don't set up EDAC PCI control on Family 17h+ (Yazen Ghannam)  [Orabug: 36092305]
    - x86/amd_nb: Unexport amd_cache_northbridges() (Muralidhara M K)  [Orabug: 36092305]
    - EDAC/amd64: Add new register offset support and related changes (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Set memory type per DIMM (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Add support for family 19h, models 50h-5fh (Marc Bevand)  [Orabug: 36092305]
    - EDAC/amd64: Add context struct (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Allow for DF Indirect Broadcast reads (Yazen Ghannam)  [Orabug: 36092305]
    - x86/amd_nb, EDAC/amd64: Move DF Indirect Read to AMD64 EDAC (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Issue probing messages only on properly detected hardware (Borislav Petkov)  [Orabug:
    36092305]
    - EDAC/amd64: Tone down messages about missing PCI IDs (Yazen Ghannam)  [Orabug: 36092305]
    - EDAC/amd64: Do not load on family 0x15, model 0x13 (Borislav Petkov)  [Orabug: 36092305]
    - EDAC/amd64: Remove redundant assignment to variable ret in hw_info_get() (Colin Ian King)  [Orabug:
    36092305]
    - crypto: ccp - Add support for PCI device 0x156E (John Allen)  [Orabug: 36092305]
    - crypto: ccp - Add support for PCI device 0x17E0 (Mario Limonciello)  [Orabug: 36092305]
    - crypto: ccp - Provide MMIO register naming for documenation (Tom Lendacky)  [Orabug: 36092305]
    - crypto: ccp - Add support for TEE for PCI ID 0x14CA (Mario Limonciello)  [Orabug: 36092305]
    - crypto: ccp - Add support for new CCP/PSP device ID (Mario Limonciello)  [Orabug: 36092305]
    - x86/amd_nb: Add PCI IDs for AMD Family 1Ah-based models (Avadhut Naik)  [Orabug: 36092305]
    - x86/amd_nb: Re-sort and re-indent PCI defines (Borislav Petkov (AMD))  [Orabug: 36092305]
    - x86/amd_nb: Add MI200 PCI IDs (Yazen Ghannam)  [Orabug: 36092305]
    - x86/amd_nb: Add PCI ID for family 19h model 78h (Mario Limonciello)  [Orabug: 36092305]
    - x86/amd_nb: Add AMD PCI IDs for SMN communication (Mario Limonciello)  [Orabug: 36092305]
    - hwmon: (k10temp) Add thermal support for AMD Family 1Ah-based models (Avadhut Naik)  [Orabug: 36092305]
    - hwmon: (k10temp) Add PCI ID for family 19, model 78h (Mario Limonciello)  [Orabug: 36092305]
    - hwmon: (k10temp): Add support for new family 17h and 19h models (Mario Limonciello)  [Orabug: 36092305]
    - uek-rpm: Update the x86 kABI files for new symbol (Yifei Liu)  [Orabug: 36090182]
    - audit: Apply special optimizations (Hakon Bugge)  [Orabug: 36089817]
    - audit: Vary struct audit_entry alignment (Hakon Bugge)  [Orabug: 36089817]
    - eth: bnxt: handle invalid Tx completions more gracefully (Jakub Kicinski)  [Orabug: 36075755]
    - tcp: Tunables for TCP delayed ack (min and max) timers (Venkat Venkatsubra)  [Orabug: 35875891]
    - tcp: fix ambiguity for SACKed TLP retransmits with RTT < min_rtt (Neal Cardwell)  [Orabug: 35875891]
    - Add basic Emerald Rapids support to UEK6 (Henry Willard)  [Orabug: 35063919]

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12151.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29900");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-25775");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::developer_UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::developer_UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8:9:baseos_patch");
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
  var fixed_uptrack_levels = ['5.4.17-2136.328.3.el7uek', '5.4.17-2136.328.3.el8uek'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-12151');
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
    {'reference':'kernel-uek-5.4.17-2136.328.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.328.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.328.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.328.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.328.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2136.328.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-tools-libs-5.4.17-2136.328.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-5.4.17'},
    {'reference':'perf-5.4.17-2136.328.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-5.4.17'},
    {'reference':'python-perf-5.4.17-2136.328.3.el7uek', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.328.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.328.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.328.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.328.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.328.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-tools-5.4.17-2136.328.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-5.4.17'},
    {'reference':'kernel-uek-tools-libs-5.4.17-2136.328.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-tools-libs-5.4.17'},
    {'reference':'perf-5.4.17-2136.328.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'perf-5.4.17'},
    {'reference':'python-perf-5.4.17-2136.328.3.el7uek', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'python-perf-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.328.3.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.328.3.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.328.3.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.328.3.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.328.3.el8uek', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'},
    {'reference':'kernel-uek-5.4.17-2136.328.3.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-5.4.17'},
    {'reference':'kernel-uek-debug-5.4.17-2136.328.3.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-5.4.17'},
    {'reference':'kernel-uek-debug-devel-5.4.17-2136.328.3.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-debug-devel-5.4.17'},
    {'reference':'kernel-uek-devel-5.4.17-2136.328.3.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-devel-5.4.17'},
    {'reference':'kernel-uek-doc-5.4.17-2136.328.3.el8uek', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-doc-5.4.17'}
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
      severity   : SECURITY_NOTE,
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
