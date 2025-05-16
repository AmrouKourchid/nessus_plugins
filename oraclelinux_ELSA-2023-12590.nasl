#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-12590.
##

include('compat.inc');

if (description)
{
  script_id(178262);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2022-34918", "CVE-2022-39189");

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel-container (ELSA-2023-12590)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-12590 advisory.

    [5.4.17-2136.321.4.el7]
    - tick/common: Align tick period during sched_timer setup (Thomas Gleixner)  [Orabug: 35520079]
    - net/rds: Fix endless rds_send_xmit() loop if cp_index > 0 (Gerd Rausch)  [Orabug: 35510149]

    [5.4.17-2136.321.3.el7]
    - selinux: don't use make's grouped targets feature yet (Paul Moore)
    - lib: cpu_rmap: Fix potential use-after-free in irq_cpu_rmap_release() (Ben Hutchings)
    - Revert 'staging: rtl8192e: Replace macro RTL_PCI_DEVICE with PCI_DEVICE' (Greg Kroah-Hartman)
    - iommu/amd: Fix compile error for unused function (Joerg Roedel)  [Orabug: 35070061]
    - iommu/amd: Do not Invalidate IRT when IRTE caching is disabled (Suravee Suthikulpanit)  [Orabug:
    35070061]
    - iommu/amd: Introduce Disable IRTE Caching Support (Suravee Suthikulpanit)  [Orabug: 35070061]
    - iommu/amd: Remove the unused struct amd_ir_data.ref (Suravee Suthikulpanit)  [Orabug: 35070061]
    - iommu/amd: Switch amd_iommu_update_ga() to use modify_irte_ga() (Joao Martins)  [Orabug: 35070061]
    - iommu/amd: Handle GALog overflows (Joao Martins)  [Orabug: 35070061]
    - iommu/amd: Fix 'Guest Virtual APIC Table Root Pointer' configuration in IRTE (Kishon Vijay Abraham I)
    [Orabug: 35070061]
    - KVM: x86: ioapic: Fix level-triggered EOI and userspace I/OAPIC reconfigure race (Adamos Ttofari)
    [Orabug: 35070061]
    - xfs: fix AGFL allocation deadlock (Wengang Wang)  [Orabug: 35159734]
    - crypto: api - Demote BUG_ON() in crypto_unregister_alg() to a WARN_ON() (Toke H?iland-J?rgensen)
    [Orabug: 35152388]
    - crypto: qat - drop log level of msg in get_instance_node() (Giovanni Cabiddu)  [Orabug: 35152388]
    - crypto: algapi - make unregistration functions return void (Eric Biggers)  [Orabug: 35152388]
    - bnxt_en: Clear DEFRAG flag in firmware message when retry flashing. (Pavan Chebbi)  [Orabug: 35365203]
    - bnxt_en: Enable batch mode when using HWRM_NVM_MODIFY to flash packages. (Michael Chan)  [Orabug:
    35365203]
    - bnxt_en: Retry installing FW package under NO_SPACE error condition. (Pavan Chebbi)  [Orabug: 35365203]
    - bnxt_en: Restructure bnxt_flash_package_from_fw_obj() to execute in a loop. (Pavan Chebbi)  [Orabug:
    35365203]
    - bnxt_en: Rearrange the logic in bnxt_flash_package_from_fw_obj(). (Michael Chan)  [Orabug: 35365203]
    - bnxt_en: Refactor bnxt_flash_nvram. (Pavan Chebbi)  [Orabug: 35365203]

    [5.4.17-2136.321.2.el7]
    - LTS tag: v5.4.245 (Sherry Yang)
    - netfilter: ctnetlink: Support offloaded conntrack entry deletion (Paul Blakey)
    - ipv{4,6}/raw: fix output xfrm lookup wrt protocol (Nicolas Dichtel)
    - binder: fix UAF caused by faulty buffer cleanup (Carlos Llamas)
    - bluetooth: Add cmd validity checks at the start of hci_sock_ioctl() (Ruihan Li)
    - cdc_ncm: Fix the build warning (Alexander Bersenev)
    - net/mlx5: Devcom, serialize devcom registration (Shay Drory)
    - net/mlx5: devcom only supports 2 ports (Mark Bloch)
    - fs: fix undefined behavior in bit shift for SB_NOUSER (Hao Ge)
    - power: supply: bq24190: Call power_supply_changed() after updating input current (Hans de Goede)
    - power: supply: core: Refactor power_supply_set_input_current_limit_from_supplier() (Hans de Goede)
    - power: supply: bq27xxx: After charger plug in/out wait 0.5s for things to stabilize (Hans de Goede)
    - net: cdc_ncm: Deal with too low values of dwNtbOutMaxSize (Tudor Ambarus)
    - cdc_ncm: Implement the 32-bit version of NCM Transfer Block (Alexander Bersenev)
    - LTS tag: v5.4.244 (Sherry Yang)
    - 3c589_cs: Fix an error handling path in tc589_probe() (Christophe JAILLET)
    - net/mlx5: Devcom, fix error flow in mlx5_devcom_register_device (Shay Drory)
    - net/mlx5: Fix error message when failing to allocate device memory (Roi Dayan)
    - forcedeth: Fix an error handling path in nv_probe() (Christophe JAILLET)
    - ASoC: Intel: Skylake: Fix declaration of enum skl_ch_cfg (Cezary Rojewski)
    - x86/show_trace_log_lvl: Ensure stack pointer is aligned, again (Vernon Lovejoy)
    - xen/pvcalls-back: fix double frees with pvcalls_new_active_socket() (Dan Carpenter)
    - coresight: Fix signedness bug in tmc_etr_buf_insert_barrier_packet() (Dan Carpenter)
    - power: supply: sbs-charger: Fix INHIBITED bit for Status reg (Daisuke Nojiri)
    - power: supply: bq27xxx: Fix poll_interval handling and races on remove (Hans de Goede)
    - power: supply: bq27xxx: Fix I2C IRQ race on remove (Hans de Goede)
    - power: supply: bq27xxx: Fix bq27xxx_battery_update() race condition (Hans de Goede)
    - power: supply: leds: Fix blink to LED on transition (Hans de Goede)
    - ipv6: Fix out-of-bounds access in ipv6_find_tlv() (Gavrilov Ilia)
    - bpf: Fix mask generation for 32-bit narrow loads of 64-bit fields (Will Deacon)
    - net: fix skb leak in __skb_tstamp_tx() (Pratyush Yadav)
    - media: radio-shark: Add endpoint checks (Alan Stern)
    - USB: sisusbvga: Add endpoint checks (Alan Stern)
    - USB: core: Add routines for endpoint checks in old drivers (Alan Stern)
    - udplite: Fix NULL pointer dereference in __sk_mem_raise_allocated(). (Kuniyuki Iwashima)
    - net: fix stack overflow when LRO is disabled for virtual interfaces (Taehee Yoo)
    - fbdev: udlfb: Fix endpoint check (Alan Stern)
    - debugobjects: Don't wake up kswapd from fill_pool() (Tetsuo Handa)
    - x86/topology: Fix erroneous smp_num_siblings on Intel Hybrid platforms (Zhang Rui)
    - parisc: Fix flush_dcache_page() for usage from irq context (Helge Deller)
    - selftests/memfd: Fix unknown type name build failure (Hardik Garg)
    - x86/mm: Avoid incomplete Global INVLPG flushes (Dave Hansen)
    - btrfs: use nofs when cleaning up aborted transactions (Josef Bacik)
    - gpio: mockup: Fix mode of debugfs files (Zev Weiss)
    - parisc: Allow to reboot machine after system halt (Helge Deller)
    - parisc: Handle kgdb breakpoints only in kernel context (Helge Deller)
    - m68k: Move signal frame following exception on 68020/030 (Finn Thain)
    - ALSA: hda/realtek: Enable headset onLenovo M70/M90 (Bin Li)
    - ALSA: hda/ca0132: add quirk for EVGA X299 DARK (Adam Stylinski)
    - mt76: mt7615: Fix build with older compilers (Pablo Greco)
    - spi: fsl-cpm: Use 16 bit mode for large transfers with even size (Christophe Leroy)
    - spi: fsl-spi: Re-organise transfer bits_per_word adaptation (Christophe Leroy)
    - watchdog: sp5100_tco: Immediately trigger upon starting. (Gregory Oakes)
    - s390/qdio: fix do_sqbs() inline assembly constraint (Heiko Carstens)
    - s390/qdio: get rid of register asm (Heiko Carstens)
    - vc_screen: reload load of struct vc_data pointer in vcs_write() to avoid UAF (George Kennedy)
    - vc_screen: rewrite vcs_size to accept vc, not inode (Jiri Slaby)
    - usb: gadget: u_ether: Fix host MAC address case (Konrad Grafe)
    - usb: gadget: u_ether: Convert prints to device prints (Jon Hunter)
    - lib/string_helpers: Introduce string_upper() and string_lower() helpers (Vadim Pasternak)
    - HID: wacom: add three styli to wacom_intuos_get_tool_type (Ping Cheng)
    - HID: wacom: Add new Intuos Pro Small (PTH-460) device IDs (Ping Cheng)
    - HID: wacom: Force pen out of prox if no events have been received in a while (Jason Gerecke)
    - netfilter: nf_tables: hold mutex on netns pre_exit path (Pablo Neira Ayuso)
    - netfilter: nf_tables: validate NFTA_SET_ELEM_OBJREF based on NFT_SET_OBJECT flag (Pablo Neira Ayuso)
    - netfilter: nf_tables: stricter validation of element data (Pablo Neira Ayuso)
    - netfilter: nf_tables: allow up to 64 bytes in the set element data area (Pablo Neira Ayuso)
    - netfilter: nf_tables: add nft_setelem_parse_key() (Pablo Neira Ayuso)
    - netfilter: nf_tables: validate registers coming from userspace. (Pablo Neira Ayuso)
    - netfilter: nftables: statify nft_parse_register() (Pablo Neira Ayuso)
    - netfilter: nftables: add nft_parse_register_store() and use it (Pablo Neira Ayuso)
    - netfilter: nftables: add nft_parse_register_load() and use it (Pablo Neira Ayuso)
    - nilfs2: fix use-after-free bug of nilfs_root in nilfs_evict_inode() (Ryusuke Konishi)
    - powerpc/64s/radix: Fix soft dirty tracking (Michael Ellerman)
    - tpm/tpm_tis: Disable interrupts for more Lenovo devices (Jerry Snitselaar)
    - ceph: force updating the msg pointer in non-split case (Xiubo Li)
    - serial: Add support for Advantech PCI-1611U card (Vitaliy Tomin)
    - statfs: enforce statfs[64] structure initialization (Ilya Leoshkevich)
    - KVM: x86: do not report a vCPU as preempted outside instruction boundaries (Paolo Bonzini)
    - can: kvaser_pciefd: Disable interrupts in probe error path (Jimmy Assarsson)
    - can: kvaser_pciefd: Do not send EFLUSH command on TFD interrupt (Jimmy Assarsson)
    - can: kvaser_pciefd: Clear listen-only bit if not explicitly requested (Jimmy Assarsson)
    - can: kvaser_pciefd: Empty SRB buffer in probe (Jimmy Assarsson)
    - can: kvaser_pciefd: Call request_irq() before enabling interrupts (Jimmy Assarsson)
    - can: kvaser_pciefd: Set CAN_STATE_STOPPED in kvaser_pciefd_stop() (Jimmy Assarsson)
    - can: j1939: recvmsg(): allow MSG_CMSG_COMPAT flag (Oliver Hartkopp)
    - ALSA: hda/realtek: Add quirk for 2nd ASUS GU603 (Luke D. Jones)
    - ALSA: hda/realtek: Add a quirk for HP EliteDesk 805 (Ai Chao)
    - ALSA: hda: Add NVIDIA codec IDs a3 through a7 to patch table (Nikhil Mahale)
    - ALSA: hda: Fix Oops by 9.1 surround channel names (Takashi Iwai)
    - usb: typec: altmodes/displayport: fix pin_assignment_show (Badhri Jagan Sridharan)
    - usb: dwc3: debugfs: Resume dwc3 before accessing registers (Udipto Goswami)
    - USB: UHCI: adjust zhaoxin UHCI controllers OverCurrent bit value (Weitao Wang)
    - usb-storage: fix deadlock when a scsi command timeouts more than once (Maxime Bizon)
    - USB: usbtmc: Fix direction for 0-length ioctl control messages (Alan Stern)
    - vlan: fix a potential uninit-value in vlan_dev_hard_start_xmit() (Eric Dumazet)
    - igb: fix bit_shift to be in [1..8] range (Aleksandr Loktionov)
    - cassini: Fix a memory leak in the error handling path of cas_init_one() (Christophe JAILLET)
    - wifi: iwlwifi: mvm: don't trust firmware n_channels (Johannes Berg)
    - net: bcmgenet: Restore phy_stop() depending upon suspend/close (Florian Fainelli)
    - net: bcmgenet: Remove phy_stop() from bcmgenet_netif_stop() (Florian Fainelli)
    - net: nsh: Use correct mac_offset to unwind gso skb in nsh_gso_segment() (Dong Chenchen)
    - drm/exynos: fix g2d_open/close helper function definitions (Arnd Bergmann)
    - media: netup_unidvb: fix use-after-free at del_timer() (Duoming Zhou)
    - net: hns3: fix reset delay time to avoid configuration timeout (Jie Wang)
    - net: hns3: fix sending pfc frames after reset issue (Jijie Shao)
    - erspan: get the proto with the md version for collect_md (Xin Long)
    - ip_gre, ip6_gre: Fix race condition on o_seqno in collect_md mode (Peilin Ye)
    - ip6_gre: Make o_seqno start from 0 in native mode (Peilin Ye)
    - ip6_gre: Fix skb_under_panic in __gre6_xmit() (Peilin Ye)
    - serial: arc_uart: fix of_iomap leak in arc_serial_probe (Ke Zhang)
    - vsock: avoid to close connected socket after the timeout (Zhuang Shengen)
    - ALSA: firewire-digi00x: prevent potential use after free (Dan Carpenter)
    - net: fec: Better handle pm_runtime_get() failing in .remove() (Uwe Kleine-Konig)
    - af_key: Reject optional tunnel/BEET mode templates in outbound policies (Tobias Brunner)
    - cpupower: Make TSC read per CPU for Mperf monitor (Wyes Karny)
    - ASoC: fsl_micfil: register platform component before registering cpu dai (Shengjiu Wang)
    - btrfs: fix space cache inconsistency after error loading it from disk (Filipe Manana)
    - btrfs: replace calls to btrfs_find_free_ino with btrfs_find_free_objectid (Nikolay Borisov)
    - mfd: dln2: Fix memory leak in dln2_probe() (Qiang Ning)
    - phy: st: miphy28lp: use _poll_timeout functions for waits (Alain Volmat)
    - Input: xpad - add constants for GIP interface numbers (Vicki Pfau)
    - iommu/arm-smmu-v3: Acknowledge pri/event queue overflow if any (Tomas Krcka)
    - clk: tegra20: fix gcc-7 constant overflow warning (Arnd Bergmann)
    - RDMA/core: Fix multiple -Warray-bounds warnings (Gustavo A. R. Silva)
    - recordmcount: Fix memory leaks in the uwrite function (Hao Zeng)
    - sched: Fix KCSAN noinstr violation (Josh Poimboeuf)
    - mcb-pci: Reallocate memory region to avoid memory overlapping (Rodriguez Barbarin, Jose Javier)
    - serial: 8250: Reinit port->pm on port specific driver unbind (Tony Lindgren)
    - usb: typec: tcpm: fix multiple times discover svids error (Frank Wang)
    - HID: wacom: generic: Set battery quirk only when we see battery data (Jason Gerecke)
    - spi: spi-imx: fix MX51_ECSPI_* macros when cs > 3 (Kevin Groeneveld)
    - HID: logitech-hidpp: Reconcile USB and Unifying serials (Bastien Nocera)
    - HID: logitech-hidpp: Don't use the USB serial for USB devices (Bastien Nocera)
    - staging: rtl8192e: Replace macro RTL_PCI_DEVICE with PCI_DEVICE (Philipp Hortmann)
    - Bluetooth: L2CAP: fix 'bad unlock balance' in l2cap_disconnect_rsp (Min Li)
    - wifi: iwlwifi: dvm: Fix memcpy: detected field-spanning write backtrace (Hans de Goede)
    - wifi: iwlwifi: pcie: Fix integer overflow in iwl_write_to_user_buf (Hyunwoo Kim)
    - wifi: iwlwifi: pcie: fix possible NULL pointer dereference (Daniel Gabay)
    - samples/bpf: Fix fout leak in hbm's run_bpf_prog (Hao Zeng)
    - f2fs: fix to drop all dirty pages during umount() if cp_error is set (Chao Yu)
    - ext4: Fix best extent lstart adjustment logic in ext4_mb_new_inode_pa() (Ojaswin Mujoo)
    - ext4: set goal start correctly in ext4_mb_normalize_request (Kemeng Shi)
    - gfs2: Fix inode height consistency check (Andreas Gruenbacher)
    - scsi: message: mptlan: Fix use after free bug in mptlan_remove() due to race condition (Zheng Wang)
    - lib: cpu_rmap: Avoid use after free on rmap->obj array entries (Eli Cohen)
    - net: Catch invalid index in XPS mapping (Nick Child)
    - net: pasemi: Fix return type of pasemi_mac_start_tx() (Nathan Chancellor)
    - scsi: lpfc: Prevent lpfc_debugfs_lockstat_write() buffer overflow (Justin Tee)
    - ext2: Check block size validity during mount (Jan Kara)
    - wifi: brcmfmac: cfg80211: Pass the PMK in binary instead of hex (Hector Martin)
    - ACPICA: ACPICA: check null return of ACPI_ALLOCATE_ZEROED in acpi_db_display_objects (void0red)
    - ACPICA: Avoid undefined behavior: applying zero offset to null pointer (Tamir Duberstein)
    - drm/tegra: Avoid potential 32-bit integer overflow (Nur Hussein)
    - ACPI: EC: Fix oops when removing custom query handlers (Armin Wolf)
    - firmware: arm_sdei: Fix sleep from invalid context BUG (Sherry Yang)
    - memstick: r592: Fix UAF bug in r592_remove due to race condition (Zheng Wang)
    - regmap: cache: Return error in cache sync operations for REGCACHE_NONE (Alexander Stein)
    - drm/amd/display: Use DC_LOG_DC in the trasform pixel function (Rodrigo Siqueira)
    - fs: hfsplus: remove WARN_ON() from hfsplus_cat_{read,write}_inode() (Tetsuo Handa)
    - af_unix: Fix data races around sk->sk_shutdown. (Kuniyuki Iwashima)
    - af_unix: Fix a data race of sk->sk_receive_queue->qlen. (Kuniyuki Iwashima)
    - net: datagram: fix data-races in datagram_poll() (Eric Dumazet)
    - ipvlan:Fix out-of-bounds caused by unclear skb->cb (t.feng)
    - net: add vlan_get_protocol_and_depth() helper (Eric Dumazet)
    - net: tap: check vlan with eth_type_vlan() method (Menglong Dong)
    - net: annotate sk->sk_err write from do_recvmmsg() (Eric Dumazet)
    - netlink: annotate accesses to nlk->cb_running (Eric Dumazet)
    - netfilter: conntrack: fix possible bug_on with enable_hooks=1 (Florian Westphal)
    - net: Fix load-tearing on sk->sk_stamp in sock_recv_cmsgs(). (Kuniyuki Iwashima)
    - linux/dim: Do nothing if no time delta between samples (Roy Novich)
    - ARM: 9296/1: HP Jornada 7XX: fix kernel-doc warnings (Randy Dunlap)
    - drm/mipi-dsi: Set the fwnode for mipi_dsi_device (Saravana Kannan)
    - driver core: add a helper to setup both the of_node and fwnode of a device (Ioana Ciornei)
    - LTS tag: v5.4.243 (Sherry Yang)
    - drm/amd/display: Fix hang when skipping modeset (Aurabindo Pillai)
    - mm/page_alloc: fix potential deadlock on zonelist_update_seq seqlock (Tetsuo Handa)
    - drm/exynos: move to use request_irq by IRQF_NO_AUTOEN flag (Tian Tao)
    - drm/msm/adreno: Fix null ptr access in adreno_gpu_cleanup() (Akhil P Oommen)
    - firmware: raspberrypi: fix possible memory leak in rpi_firmware_probe() (Yang Yingliang)
    - drm/msm: Fix double pm_runtime_disable() call (Maximilian Luz)
    - PM: domains: Restore comment indentation for generic_pm_domain.child_links (Geert Uytterhoeven)
    - printk: declare printk_deferred_{enter,safe}() in include/linux/printk.h (Tetsuo Handa)
    - PCI: pciehp: Fix AB-BA deadlock between reset_lock and device_lock (Lukas Wunner)
    - PCI: pciehp: Use down_read/write_nested(reset_lock) to fix lockdep errors (Hans de Goede)
    - drbd: correctly submit flush bio on barrier (Christoph Bohmwalder)
    - serial: 8250: Fix serial8250_tx_empty() race with DMA Tx (Ilpo Jarvinen)
    - tty: Prevent writing chars during tcsetattr TCSADRAIN/FLUSH (Ilpo Jarvinen)
    - ext4: fix invalid free tracking in ext4_xattr_move_to_block() (Theodore Ts'o)
    - ext4: remove a BUG_ON in ext4_mb_release_group_pa() (Theodore Ts'o)
    - ext4: bail out of ext4_xattr_ibody_get() fails for any reason (Theodore Ts'o)
    - ext4: add bounds checking in get_max_inline_xattr_value_size() (Theodore Ts'o)
    - ext4: fix deadlock when converting an inline directory in nojournal mode (Theodore Ts'o)
    - ext4: improve error recovery code paths in __ext4_remount() (Theodore Ts'o)
    - ext4: fix data races when using cached status extents (Jan Kara)
    - ext4: avoid a potential slab-out-of-bounds in ext4_group_desc_csum (Tudor Ambarus)
    - ext4: fix WARNING in mb_find_extent (Ye Bin)
    - HID: wacom: insert timestamp to packed Bluetooth (BT) events (Ping Cheng)
    - HID: wacom: Set a default resolution for older tablets (Ping Cheng)
    - drm/amdgpu: disable sdma ecc irq only when sdma RAS is enabled in suspend (Guchun Chen)
    - drm/amdgpu/gfx: disable gfx9 cp_ecc_error_irq only when enabling legacy gfx ras (Guchun Chen)
    - drm/amdgpu: fix an amdgpu_irq_put() issue in gmc_v9_0_hw_fini() (Hamza Mahfooz)
    - drm/panel: otm8009a: Set backlight parent to panel device (James Cowgill)
    - f2fs: fix potential corruption when moving a directory (Jaegeuk Kim)
    - ARM: dts: s5pv210: correct MIPI CSIS clock name (Krzysztof Kozlowski)
    - ARM: dts: exynos: fix WM8960 clock name in Itop Elite (Krzysztof Kozlowski)
    - remoteproc: st: Call of_node_put() on iteration error (Mathieu Poirier)
    - remoteproc: stm32: Call of_node_put() on iteration error (Mathieu Poirier)
    - sh: nmi_debug: fix return value of __setup handler (Randy Dunlap)
    - sh: init: use OF_EARLY_FLATTREE for early init (Randy Dunlap)
    - sh: math-emu: fix macro redefined warning (Randy Dunlap)
    - inotify: Avoid reporting event with invalid wd (Jan Kara)
    - platform/x86: touchscreen_dmi: Add info for the Dexp Ursus KX210i (Andrey Avdeev)
    - cifs: fix pcchunk length type in smb2_copychunk_range (Pawel Witek)
    - btrfs: print-tree: parent bytenr must be aligned to sector size (Anastasia Belova)
    - btrfs: don't free qgroup space unless specified (Josef Bacik)
    - btrfs: fix btrfs_prev_leaf() to not return the same key twice (Filipe Manana)
    - perf symbols: Fix return incorrect build_id size in elf_read_build_id() (Yang Jihong)
    - perf map: Delete two variable initialisations before null pointer checks in sort__sym_from_cmp() (Markus
    Elfring)
    - perf vendor events power9: Remove UTF-8 characters from JSON files (Kajol Jain)
    - virtio_net: suppress cpu stall when free_unused_bufs (Wenliang Wang)
    - virtio_net: split free_unused_bufs() (Xuan Zhuo)
    - net: dsa: mt7530: fix corrupt frames using trgmii on 40 MHz XTAL MT7621 (Ar?nc UNAL)
    - ALSA: caiaq: input: Add error handling for unsupported input methods in snd_usb_caiaq_input_init
    (Ruliang Lin)
    - drm/amdgpu: add a missing lock for AMDGPU_SCHED (Chia-I Wu)
    - af_packet: Don't send zero-byte data in packet_sendmsg_spkt(). (Kuniyuki Iwashima)
    - ionic: remove noise from ethtool rxnfc error msg (Shannon Nelson)
    - rxrpc: Fix hard call timeout units (David Howells)
    - net/sched: act_mirred: Add carrier check (Victor Nogueira)
    - writeback: fix call of incorrect macro (Maxim Korotkov)
    - net: dsa: mv88e6xxx: add mv88e6321 rsvd2cpu (Angelo Dureghello)
    - sit: update dev->needed_headroom in ipip6_tunnel_bind_dev() (Cong Wang)
    - net/sched: cls_api: remove block_cb from driver_list before freeing (Vlad Buslov)
    - net/ncsi: clear Tx enable mode when handling a Config required AEN (Cosmo Chou)
    - relayfs: fix out-of-bounds access in relay_file_read (Zhang Zhengming)
    - kernel/relay.c: fix read_pos error when multiple readers (Pengcheng Yang)
    - crypto: safexcel - Cleanup ring IRQ workqueues on load failure (Jonathan McDowell)
    - crypto: inside-secure - irq balance (Sven Auhagen)
    - dm verity: fix error handling for check_at_most_once on FEC (Yeongjin Gil)
    - dm verity: skip redundant verity_handle_err() on I/O errors (Akilesh Kailash)
    - mailbox: zynqmp: Fix counts of child nodes (Tanmay Shah)
    - mailbox: zynq: Switch to flexible array to simplify code (Christophe JAILLET)
    - tick/nohz: Fix cpu_is_hotpluggable() by checking with nohz subsystem (Joel Fernandes (Google))
    - nohz: Add TICK_DEP_BIT_RCU (Frederic Weisbecker)
    - debugobject: Ensure pool refill (again) (Thomas Gleixner)
    - perf intel-pt: Fix CYC timestamps after standalone CBR (Adrian Hunter)
    - perf auxtrace: Fix address filter entire kernel size (Adrian Hunter)
    - dm ioctl: fix nested locking in table_clear() to remove deadlock concern (Mike Snitzer)
    - dm flakey: fix a crash with invalid table line (Mikulas Patocka)
    - dm integrity: call kmem_cache_destroy() in dm_integrity_init() error path (Mike Snitzer)
    - dm clone: call kmem_cache_destroy() in dm_clone_init() error path (Mike Snitzer)
    - s390/dasd: fix hanging blockdevice after request requeue (Stefan Haberland)
    - btrfs: scrub: reject unsupported scrub flags (Qu Wenruo)
    - scripts/gdb: fix lx-timerlist for Python3 (Peng Liu)
    - clk: rockchip: rk3399: allow clk_cifout to force clk_cifout_src to reparent (Quentin Schulz)
    - wifi: rtl8xxxu: RTL8192EU always needs full init (Bitterblue Smith)
    - mailbox: zynqmp: Fix typo in IPI documentation (Tanmay Shah)
    - mailbox: zynqmp: Fix IPI isr handling (Tanmay Shah)
    - md/raid10: fix null-ptr-deref in raid10_sync_request (Li Nan)
    - nilfs2: fix infinite loop in nilfs_mdt_get_block() (Ryusuke Konishi)
    - nilfs2: do not write dirty data after degenerating to read-only (Ryusuke Konishi)
    - parisc: Fix argument pointer in real64_call_asm() (Helge Deller)
    - afs: Fix updating of i_size with dv jump from server (Marc Dionne)
    - dmaengine: at_xdmac: do not enable all cyclic channels (Claudiu Beznea)
    - dmaengine: dw-edma: Fix to enable to issue dma request on DMA processing (Shunsuke Mie)
    - dmaengine: dw-edma: Fix to change for continuous transfer (Shunsuke Mie)
    - phy: tegra: xusb: Add missing tegra_xusb_port_unregister for usb2_port and ulpi_port (Gaosheng Cui)
    - pwm: mtk-disp: Disable shadow registers before setting backlight values (AngeloGioacchino Del Regno)
    - pwm: mtk-disp: Adjust the clocks to avoid them mismatch (Jitao Shi)
    - pwm: mtk-disp: Don't check the return code of pwmchip_remove() (Uwe Kleine-Konig)
    - dmaengine: mv_xor_v2: Fix an error code. (Christophe JAILLET)
    - leds: TI_LMU_COMMON: select REGMAP instead of depending on it (Randy Dunlap)
    - ext4: fix use-after-free read in ext4_find_extent for bigalloc + inline (Ye Bin)
    - openrisc: Properly store r31 to pt_regs on unhandled exceptions (Stafford Horne)
    - clocksource/drivers/davinci: Fix memory leak in davinci_timer_register when init fails (Qinrun Dai)
    - clocksource: davinci: axe a pointless __GFP_NOFAIL (Christophe JAILLET)
    - clocksource/drivers/davinci: Avoid trailing '\n' hidden in pr_fmt() (Christophe JAILLET)
    - RDMA/mlx5: Use correct device num_ports when modify DC (Mark Zhang)
    - Input: raspberrypi-ts - fix refcount leak in rpi_ts_probe (Miaoqian Lin)
    - input: raspberrypi-ts: Release firmware handle when not needed (Nicolas Saenz Julienne)
    - firmware: raspberrypi: Introduce devm_rpi_firmware_get() (Nicolas Saenz Julienne)
    - firmware: raspberrypi: Keep count of all consumers (Nicolas Saenz Julienne)
    - NFSv4.1: Always send a RECLAIM_COMPLETE after establishing lease (Trond Myklebust)
    - IB/hfi1: Fix SDMA mmu_rb_node not being evicted in LRU order (Patrick Kelsey)
    - RDMA/siw: Remove namespace check from siw_netdev_event() (Tetsuo Handa)
    - clk: add missing of_node_put() in 'assigned-clocks' property parsing (Clement Leger)
    - power: supply: generic-adc-battery: fix unit scaling (Sebastian Reichel)
    - rtc: meson-vrtc: Use ktime_get_real_ts64() to get the current time (Martin Blumenstingl)
    - RDMA/mlx4: Prevent shift wrapping in set_user_sq_size() (Dan Carpenter)
    - rtc: omap: include header for omap_rtc_power_off_program prototype (Krzysztof Kozlowski)
    - RDMA/rdmavt: Delete unnecessary NULL check (Natalia Petrova)
    - RDMA/siw: Fix potential page_array out of range access (Daniil Dulov)
    - perf/core: Fix hardlockup failure caused by perf throttle (Yang Jihong)
    - powerpc/rtas: use memmove for potentially overlapping buffer copy (Nathan Lynch)
    - macintosh: via-pmu-led: requires ATA to be set (Randy Dunlap)
    - powerpc/sysdev/tsi108: fix resource printk format warnings (Randy Dunlap)
    - powerpc/wii: fix resource printk format warnings (Randy Dunlap)
    - powerpc/mpc512x: fix resource printk format warning (Randy Dunlap)
    - macintosh/windfarm_smu_sat: Add missing of_node_put() (Liang He)
    - spmi: Add a check for remove callback when removing a SPMI driver (Jishnu Prakash)
    - staging: rtl8192e: Fix W_DISABLE# does not work after stop/start (Philipp Hortmann)
    - serial: 8250: Add missing wakeup event reporting (Florian Fainelli)
    - tty: serial: fsl_lpuart: adjust buffer length to the intended size (Shenwei Wang)
    - firmware: stratix10-svc: Fix an NULL vs IS_ERR() bug in probe (Dan Carpenter)
    - usb: mtu3: fix kernel panic at qmu transfer done irq handler (Chunfeng Yun)
    - usb: chipidea: fix missing goto in ci_hdrc_probe (Yinhao Hu)
    - sh: sq: Fix incorrect element size for allocating bitmap buffer (John Paul Adrian Glaubitz)
    - uapi/linux/const.h: prefer ISO-friendly __typeof__ (Kevin Brodsky)
    - spi: cadence-quadspi: fix suspend-resume implementations (Dhruva Gole)
    - mtd: spi-nor: cadence-quadspi: Handle probe deferral while requesting DMA channel (Vignesh Raghavendra)
    - mtd: spi-nor: cadence-quadspi: Don't initialize rx_dma_complete on failure (Vignesh Raghavendra)
    - mtd: spi-nor: cadence-quadspi: Make driver independent of flash geometry (Vignesh Raghavendra)
    - scripts/gdb: bail early if there are no generic PD (Florian Fainelli)
    - PM: domains: Fix up terminology with parent/child (Kees Cook)
    - scripts/gdb: bail early if there are no clocks (Florian Fainelli)
    - ia64: salinfo: placate defined-but-not-used warning (Randy Dunlap)
    - ia64: mm/contig: fix section mismatch warning/error (Randy Dunlap)
    - of: Fix modalias string generation (Miquel Raynal)
    - vmci_host: fix a race condition in vmci_host_poll() causing GPF (Dae R. Jeong)
    - spi: fsl-spi: Fix CPM/QE mode Litte Endian (Christophe Leroy)
    - spi: qup: Don't skip cleanup in remove's error path (Uwe Kleine-Konig)
    - linux/vt_buffer.h: allow either builtin or modular for macros (Randy Dunlap)
    - ASoC: es8316: Handle optional IRQ assignment (Cristian Ciocaltea)
    - ASoC: es8316: Use IRQF_NO_AUTOEN when requesting the IRQ (Hans de Goede)
    - genirq: Add IRQF_NO_AUTOEN for request_irq/nmi() (Barry Song)
    - PCI: imx6: Install the fault handler only on compatible match (H. Nikolaus Schaller)
    - usb: gadget: udc: renesas_usb3: Fix use after free bug in renesas_usb3_remove due to race condition
    (Zheng Wang)
    - iio: light: max44009: add missing OF device matching (Krzysztof Kozlowski)
    - fpga: bridge: fix kernel-doc parameter description (Marco Pagani)
    - usb: host: xhci-rcar: remove leftover quirk handling (Wolfram Sang)
    - pstore: Revert pmsg_lock back to a normal mutex (John Stultz)
    - tcp/udp: Fix memleaks of sk and zerocopy skbs with TX timestamp. (Kuniyuki Iwashima)
    - net: amd: Fix link leak when verifying config failed (Gencen Gan)
    - netlink: Use copy_to_user() for optval in netlink_getsockopt(). (Kuniyuki Iwashima)
    - ipv4: Fix potential uninit variable access bug in __ip_make_skb() (Ziyang Xuan)
    - netfilter: nf_tables: don't write table validation state without mutex (Florian Westphal)
    - bpf: Don't EFAULT for getsockopt with optval=NULL (Stanislav Fomichev)
    - ixgbe: Enable setting RSS table to default values (Joe Damato)
    - ixgbe: Allow flow hash to be set via ethtool (Joe Damato)
    - wifi: iwlwifi: mvm: check firmware response size (Johannes Berg)
    - wifi: iwlwifi: make the loop for card preparation effective (Emmanuel Grumbach)
    - md/raid10: fix memleak of md thread (Yu Kuai)
    - md: update the optimal I/O size on reshape (Christoph Hellwig)
    - md/raid10: fix memleak for 'conf->bio_split' (Yu Kuai)
    - md/raid10: fix leak of 'r10bio->remaining' for recovery (Yu Kuai)
    - bpf, sockmap: Revert buggy deadlock fix in the sockhash and sockmap (Daniel Borkmann)
    - nvme-fcloop: fix 'inconsistent {IN-HARDIRQ-W} -> {HARDIRQ-ON-W} usage' (Ming Lei)
    - nvme: fix async event trace event (Keith Busch)
    - nvme: handle the persistent internal error AER (Michael Kelley)
    - bpf, sockmap: fix deadlocks in the sockhash and sockmap (Xin Liu)
    - scsi: lpfc: Fix ioremap issues in lpfc_sli4_pci_mem_setup() (Shuchang Li)
    - crypto: drbg - Only fail when jent is unavailable in FIPS mode (Herbert Xu)
    - crypto: drbg - make drbg_prepare_hrng() handle jent instantiation errors (Nicolai Stange)
    - bpftool: Fix bug for long instructions in program CFG dumps (Quentin Monnet)
    - wifi: rtlwifi: fix incorrect error codes in rtl_debugfs_set_write_reg() (Wei Chen)
    - wifi: rtlwifi: fix incorrect error codes in rtl_debugfs_set_write_rfreg() (Wei Chen)
    - rtlwifi: Replace RT_TRACE with rtl_dbg (Larry Finger)
    - rtlwifi: Start changing RT_TRACE into rtl_dbg (Larry Finger)
    - f2fs: handle dqget error in f2fs_transfer_project_quota() (Yangtao Li)
    - scsi: megaraid: Fix mega_cmd_done() CMDID_INT_CMDS (Danila Chernetsov)
    - net/packet: convert po->auxdata to an atomic flag (Eric Dumazet)
    - net/packet: convert po->origdev to an atomic flag (Eric Dumazet)
    - net/packet: annotate accesses to po->xmit (Eric Dumazet)
    - vlan: partially enable SIOCSHWTSTAMP in container (Vadim Fedorenko)
    - scm: fix MSG_CTRUNC setting condition for SO_PASSSEC (Alexander Mikhalitsyn)
    - wifi: rtw88: mac: Return the original error from rtw_mac_power_switch() (Martin Blumenstingl)
    - wifi: rtw88: mac: Return the original error from rtw_pwr_seq_parser() (Martin Blumenstingl)
    - tools: bpftool: Remove invalid \' json escape (Luis Gerhorst)
    - wifi: ath6kl: reduce WARN to dev_dbg() in callback (Fedor Pchelkin)
    - wifi: ath5k: fix an off by one check in ath5k_eeprom_read_freq_list() (Dan Carpenter)
    - wifi: ath9k: hif_usb: fix memory leak of remain_skbs (Fedor Pchelkin)
    - wifi: ath6kl: minor fix for allocation size (Alexey V. Vissarionov)
    - tick/common: Align tick period with the HZ tick. (Sebastian Andrzej Siewior)
    - tick: Get rid of tick_period (Thomas Gleixner)
    - tick/sched: Optimize tick_do_update_jiffies64() further (Thomas Gleixner)
    - tick/sched: Reduce seqcount held scope in tick_do_update_jiffies64() (Yunfeng Ye)
    - tick/sched: Use tick_next_period for lockless quick check (Thomas Gleixner)
    - timekeeping: Split jiffies seqlock (Thomas Gleixner)
    - debugobject: Prevent init race with static objects (Thomas Gleixner)
    - arm64: kgdb: Set PSTATE.SS to 1 to re-enable single-step (Sumit Garg)
    - x86/ioapic: Don't return 0 from arch_dynirq_lower_bound() (Saurabh Sengar)
    - regulator: stm32-pwr: fix of_iomap leak (YAN SHI)
    - media: rc: gpio-ir-recv: Fix support for wake-up (Florian Fainelli)
    - media: rcar_fdp1: Fix refcount leak in probe and remove function (Miaoqian Lin)
    - media: rcar_fdp1: Fix the correct variable assignments (Tang Bin)
    - media: rcar_fdp1: Make use of the helper function devm_platform_ioremap_resource() (Cai Huoqing)
    - media: rcar_fdp1: fix pm_runtime_get_sync() usage count (Mauro Carvalho Chehab)
    - media: rcar_fdp1: simplify error check logic at fdp_open() (Mauro Carvalho Chehab)
    - media: saa7134: fix use after free bug in saa7134_finidev due to race condition (Zheng Wang)
    - media: dm1105: Fix use after free bug in dm1105_remove due to race condition (Zheng Wang)
    - x86/apic: Fix atomic update of offset in reserve_eilvt_offset() (Uros Bizjak)
    - regulator: core: Avoid lockdep reports when resolving supplies (Douglas Anderson)
    - regulator: core: Consistently set mutex_owner when using ww_mutex_lock_slow() (Douglas Anderson)
    - drm/lima/lima_drv: Add missing unwind goto in lima_pdev_probe() (Harshit Mogalapalli)
    - mmc: sdhci-of-esdhc: fix quirk to ignore command inhibit for data (Georgii Kruglov)
    - drm/msm/adreno: drop bogus pm_runtime_set_active() (Johan Hovold)
    - drm/msm/adreno: Defer enabling runpm until hw_init() (Rob Clark)
    - drm/msm: fix unbalanced pm_runtime_enable in adreno_gpu_{init, cleanup} (Jonathan Marek)
    - firmware: qcom_scm: Clear download bit during reboot (Mukesh Ojha)
    - media: av7110: prevent underflow in write_ts_to_decoder() (Dan Carpenter)
    - media: uapi: add MEDIA_BUS_FMT_METADATA_FIXED media bus format. (Dafna Hirschfeld)
    - media: bdisp: Add missing check for create_workqueue (Jiasheng Jiang)
    - ARM: dts: qcom: ipq8064: Fix the PCI I/O port range (Manivannan Sadhasivam)
    - ARM: dts: qcom: ipq8064: reduce pci IO size to 64K (Christian Marangi)
    - ARM: dts: qcom: ipq4019: Fix the PCI I/O port range (Manivannan Sadhasivam)
    - EDAC/skx: Fix overflows on the DRAM row address mapping arrays (Qiuxu Zhuo)
    - arm64: dts: renesas: r8a774c0: Remove bogus voltages from OPP table (Geert Uytterhoeven)
    - arm64: dts: renesas: r8a77990: Remove bogus voltages from OPP table (Geert Uytterhoeven)
    - drm/probe-helper: Cancel previous job before starting new one (Dom Cobley)
    - drm/vgem: add missing mutex_destroy (Maira Canal)
    - drm/rockchip: Drop unbalanced obj unref (Rob Clark)
    - erofs: fix potential overflow calculating xattr_isize (Jingbo Xu)
    - erofs: stop parsing non-compact HEAD index if clusterofs is invalid (Gao Xiang)
    - tpm, tpm_tis: Do not skip reset of original interrupt vector (Lino Sanfilippo)
    - selinux: ensure av_permissions.h is built when needed (Paul Moore)
    - selinux: fix Makefile dependencies of flask.h (Ondrej Mosnacek)
    - ubifs: Free memory for tmpfile name (Marten Lindahl)
    - ubi: Fix return value overwrite issue in try_write_vid_and_data() (Wang YanQing)
    - ubifs: Fix memleak when insert_old_idx() failed (Zhihao Cheng)
    - i2c: omap: Fix standard mode false ACK readings (Reid Tonking)
    - KVM: nVMX: Emulate NOPs in L2, and PAUSE if it's not intercepted (Sean Christopherson)
    - reiserfs: Add security prefix to xattr name in reiserfs_security_write() (Roberto Sassu)
    - ring-buffer: Sync IRQ works before buffer destruction (Johannes Berg)
    - pwm: meson: Fix g12a ao clk81 name (Heiner Kallweit)
    - pwm: meson: Fix axg ao mux parents (Heiner Kallweit)
    - kheaders: Use array declaration instead of char (Kees Cook)
    - ipmi: fix SSIF not responding under certain cond. (Zhang Yuchen)
    - MIPS: fw: Allow firmware to pass a empty env (Jiaxun Yang)
    - xhci: fix debugfs register accesses while suspended (Johan Hovold)
    - debugfs: regset32: Add Runtime PM support (Geert Uytterhoeven)
    - staging: iio: resolver: ads1210: fix config mode (Nuno Sa)
    - perf sched: Cast PTHREAD_STACK_MIN to int as it may turn into sysconf(__SC_THREAD_STACK_MIN_VALUE)
    (Arnaldo Carvalho de Melo)
    - USB: dwc3: fix runtime pm imbalance on unbind (Johan Hovold)
    - USB: dwc3: fix runtime pm imbalance on probe errors (Johan Hovold)
    - asm-generic/io.h: suppress endianness warnings for readq() and writeq() (Vladimir Oltean)
    - ASoC: Intel: bytcr_rt5640: Add quirk for the Acer Iconia One 7 B1-750 (Hans de Goede)
    - iio: adc: palmas_gpadc: fix NULL dereference on rmmod (Patrik Dahlstrom)
    - USB: serial: option: add UNISOC vendor and TOZED LT70C product (Ar?nc UNAL)
    - bluetooth: Perform careful capability checks in hci_sock_ioctl() (Ruihan Li)
    - drm/fb-helper: set x/yres_virtual in drm_fb_helper_check_var (Daniel Vetter)
    - wifi: brcmfmac: slab-out-of-bounds read in brcmf_get_assoc_ies() (Jisoo Jang)
    - counter: 104-quad-8: Fix race condition between FLAG and CNTR reads (William Breathitt Gray)

    [5.4.17-2136.321.1.el7]
    - uek-rpm: Blacklist cls_tcindex module (Somasundaram Krishnasamy)  [Orabug: 35408335]
    - uek_kabi: Add UEK_KABI_DEPRECATE_ENUM (Sherry Yang)  [Orabug: 35469883]
    - perf kvm: Add kvm-stat for arm64 (Sergey Senozhatsky)  [Orabug: 35415996]
    - dsc-drivers: update ionic drivers to 23.04.1-001 (Dave Kleikamp)  [Orabug: 35416310]
    - dsc-drivers: update ionic drivers to 22.11.1-001 (Dave Kleikamp)  [Orabug: 35416310]
    - dsc-drivers: update drivers for 1.15.9-C-100 (Dave Kleikamp)  [Orabug: 35416310]
    - elba.dtsi: Improved sdclk and sdclk-hsmmc timing. (David Clear)  [Orabug: 35416310]
    - drivers/i2c: Fix Lattice RD1173 interrupt handling (Hiren Mehta)  [Orabug: 35416310]
    - defconfig: cleanup elba_defconfig (Hiren Mehta)  [Orabug: 35416310]

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-12590.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek-container and / or kernel-uek-container-debug packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34918");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39189");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter nft_set_elem_init Heap Overflow Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::UEKR6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container-debug");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.4.17-2136.321.4.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2023-12590');
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
    {'reference':'kernel-uek-container-5.4.17-2136.321.4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.4.17'},
    {'reference':'kernel-uek-container-debug-5.4.17-2136.321.4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.4.17'}
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
