#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-10023.
##

include('compat.inc');

if (description)
{
  script_id(168198);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2022-1184");

  script_name(english:"Oracle Linux 8 : Unbreakable Enterprise kernel-container (ELSA-2022-10023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2022-10023 advisory.

    [5.15.0-4.70.5.2]
    - Revert 'sched: Remove the limitation of WF_ON_CPU on wakelist if wakee cpu is idle' (Samasth Norway
    Ananda)  [Orabug: 34783367]

    [5.15.0-4.70.5.1]
    - NFSv4: Fixes for nfs4_inode_return_delegation() (Trond Myklebust)  [Orabug: 34751176]

    [5.15.0-4.70.5]
    - uek: kabi: update kABI files for new symbols (Saeed Mirzamohammadi)  [Orabug: 34595591]
    - Revert 'scsi: lpfc: SLI path split: Refactor lpfc_iocbq' (John Donnelly)  [Orabug: 34678989]
    - Revert 'scsi: lpfc: SLI path split: Refactor fast and slow paths to native SLI4' (John Donnelly)
    [Orabug: 34678989]
    - Revert 'scsi: lpfc: SLI path split: Refactor SCSI paths' (John Donnelly)  [Orabug: 34678989]
    - Revert 'scsi: lpfc: Remove extra atomic_inc on cmd_pending in queuecommand after VMID' (John Donnelly)
    [Orabug: 34678989]
    - Revert 'scsi: lpfc: Fix locking for lpfc_sli_iocbq_lookup()' (John Donnelly)  [Orabug: 34678989]
    - Revert 'scsi: lpfc: Fix element offset in __lpfc_sli_release_iocbq_s4()' (John Donnelly)  [Orabug:
    34678989]
    - Revert 'scsi: lpfc: Resolve some cleanup issues following SLI path refactoring' (John Donnelly)
    [Orabug: 34678989]
    - Revert 'scsi: lpfc: Prevent buffer overflow crashes in debugfs with malformed user input' (John
    Donnelly)  [Orabug: 34678989]
    - Revert 'scsi: lpfc: Fix possible memory leak when failing to issue CMF WQE' (John Donnelly)  [Orabug:
    34678989]
    - RDS/IB Fix allocation warning (Hans Westgaard Ry)  [Orabug: 34684321]
    - fs: remove no_llseek (Jason A. Donenfeld)  [Orabug: 34705082]
    - vfio: do not set FMODE_LSEEK flag (Jason A. Donenfeld)  [Orabug: 34705082]
    - dma-buf: remove useless FMODE_LSEEK flag (Jason A. Donenfeld)  [Orabug: 34705082]
    - fs: do not compare against ->llseek (Jason A. Donenfeld)  [Orabug: 34705082]
    - fs: clear or set FMODE_LSEEK based on llseek function (Jason A. Donenfeld)  [Orabug: 34705082]
    - hwmon: (opbmc) AST2600 SP reset driver adjustment (Jan Zdarek)  [Orabug: 34710681]
    - hwmon: (opbmc) Driver message prefixes (Jan Zdarek)  [Orabug: 34710681]
    - NFSD: fix use-after-free on source server when doing inter-server copy (Dai Ngo)  [Orabug: 34716070]

    [5.15.0-4.70.4]
    - xen/ovmapi: Build OVM guest messaging driver (Jonah Palmer)  [Orabug: 34512197]
    - net/rds: Send congestion map updates only via path zero (Anand Khoje)  [Orabug: 34578048]
    - Revert 'RDS/IB: Fix RDS IB SRQ implementation and tune it' (Hans Westgaard Ry)  [Orabug: 34662659]
    - RDMA/cma: Use output interface for net_dev check (Hakon Bugge)  [Orabug: 34694979]
    - crypto: qat - add support for 401xx devices (Giovanni Cabiddu)  [Orabug: 34686738]

    [5.15.0-4.70.3]
    - Revert 'Makefile: link with -z noexecstack --no-warn-rwx-segments' (Jack Vogel)
    - Revert 'x86: link vdso and boot with -z noexecstack --no-warn-rwx-segments' (Jack Vogel)

    [5.15.0-4.70.2]
    - LTS version: v5.15.70 (Jack Vogel)
    - ALSA: hda/sigmatel: Fix unused variable warning for beep power change (Takashi Iwai)
    - KVM: SEV: add cache flush to solve SEV cache incoherency issues (Mingwei Zhang)
    - net: Find dst with sk's xfrm policy not ctl_sk (sewookseo)
    - video: fbdev: pxa3xx-gcu: Fix integer overflow in pxa3xx_gcu_write (Hyunwoo Kim)
    - mksysmap: Fix the mismatch of 'L0' symbols in System.map (Youling Tang)
    - drm/panfrost: devfreq: set opp to the recommended one to configure regulator (Clement Peron)
    - MIPS: OCTEON: irq: Fix octeon_irq_force_ciu_mapping() (Alexander Sverdlin)
    - afs: Return -EAGAIN, not -EREMOTEIO, when a file already locked (David Howells)
    - net: usb: qmi_wwan: add Quectel RM520N (jerry.meng)
    - ALSA: hda/tegra: Align BDL entry to 4KB boundary (Mohan Kumar)
    - ALSA: hda/sigmatel: Keep power up while beep is enabled (Takashi Iwai)
    - wifi: mac80211_hwsim: check length for virtio packets (Soenke Huster)
    - rxrpc: Fix calc of resend age (David Howells)
    - rxrpc: Fix local destruction being repeated (David Howells)
    - scsi: lpfc: Return DID_TRANSPORT_DISRUPTED instead of DID_REQUEUE (Hannes Reinecke)
    - regulator: pfuze100: Fix the global-out-of-bounds access in pfuze100_regulator_probe() (Xiaolei Wang)
    - ASoC: nau8824: Fix semaphore unbalance at error paths (Takashi Iwai)
    - arm64: dts: juno: Add missing MHU secure-irq (Jassi Brar)
    - video: fbdev: i740fb: Error out if 'pixclock' equals zero (Zheyu Ma)
    - binder: remove inaccurate mmap_assert_locked() (Carlos Llamas)
    - drm/amdgpu: move nbio sdma_doorbell_range() into sdma code for vega (Alex Deucher)
    - drm/amdgpu: move nbio ih_doorbell_range() into ih code for vega (Alex Deucher)
    - drm/amdgpu: Don't enable LTR if not supported (Lijo Lazar)
    for parisc and xtensa (Ben Hutchings)
    - parisc: Allow CONFIG_64BIT with ARCH=parisc (Helge Deller)
    - cifs: always initialize struct msghdr smb_msg completely (Stefan Metzmacher)
    - cifs: don't send down the destination address to sendmsg for a SOCK_STREAM (Stefan Metzmacher)
    - cifs: revalidate mapping when doing direct writes (Ronnie Sahlberg)
    - of/device: Fix up of_dma_configure_id() stub (Thierry Reding)
    - parisc: ccio-dma: Add missing iounmap in error path in ccio_probe() (Yang Yingliang)
    - block: blk_queue_enter() / __bio_queue_enter() must return -EAGAIN for nowait (Stefan Roesch)
    - drm/meson: Fix OSD1 RGB to YCbCr coefficient (Stuart Menefy)
    - drm/meson: Correct OSD1 global alpha value (Stuart Menefy)
    - gpio: mpc8xxx: Fix support for IRQ_TYPE_LEVEL_LOW flow_type in mpc85xx (Pali Rohar)
    - NFSv4: Turn off open-by-filehandle and NFS re-export for NFSv4.0 (Trond Myklebust)
    - pinctrl: sunxi: Fix name for A100 R_PIO (Michael Wu)
    - pinctrl: rockchip: Enhance support for IRQ_TYPE_EDGE_BOTH (Joao H. Spies)
    - pinctrl: qcom: sc8180x: Fix wrong pin numbers (Molly Sophia)
    - pinctrl: qcom: sc8180x: Fix gpio_wakeirq_map (Molly Sophia)
    - of: fdt: fix off-by-one error in unflatten_dt_nodes() (Sergey Shtylyov)
    - tty: serial: atmel: Preserve previous USART mode if RS485 disabled (Sergiu Moga)
    - serial: atmel: remove redundant assignment in rs485_config (Lino Sanfilippo)
    - drm/tegra: vic: Fix build warning when CONFIG_PM=n (YueHaibing)
    - LTS version: v5.15.69 (Jack Vogel)
    - Input: goodix - add compatible string for GT1158 (Jarrah Gosbell)
    - RDMA/irdma: Use s/g array in post send only when its valid (Sindhu-Devale)
    - usb: gadget: f_uac2: fix superspeed transfer (Jing Leng)
    - usb: gadget: f_uac2: clean up some inconsistent indenting (Colin Ian King)
    - soc: fsl: select FSL_GUTS driver for DPIO (Mathew McBride)
    - mm: Fix TLB flush for not-first PFNMAP mappings in unmap_region() (Jann Horn)
    to IGNORE_UAS (Hu Xiaoying)
    - platform/x86: acer-wmi: Acer Aspire One AOD270/Packard Bell Dot keymap fixes (Hans de Goede)
    - perf/arm_pmu_platform: fix tests for platform_get_irq() failure (Yu Zhe)
    - net: dsa: hellcreek: Print warning only once (Kurt Kanzenbach)
    - drm/amd/amdgpu: skip ucode loading if ucode_size == 0 (Chengming Gui)
    - nvmet-tcp: fix unhandled tcp states in nvmet_tcp_state_change() (Maurizio Lombardi)
    - Input: iforce - add support for Boeder Force Feedback Wheel (Greg Tulli)
    - ieee802154: cc2520: add rc code in cc2520_tx() (Li Qiong)
    - gpio: mockup: remove gpio debugfs when remove device (Wei Yongjun)
    - tg3: Disable tg3 device on system reboot to avoid triggering AER (Kai-Heng Feng)
    - hid: intel-ish-hid: ishtp: Fix ishtp client sending disordered message (Even Xu)
    - HID: ishtp-hid-clientHID: ishtp-hid-client: Fix comment typo (Jason Wang)
    - dt-bindings: iio: gyroscope: bosch,bmg160: correct number of pins (Krzysztof Kozlowski)
    - drm/msm/rd: Fix FIFO-full deadlock (Rob Clark)
    - platform/surface: aggregator_registry: Add support for Surface Laptop Go 2 (Maximilian Luz)
    - Input: goodix - add support for GT1158 (Ondrej Jirman)
    - iommu/vt-d: Fix kdump kernels boot failure with scalable mode (Lu Baolu)
    - tracefs: Only clobber mode/uid/gid on remount if asked (Brian Norris)
    - tracing: hold caller_addr to hardirq_{enable,disable}_ip (Yipeng Zou)
    - task_stack, x86/cea: Force-inline stack helpers (Borislav Petkov)
    - x86/mm: Force-inline __phys_addr_nodebug() (Borislav Petkov)
    - lockdep: Fix -Wunused-parameter for _THIS_IP_ (Nick Desaulniers)
    - ARM: dts: at91: sama7g5ek: specify proper regulator output ranges (Claudiu Beznea)
    - ARM: dts: at91: fix low limit for CPU regulator (Claudiu Beznea)
    - ARM: dts: imx6qdl-kontron-samx6i: fix spi-flash compatible (Marco Felsch)
    - ARM: dts: imx: align SPI NOR node name with dtschema (Krzysztof Kozlowski)
    - ACPI: resource: skip IRQ override on AMD Zen platforms (Chuanhong Guo)
    - NFS: Fix WARN_ON due to unionization of nfs_inode.nrequests (Dave Wysochanski)
    - LTS version: v5.15.68 (Jack Vogel)
    - ARM: at91: ddr: remove CONFIG_SOC_SAMA7 dependency (Claudiu Beznea)
    - perf machine: Use path__join() to compose a path instead of snprintf(dir, '/', filename) (Arnaldo
    Carvalho de Melo)
    - drm/bridge: display-connector: implement bus fmts callbacks (Neil Armstrong)
    - arm64: errata: add detection for AMEVCNTR01 incrementing incorrectly (Ionela Voinescu)
    - iommu/vt-d: Correctly calculate sagaw value of IOMMU (Lu Baolu)
    - arm64/bti: Disable in kernel BTI when cross section thunks are broken (Mark Brown)
    - Revert 'arm64: kasan: Revert 'arm64: mte: reset the page tag in page->flags'' (Sasha Levin)
    - hwmon: (mr75203) enable polling for all VM channels (Eliav Farber)
    - hwmon: (mr75203) fix multi-channel voltage reading (Eliav Farber)
    - hwmon: (mr75203) fix voltage equation for negative source input (Eliav Farber)
    - hwmon: (mr75203) update pvt->v_num and vm_num to the actual number of used sensors (Eliav Farber)
    - hwmon: (mr75203) fix VM sensor allocation when 'intel,vm-map' not defined (Eliav Farber)
    - s390/boot: fix absolute zero lowcore corruption on boot (Alexander Gordeev)
    - iommu/amd: use full 64-bit value in build_completion_wait() (John Sperbeck)
    - swiotlb: avoid potential left shift overflow (Chao Gao)
    - i40e: Fix ADQ rate limiting for PF (Przemyslaw Patynowski)
    - i40e: Refactor tc mqprio checks (Przemyslaw Patynowski)
    - kbuild: disable header exports for UML in a straightforward way (Masahiro Yamada)
    - MIPS: loongson32: ls1c: Fix hang during startup (Yang Ling)
    - ASoC: mchp-spdiftx: Fix clang -Wbitfield-constant-conversion (Nathan Chancellor)
    - ASoC: mchp-spdiftx: remove references to mchp_i2s_caps (Claudiu Beznea)
    - hwmon: (tps23861) fix byte order in resistance register (Alexandru Gagniuc)
    - perf script: Fix Cannot print 'iregs' field for hybrid systems (Zhengjun Xing)
    - sch_sfb: Also store skb len before calling child enqueue (Toke Hoiland-Jorgensen)
    - RDMA/irdma: Report RNR NAK generation in device caps (Sindhu-Devale)
    - RDMA/irdma: Return correct WC error for bind operation failure (Sindhu-Devale)
    - RDMA/irdma: Report the correct max cqes from query device (Sindhu-Devale)
    - nvmet: fix mar and mor off-by-one errors (Dennis Maisenbacher)
    - tcp: fix early ETIMEDOUT after spurious non-SACK RTO (Neal Cardwell)
    - nvme-tcp: fix regression that causes sporadic requests to time out (Sagi Grimberg)
    - nvme-tcp: fix UAF when detecting digest errors (Sagi Grimberg)
    - erofs: fix pcluster use-after-free on UP platforms (Gao Xiang)
    - RDMA/mlx5: Set local port to one when accessing counters (Chris Mi)
    - IB/core: Fix a nested dead lock as part of ODP flow (Yishai Hadas)
    - ipv6: sr: fix out-of-bounds read when setting HMAC data. (David Lebrun)
    - RDMA/siw: Pass a pointer to virt_to_page() (Linus Walleij)
    - xen-netback: only remove 'hotplug-status' when the vif is actually destroyed (Paul Durrant)
    - iavf: Detach device during reset task (Ivan Vecera)
    - i40e: Fix kernel crash during module removal (Ivan Vecera)
    - ice: use bitmap_free instead of devm_kfree (Michal Swiatkowski)
    - tcp: TX zerocopy should not sense pfmemalloc status (Eric Dumazet)
    - net: introduce __skb_fill_page_desc_noacc (Pavel Begunkov)
    - tipc: fix shift wrapping bug in map_get() (Dan Carpenter)
    - sch_sfb: Don't assume the skb is still around after enqueueing to child (Toke Hoiland-Jorgensen)
    - Revert 'net: phy: meson-gxl: improve link-up behavior' (Heiner Kallweit)
    - afs: Use the operation issue time instead of the reply time for callbacks (David Howells)
    - rxrpc: Fix an insufficiently large sglist in rxkad_verify_packet_2() (David Howells)
    - rxrpc: Fix ICMP/ICMP6 error handling (David Howells)
    - ALSA: usb-audio: Register card again for iface over delayed_register option (Takashi Iwai)
    - ALSA: usb-audio: Inform the delayed registration more properly (Takashi Iwai)
    - RDMA/srp: Set scmnd->result only when scmnd is not NULL (yangx.jy@fujitsu.com)
    - netfilter: nf_conntrack_irc: Fix forged IP logic (David Leadbeater)
    - netfilter: nf_tables: clean up hook list when offload flags check fails (Pablo Neira Ayuso)
    - netfilter: br_netfilter: Drop dst references before setting. (Harsh Modi)
    - ARM: dts: at91: sama5d2_icp: don't keep vdd_other enabled all the time (Claudiu Beznea)
    - ARM: dts: at91: sama5d27_wlsom1: don't keep ldo2 enabled all the time (Claudiu Beznea)
    - ARM: dts: at91: sama5d2_icp: specify proper regulator output ranges (Claudiu Beznea)
    - ARM: dts: at91: sama5d27_wlsom1: specify proper regulator output ranges (Claudiu Beznea)
    - ARM: at91: pm: fix DDR recalibration when resuming from backup and self-refresh (Claudiu Beznea)
    - ARM: at91: pm: fix self-refresh for sama7g5 (Claudiu Beznea)
    - wifi: wilc1000: fix DMA on stack objects (Ajay.Kathat@microchip.com)
    - RDMA/hns: Fix wrong fixed value of qp->rq.wqe_shift (Wenpeng Liang)
    - RDMA/hns: Fix supported page size (Chengchang Tang)
    - soc: brcmstb: pm-arm: Fix refcount leak and __iomem leak bugs (Liang He)
    - RDMA/cma: Fix arguments order in net device validation (Michael Guralnik)
    - tee: fix compiler warning in tee_shm_register() (Jens Wiklander)
    - regulator: core: Clean up on enable failure (Andrew Halaney)
    - soc: imx: gpcv2: Assert reset before ungating clock (Marek Vasut)
    - ARM: dts: imx6qdl-kontron-samx6i: remove duplicated node (Marco Felsch)
    - RDMA/rtrs-srv: Pass the correct number of entries for dma mapped SGL (Jack Wang)
    - RDMA/rtrs-clt: Use the right sg_cnt after ib_dma_map_sg (Jack Wang)
    - ASoC: qcom: sm8250: add missing module owner (Srinivas Kandagatla)
    - cgroup: Elide write-locking threadgroup_rwsem when updating csses on an empty subtree (Tejun Heo)
    - NFS: Fix another fsync() issue after a server reboot (Trond Myklebust)
    - NFS: Save some space in the inode (Trond Myklebust)
    - NFS: Further optimisations for 'ls -l' (Trond Myklebust)
    - scsi: lpfc: Add missing destroy_workqueue() in error path (Yang Yingliang)
    - scsi: mpt3sas: Fix use-after-free warning (Sreekanth Reddy)
    - drm/i915: Implement WaEdpLinkRateDataReload (Ville Syrjala)
    - nvmet: fix a use-after-free (Bart Van Assche)
    - drm/amd/display: fix memory leak when using debugfs_lookup() (Greg Kroah-Hartman)
    - sched/debug: fix dentry leak in update_sched_domain_debugfs (Greg Kroah-Hartman)
    - debugfs: add debugfs_lookup_and_remove() (Greg Kroah-Hartman)
    - kprobes: Prohibit probes in gate area (Christian A. Ehrhardt)
    - vfio/type1: Unpin zero pages (Alex Williamson)
    - btrfs: zoned: set pseudo max append zone limit in zone emulation mode (Shin'ichiro Kawasaki)
    - tracing: Fix to check event_mutex is held while accessing trigger list (Masami Hiramatsu (Google))
    - ALSA: usb-audio: Fix an out-of-bounds bug in __snd_usb_parse_audio_interface() (Dongxiang Ke)
    - ALSA: usb-audio: Split endpoint setups for hw_params and prepare (Takashi Iwai)
    - ALSA: aloop: Fix random zeros in capture data when using jiffies timer (Pattara Teerapong)
    - ALSA: emu10k1: Fix out of bounds access in snd_emu10k1_pcm_channel_alloc() (Tasos Sahanidis)
    - ALSA: pcm: oss: Fix race at SNDCTL_DSP_SYNC (Takashi Iwai)
    - drm/amdgpu: mmVM_L2_CNTL3 register not initialized correctly (Qu Huang)
    - fbdev: chipsfb: Add missing pci_disable_device() in chipsfb_pci_init() (Yang Yingliang)
    - fbdev: fbcon: Destroy mutex on freeing struct fb_info (Shigeru Yoshida)
    - md: Flush workqueue md_rdev_misc_wq in md_alloc() (David Sloan)
    - net/core/skbuff: Check the return value of skb_copy_bits() (lily)
    - cpufreq: check only freq_table in __resolve_freq() (Lukasz Luba)
    - netfilter: conntrack: work around exceeded receive window (Florian Westphal)
    - arm64: cacheinfo: Fix incorrect assignment of signed error value to unsigned fw_level (Sudeep Holla)
    - parisc: Add runtime check to prevent PA2.0 kernels on PA1.x machines (Helge Deller)
    - parisc: ccio-dma: Handle kmalloc failure in ccio_init_resources() (Li Qiong)
    - Revert 'parisc: Show error if wrong 32/64-bit compiler is being used' (Helge Deller)
    - scsi: ufs: core: Reduce the power mode change timeout (Bart Van Assche)
    - drm/radeon: add a force flush to delay work when radeon (Zhenneng Li)
    - drm/amdgpu: Check num_gfx_rings for gfx v9_0 rb setup. (Candice Li)
    - drm/amdgpu: Move psp_xgmi_terminate call from amdgpu_xgmi_remove_device to psp_hw_fini (YiPeng Chai)
    - drm/gem: Fix GEM handle release errors (Jeffy Chen)
    - scsi: megaraid_sas: Fix double kfree() (Guixin Liu)
    - scsi: qla2xxx: Disable ATIO interrupt coalesce for quad port ISP27XX (Tony Battersby)
    - Revert 'mm: kmemleak: take a full lowmem check in kmemleak_*_phys()' (Yee Lee)
    - fs: only do a memory barrier for the first set_buffer_uptodate() (Linus Torvalds)
    - wifi: iwlegacy: 4965: corrected fix for potential off-by-one overflow in il4965_rs_fill_link_cmd()
    (Stanislaw Gruszka)
    - efi: capsule-loader: Fix use-after-free in efi_capsule_write (Hyunwoo Kim)
    - efi: libstub: Disable struct randomization (Ard Biesheuvel)
    - net: wwan: iosm: remove pointless null check (Jakub Kicinski)
    - LTS version: v5.15.67 (Jack Vogel)
    - kbuild: fix up permissions on scripts/pahole-flags.sh (Greg Kroah-Hartman)
    - LTS version: v5.15.66 (Jack Vogel)
    - USB: serial: ch341: fix disabled rx timer on older devices (Johan Hovold)
    - USB: serial: ch341: fix lost character on LCR updates (Johan Hovold)
    - usb: dwc3: disable USB core PHY management (Johan Hovold)
    - usb: dwc3: qcom: fix use-after-free on runtime-PM wakeup (Johan Hovold)
    - usb: dwc3: fix PHY disable sequence (Johan Hovold)
    - kbuild: Add skip_encoding_btf_enum64 option to pahole (Martin Rodriguez Reboredo)
    - kbuild: Unify options for BTF generation for vmlinux and modules (Jiri Olsa)
    - tty: n_gsm: add sanity check for gsm->receive in gsm_receive_buf() (Mazin Al Haddad)
    - drm/i915: Skip wm/ddb readout for disabled pipes (Ville Syrjala)
    - drm/i915/glk: ECS Liva Q2 needs GLK HDMI port timing quirk (Diego Santa Cruz)
    - ALSA: seq: Fix data-race at module auto-loading (Takashi Iwai)
    - ALSA: seq: oss: Fix data-race for max_midi_devs access (Takashi Iwai)
    - ALSA: hda/realtek: Add speaker AMP init for Samsung laptops with ALC298 (Kacper Michajlow)
    - net: mac802154: Fix a condition in the receive path (Miquel Raynal)
    - net: Use u64_stats_fetch_begin_irq() for stats fetch. (Sebastian Andrzej Siewior)
    - ip: fix triggering of 'icmp redirect' (Nicolas Dichtel)
    - wifi: mac80211: Fix UAF in ieee80211_scan_rx() (Siddh Raman Pant)
    - wifi: mac80211: Don't finalize CSA in IBSS mode if state is disconnected (Siddh Raman Pant)
    - driver core: Don't probe devices after bus_type.match() probe deferral (Isaac J. Manjarres)
    - usb: gadget: mass_storage: Fix cdrom data transfers on MAC-OS (Krishna Kurapati)
    - usb: xhci-mtk: fix bandwidth release issue (Chunfeng Yun)
    - usb: xhci-mtk: relax TT periodic bandwidth allocation (Chunfeng Yun)
    - USB: core: Prevent nested device-reset calls (Alan Stern)
    - s390: fix nospec table alignments (Josh Poimboeuf)
    - s390/hugetlb: fix prepare_hugepage_range() check for 2 GB hugepages (Gerald Schaefer)
    - usb-storage: Add ignore-residue quirk for NXP PN7462AU (Witold Lipieta)
    - USB: cdc-acm: Add Icom PMR F3400 support (0c26:0020) (Thierry GUIBERT)
    - usb: cdns3: fix incorrect handling TRB_SMM flag for ISOC transfer (Pawel Laszczak)
    - usb: cdns3: fix issue with rearming ISO OUT endpoint (Pawel Laszczak)
    - usb: dwc2: fix wrong order of phy_power_on and phy_init (Heiner Kallweit)
    - usb: typec: tcpm: Return ENOTSUPP for power supply prop writes (Badhri Jagan Sridharan)
    - usb: typec: intel_pmc_mux: Add new ACPI ID for Meteor Lake IOM device (Utkarsh Patel)
    - usb: typec: altmodes/displayport: correct pin assignment for UFP receptacles (Pablo Sun)
    - USB: serial: option: add support for Cinterion MV32-WA/WB RmNet mode (Slark Xiao)
    - USB: serial: option: add Quectel EM060K modem (Yonglin Tan)
    - USB: serial: option: add support for OPPO R11 diag port (Yan Xinyu)
    - USB: serial: cp210x: add Decagon UCA device id (Johan Hovold)
    - xhci: Add grace period after xHC start to prevent premature runtime suspend. (Mathias Nyman)
    - media: mceusb: Use new usb_control_msg_*() routines (Alan Stern)
    - usb: dwc3: pci: Add support for Intel Raptor Lake (Heikki Krogerus)
    - thunderbolt: Use the actual buffer in tb_async_error() (Mika Westerberg)
    - xen-blkfront: Cache feature_persistent value before advertisement (SeongJae Park)
    - xen-blkfront: Advertise feature-persistent as user requested (SeongJae Park)
    - xen-blkback: Advertise feature-persistent as user requested (SeongJae Park)
    - mm: pagewalk: Fix race between unmap and page walker (Steven Price)
    - xen/grants: prevent integer overflow in gnttab_dma_alloc_pages() (Dan Carpenter)
    - KVM: x86: Mask off unsupported and unknown bits of IA32_ARCH_CAPABILITIES (Jim Mattson)
    - gpio: pca953x: Add mutex_lock for regcache sync in PM (Haibo Chen)
    - hwmon: (gpio-fan) Fix array out of bounds access (Armin Wolf)
    - clk: bcm: rpi: Add missing newline (Stefan Wahren)
    - clk: bcm: rpi: Prevent out-of-bounds access (Stefan Wahren)
    - clk: bcm: rpi: Use correct order for the parameters of devm_kcalloc() (Christophe JAILLET)
    - clk: bcm: rpi: Fix error handling of raspberrypi_fw_get_rate (Stefan Wahren)
    - Input: rk805-pwrkey - fix module autoloading (Peter Robinson)
    - clk: core: Fix runtime PM sequence in clk_core_unprepare() (Chen-Yu Tsai)
    - Revert 'clk: core: Honor CLK_OPS_PARENT_ENABLE for clk gate ops' (Stephen Boyd)
    - clk: core: Honor CLK_OPS_PARENT_ENABLE for clk gate ops (Chen-Yu Tsai)
    - drm/i915/reg: Fix spelling mistake 'Unsupport' -> 'Unsupported' (Colin Ian King)
    - KVM: VMX: Heed the 'msr' argument in msr_write_intercepted() (Jim Mattson)
    - cifs: fix small mempool leak in SMB2_negotiate() (Enzo Matsumiya)
    - binder: fix alloc->vma_vm_mm null-ptr dereference (Carlos Llamas)
    - binder: fix UAF of ref->proc caused by race condition (Carlos Llamas)
    - mmc: core: Fix inconsistent sd3_bus_mode at UHS-I SD voltage switch failure (Adrian Hunter)
    - mmc: core: Fix UHS-I SD 1.8V workaround branch (Adrian Hunter)
    - USB: serial: ftdi_sio: add Omron CS1W-CIF31 device id (Niek Nooijens)
    - misc: fastrpc: fix memory corruption on open (Johan Hovold)
    - misc: fastrpc: fix memory corruption on probe (Johan Hovold)
    - iio: adc: mcp3911: use correct formula for AD conversion (Marcus Folkesson)
    - iio: ad7292: Prevent regulator double disable (Matti Vaittinen)
    - Input: iforce - wake up after clearing IFORCE_XMIT_RUNNING flag (Tetsuo Handa)
    - tty: serial: lpuart: disable flow control while waiting for the transmit engine to complete (Sherry Sun)
    - musb: fix USB_MUSB_TUSB6010 dependency (Arnd Bergmann)
    - vt: Clear selection before changing the font (Helge Deller)
    - powerpc: align syscall table for ppc32 (Masahiro Yamada)
    - staging: r8188eu: add firmware dependency (Grzegorz Szymaszek)
    - staging: rtl8712: fix use after free bugs (Dan Carpenter)
    - serial: fsl_lpuart: RS485 RTS polariy is inverse (Shenwei Wang)
    - soundwire: qcom: fix device status array range (Srinivas Kandagatla)
    - net/smc: Remove redundant refcount increase (Yacan Liu)
    - Revert 'sch_cake: Return __NET_XMIT_STOLEN when consuming enqueued skb' (Jakub Kicinski)
    - tcp: annotate data-race around challenge_timestamp (Eric Dumazet)
    - sch_cake: Return __NET_XMIT_STOLEN when consuming enqueued skb (Toke Hoiland-Jorgensen)
    - kcm: fix strp_init() order and cleanup (Cong Wang)
    - mlxbf_gige: compute MDIO period based on i1clk (David Thompson)
    - ethernet: rocker: fix sleep in atomic context bug in neigh_timer_handler (Duoming Zhou)
    - net/sched: fix netdevice reference leaks in attach_default_qdiscs() (Wang Hai)
    - net: sched: tbf: don't call qdisc_put() while holding tree lock (Zhengchao Shao)
    - net: dsa: xrs700x: Use irqsave variant for u64 stats update (Sebastian Andrzej Siewior)
    - openvswitch: fix memory leak at failed datapath creation (Andrey Zhadchenko)
    - net: smsc911x: Stop and start PHY during suspend and resume (Florian Fainelli)
    - net: sparx5: fix handling uneven length packets in manual extraction (Casper Andersson)
    - Revert 'xhci: turn off port power in shutdown' (Mathias Nyman)
    - wifi: cfg80211: debugfs: fix return type in ht40allow_map_read() (Dan Carpenter)
    - ALSA: hda: intel-nhlt: Correct the handling of fmt_config flexible array (Peter Ujfalusi)
    - ALSA: hda: intel-nhlt: remove use of __func__ in dev_dbg (Pierre-Louis Bossart)
    - drm/i915/display: avoid warnings when registering dual panel backlight (Arun R Murthy)
    - drm/i915/backlight: extract backlight code to a separate file (Jani Nikula)
    - ieee802154/adf7242: defer destroy_workqueue call (Lin Ma)
    - bpf, cgroup: Fix kernel BUG in purge_effective_progs (Pu Lehui)
    - bpf: Restrict bpf_sys_bpf to CAP_PERFMON (YiFei Zhu)
    - skmsg: Fix wrong last sg check in sk_msg_recvmsg() (Liu Jian)
    - iio: adc: mcp3911: make use of the sign bit (Marcus Folkesson)
    - platform/x86: pmc_atom: Fix SLP_TYPx bitfield mask (Andy Shevchenko)
    - drm/msm/dsi: Fix number of regulators for SDM660 (Douglas Anderson)
    - drm/msm/dsi: Fix number of regulators for msm8996_dsi_cfg (Douglas Anderson)
    - drm/msm/dp: delete DP_RECOVERED_CLOCK_OUT_EN to fix tps4 (Kuogee Hsieh)
    - drm/msm/dsi: fix the inconsistent indenting (sunliming)
    - LTS version: v5.15.65 (Jack Vogel)
    - net: neigh: don't call kfree_skb() under spin_lock_irqsave() (Yang Yingliang)
    - net/af_packet: check len when min_header_len equals to 0 (Zhengchao Shao)
    - android: binder: fix lockdep check on clearing vma (Liam Howlett)
    - btrfs: fix space cache corruption and potential double allocations (Omar Sandoval)
    - kprobes: don't call disarm_kprobe() for disabled kprobes (Kuniyuki Iwashima)
    - btrfs: tree-checker: check for overlapping extent items (Josef Bacik)
    - btrfs: fix lockdep splat with reloc root extent buffers (Josef Bacik)
    - btrfs: move lockdep class helpers to locking.c (Josef Bacik)
    - testing: selftests: nft_flowtable.sh: use random netns names (Florian Westphal)
    - netfilter: conntrack: NF_CONNTRACK_PROCFS should no longer default to y (Geert Uytterhoeven)
    - drm/amd/display: avoid doing vm_init multiple time (Charlene Liu)
    - drm/amdgpu: Increase tlb flush timeout for sriov (Dusica Milinkovic)
    - drm/amd/display: Fix pixel clock programming (Ilya Bakoulin)
    - drm/amd/pm: add missing ->fini_microcode interface for Sienna Cichlid (Evan Quan)
    - ksmbd: don't remove dos attribute xattr on O_TRUNC open (Namjae Jeon)
    - s390/hypfs: avoid error message under KVM (Juergen Gross)
    - neigh: fix possible DoS due to net iface start/stop loop (Denis V. Lunev)
    - ksmbd: return STATUS_BAD_NETWORK_NAME error status if share is not configured (Namjae Jeon)
    - drm/amd/display: clear optc underflow before turn off odm clock (Fudong Wang)
    - drm/amd/display: For stereo keep 'FLIP_ANY_FRAME' (Alvin Lee)
    - drm/amd/display: Fix HDMI VSIF V3 incorrect issue (Leo Ma)
    - drm/amd/display: Avoid MPC infinite loop (Josip Pavic)
    - ASoC: sh: rz-ssi: Improve error handling in rz_ssi_probe() error path (Biju Das)
    - fs/ntfs3: Fix work with fragmented xattr (Konstantin Komarov)
    - btrfs: fix warning during log replay when bumping inode link count (Filipe Manana)
    - btrfs: add and use helper for unlinking inode during log replay (Filipe Manana)
    - btrfs: remove no longer needed logic for replaying directory deletes (Filipe Manana)
    - btrfs: remove root argument from btrfs_unlink_inode() (Filipe Manana)
    - mmc: sdhci-of-dwcmshc: Re-enable support for the BlueField-3 SoC (Liming Sun)
    - mmc: sdhci-of-dwcmshc: rename rk3568 to rk35xx (Sebastian Reichel)
    - mmc: sdhci-of-dwcmshc: add reset call back for rockchip Socs (Yifeng Zhao)
    - mmc: mtk-sd: Clear interrupts when cqe off/disable (Wenbin Mei)
    - drm/i915/gt: Skip TLB invalidations once wedged (Chris Wilson)
    - HID: thrustmaster: Add sparco wheel and fix array length (Michael Hubner)
    - HID: asus: ROG NKey: Ignore portion of 0x5a report (Josh Kilmer)
    - HID: AMD_SFH: Add a DMI quirk entry for Chromebooks (Akihiko Odaki)
    - HID: add Lenovo Yoga C630 battery quirk (Steev Klimaszewski)
    - ALSA: usb-audio: Add quirk for LH Labs Geek Out HD Audio 1V5 (Takashi Iwai)
    - mm/rmap: Fix anon_vma->degree ambiguity leading to double-reuse (Jann Horn)
    - bpf: Don't redirect packets with invalid pkt_len (Zhengchao Shao)
    - ftrace: Fix NULL pointer dereference in is_ftrace_trampoline when ftrace is dead (Yang Jihong)
    - fbdev: fb_pm2fb: Avoid potential divide by zero error (Letu Ren)
    - net: fix refcount bug in sk_psock_get (2) (Hawkins Jiawei)
    - HID: hidraw: fix memory leak in hidraw_release() (Karthik Alapati)
    - media: pvrusb2: fix memory leak in pvr_probe (Dongliang Mu)
    - udmabuf: Set the DMA mask for the udmabuf device (v2) (Vivek Kasireddy)
    - HID: steam: Prevent NULL pointer dereference in steam_{recv,send}_report (Lee Jones)
    - Revert 'PCI/portdrv: Don't disable AER reporting in get_port_device_capability()' (Greg Kroah-Hartman)
    - Bluetooth: L2CAP: Fix build errors in some archs (Luiz Augusto von Dentz)
    - kbuild: Fix include path in scripts/Makefile.modpost (Jing Leng)
    - io_uring: fix UAF due to missing POLLFREE handling (Pavel Begunkov)
    - io_uring: fix wrong arm_poll error handling (Pavel Begunkov)
    - io_uring: fail links when poll fails (Pavel Begunkov)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-10023.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-uek-container and / or kernel-uek-container-debug packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1184");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-container-debug");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.15.0-4.70.5.2.el8'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2022-10023');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.15';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-uek-container-5.15.0-4.70.5.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-5.15.0'},
    {'reference':'kernel-uek-container-debug-5.15.0-4.70.5.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uek-container-debug-5.15.0'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-uek-container / kernel-uek-container-debug');
}
