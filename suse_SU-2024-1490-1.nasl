#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1490-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(194976);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/23");

  script_cve_id(
    "CVE-2021-46925",
    "CVE-2021-46926",
    "CVE-2021-46927",
    "CVE-2021-46929",
    "CVE-2021-46930",
    "CVE-2021-46931",
    "CVE-2021-46933",
    "CVE-2021-46936",
    "CVE-2021-47082",
    "CVE-2021-47087",
    "CVE-2021-47091",
    "CVE-2021-47093",
    "CVE-2021-47094",
    "CVE-2021-47095",
    "CVE-2021-47096",
    "CVE-2021-47097",
    "CVE-2021-47098",
    "CVE-2021-47099",
    "CVE-2021-47100",
    "CVE-2021-47101",
    "CVE-2021-47102",
    "CVE-2021-47104",
    "CVE-2021-47105",
    "CVE-2021-47107",
    "CVE-2021-47108",
    "CVE-2021-47181",
    "CVE-2021-47182",
    "CVE-2021-47183",
    "CVE-2021-47185",
    "CVE-2021-47189",
    "CVE-2022-4744",
    "CVE-2022-48626",
    "CVE-2022-48629",
    "CVE-2022-48630",
    "CVE-2023-0160",
    "CVE-2023-4881",
    "CVE-2023-6356",
    "CVE-2023-6535",
    "CVE-2023-6536",
    "CVE-2023-7042",
    "CVE-2023-7192",
    "CVE-2023-28746",
    "CVE-2023-35827",
    "CVE-2023-52447",
    "CVE-2023-52450",
    "CVE-2023-52453",
    "CVE-2023-52454",
    "CVE-2023-52469",
    "CVE-2023-52470",
    "CVE-2023-52474",
    "CVE-2023-52476",
    "CVE-2023-52477",
    "CVE-2023-52481",
    "CVE-2023-52484",
    "CVE-2023-52486",
    "CVE-2023-52488",
    "CVE-2023-52492",
    "CVE-2023-52493",
    "CVE-2023-52494",
    "CVE-2023-52497",
    "CVE-2023-52500",
    "CVE-2023-52501",
    "CVE-2023-52502",
    "CVE-2023-52503",
    "CVE-2023-52504",
    "CVE-2023-52507",
    "CVE-2023-52508",
    "CVE-2023-52509",
    "CVE-2023-52510",
    "CVE-2023-52511",
    "CVE-2023-52513",
    "CVE-2023-52515",
    "CVE-2023-52517",
    "CVE-2023-52518",
    "CVE-2023-52519",
    "CVE-2023-52520",
    "CVE-2023-52523",
    "CVE-2023-52524",
    "CVE-2023-52525",
    "CVE-2023-52528",
    "CVE-2023-52529",
    "CVE-2023-52532",
    "CVE-2023-52561",
    "CVE-2023-52563",
    "CVE-2023-52564",
    "CVE-2023-52566",
    "CVE-2023-52567",
    "CVE-2023-52569",
    "CVE-2023-52574",
    "CVE-2023-52575",
    "CVE-2023-52576",
    "CVE-2023-52582",
    "CVE-2023-52583",
    "CVE-2023-52587",
    "CVE-2023-52591",
    "CVE-2023-52594",
    "CVE-2023-52595",
    "CVE-2023-52597",
    "CVE-2023-52598",
    "CVE-2023-52599",
    "CVE-2023-52600",
    "CVE-2023-52601",
    "CVE-2023-52602",
    "CVE-2023-52603",
    "CVE-2023-52604",
    "CVE-2023-52605",
    "CVE-2023-52606",
    "CVE-2023-52607",
    "CVE-2023-52608",
    "CVE-2023-52612",
    "CVE-2023-52615",
    "CVE-2023-52617",
    "CVE-2023-52619",
    "CVE-2023-52621",
    "CVE-2023-52623",
    "CVE-2023-52627",
    "CVE-2023-52628",
    "CVE-2023-52632",
    "CVE-2023-52636",
    "CVE-2023-52637",
    "CVE-2023-52639",
    "CVE-2024-0841",
    "CVE-2024-2201",
    "CVE-2024-22099",
    "CVE-2024-23307",
    "CVE-2024-23850",
    "CVE-2024-25739",
    "CVE-2024-25742",
    "CVE-2024-26599",
    "CVE-2024-26600",
    "CVE-2024-26602",
    "CVE-2024-26612",
    "CVE-2024-26614",
    "CVE-2024-26620",
    "CVE-2024-26627",
    "CVE-2024-26629",
    "CVE-2024-26642",
    "CVE-2024-26645",
    "CVE-2024-26646",
    "CVE-2024-26651",
    "CVE-2024-26654",
    "CVE-2024-26659",
    "CVE-2024-26660",
    "CVE-2024-26664",
    "CVE-2024-26667",
    "CVE-2024-26670",
    "CVE-2024-26680",
    "CVE-2024-26681",
    "CVE-2024-26684",
    "CVE-2024-26685",
    "CVE-2024-26689",
    "CVE-2024-26695",
    "CVE-2024-26696",
    "CVE-2024-26697",
    "CVE-2024-26704",
    "CVE-2024-26717",
    "CVE-2024-26718",
    "CVE-2024-26722",
    "CVE-2024-26727",
    "CVE-2024-26733",
    "CVE-2024-26736",
    "CVE-2024-26737",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26745",
    "CVE-2024-26747",
    "CVE-2024-26749",
    "CVE-2024-26751",
    "CVE-2024-26754",
    "CVE-2024-26760",
    "CVE-2024-26763",
    "CVE-2024-26766",
    "CVE-2024-26769",
    "CVE-2024-26771",
    "CVE-2024-26776",
    "CVE-2024-26779",
    "CVE-2024-26787",
    "CVE-2024-26790",
    "CVE-2024-26793",
    "CVE-2024-26798",
    "CVE-2024-26805",
    "CVE-2024-26807",
    "CVE-2024-26848"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1490-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2024:1490-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2024:1490-1 advisory.

    The SUSE Linux Enterprise 15 SP5 Azure kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2021-46925: Fixed kernel panic caused by race of smc_sock (bsc#1220466).
    - CVE-2021-46926: Fixed bug when detecting controllers in ALSA/hda/intel-sdw-acpi (bsc#1220478).
    - CVE-2021-46927: Fixed assertion bug in nitro_enclaves: Use get_user_pages_unlocked() (bsc#1220443).
    - CVE-2021-46929: Fixed use-after-free issue in sctp_sock_dump() (bsc#1220482).
    - CVE-2021-46930: Fixed usb/mtu3 list_head check warning (bsc#1220484).
    - CVE-2021-46931: Fixed wrong type casting in mlx5e_tx_reporter_dump_sq() (bsc#1220486).
    - CVE-2021-46933: Fixed possible underflow in ffs_data_clear() (bsc#1220487).
    - CVE-2021-46936: Fixed use-after-free in tw_timer_handler() (bsc#1220439).
    - CVE-2021-47082: Fixed ouble free in tun_free_netdev() (bsc#1220969).
    - CVE-2021-47087: Fixed incorrect page free bug in tee/optee (bsc#1220954).
    - CVE-2021-47091: Fixed locking in ieee80211_start_ap()) error path (bsc#1220959).
    - CVE-2021-47093: Fixed memleak on registration failure in intel_pmc_core (bsc#1220978).
    - CVE-2021-47094: Fixed possible memory leak in KVM x86/mmu (bsc#1221551).
    - CVE-2021-47095: Fixed missing initialization in ipmi/ssif (bsc#1220979).
    - CVE-2021-47096: Fixed uninitalized user_pversion in ALSA rawmidi (bsc#1220981).
    - CVE-2021-47097: Fixed stack out of bound access in elantech_change_report_id() (bsc#1220982).
    - CVE-2021-47098: Fixed integer overflow/underflow in hysteresis calculations hwmon: (lm90) (bsc#1220983).
    - CVE-2021-47099: Fixed BUG_ON assertion in veth when skb entering GRO are cloned (bsc#1220955).
    - CVE-2021-47100: Fixed UAF when uninstall in ipmi (bsc#1220985).
    - CVE-2021-47101: Fixed uninit-value in asix_mdio_read() (bsc#1220987).
    - CVE-2021-47102: Fixed incorrect structure access In line: upper = info->upper_dev in
    net/marvell/prestera (bsc#1221009).
    - CVE-2021-47104: Fixed memory leak in qib_user_sdma_queue_pkts() (bsc#1220960).
    - CVE-2021-47105: Fixed potential memory leak in ice/xsk (bsc#1220961).
    - CVE-2021-47107: Fixed READDIR buffer overflow in NFSD (bsc#1220965).
    - CVE-2021-47108: Fixed possible NULL pointer dereference for mtk_hdmi_conf in drm/mediatek (bsc#1220986).
    - CVE-2021-47181: Fixed a null pointer dereference caused by calling platform_get_resource()
    (bsc#1222660).
    - CVE-2021-47182: Fixed buffer length handling in scsi_mode_sense() in scsi core (bsc#1222662).
    - CVE-2021-47183: Fixed a null pointer dereference during link down processing in scsi lpfc (bsc#1192145,
    bsc#1222664).
    - CVE-2021-47185: Fixed a softlockup issue in flush_to_ldisc in tty tty_buffer (bsc#1222669).
    - CVE-2021-47189: Fixed denial of service due to memory ordering issues between normal and ordered work
    functions in btrfs (bsc#1222706).
    - CVE-2022-4744: Fixed double-free that could lead to DoS or privilege escalation in TUN/TAP device driver
    functionality (bsc#1209635).
    - CVE-2022-48626: Fixed a potential use-after-free on remove path moxart (bsc#1220366).
    - CVE-2022-48629: Fixed possible memory leak in qcom-rng (bsc#1220989).
    - CVE-2022-48630: Fixed infinite loop on requests not multiple of WORD_SZ in crypto: qcom-rng
    (bsc#1220990).
    - CVE-2023-0160: Fixed deadlock flaw in BPF that could allow a local user to potentially crash the system
    (bsc#1209657).
    - CVE-2023-28746: Fixed Register File Data Sampling (bsc#1213456).
    - CVE-2023-35827: Fixed a use-after-free issue in ravb_tx_timeout_work() (bsc#1212514).
    - CVE-2023-4881: Fixed a out-of-bounds write flaw in the netfilter subsystem that could lead to potential
    information disclosure or a denial of service (bsc#1215221).
    - CVE-2023-52447: Fixed map_fd_put_ptr() signature kABI workaround  (bsc#1220251).
    - CVE-2023-52450: Fixed NULL pointer dereference issue in upi_fill_topology() (bsc#1220237).
    - CVE-2023-52453: Fixed data corruption in hisi_acc_vfio_pci (bsc#1220337).
    - CVE-2023-52454: Fixed a kernel panic when host sends an invalid H2C PDU length (bsc#1220320).
    - CVE-2023-52469: Fixed a use-after-free in kv_parse_power_table (bsc#1220411).
    - CVE-2023-52470: Fixed null-ptr-deref in radeon_crtc_init() (bsc#1220413).
    - CVE-2023-52474: Fixed a vulnerability with non-PAGE_SIZE-end multi-iovec user SDMA requests
    (bsc#1220445).
    - CVE-2023-52476: Fixed possible unhandled page fault via perf sampling NMI during vsyscall (bsc#1220703).
    - CVE-2023-52477: Fixed USB Hub accesses to uninitialized BOS descriptors (bsc#1220790).
    - CVE-2023-52481: Fixed speculative unprivileged load in Cortex-A520 (bsc#1220887).
    - CVE-2023-52484: Fixed a soft lockup triggered by arm_smmu_mm_invalidate_range (bsc#1220797).
    - CVE-2023-52486: Fixed possible use-after-free in drm (bsc#1221277).
    - CVE-2023-52488: Fixed data corruption due to error on incrementing register address in regmap functions
    for FIFO in serial sc16is7xx (bsc#1221162).
    - CVE-2023-52492: Fixed a null-pointer-dereference in channel unregistration function
    __dma_async_device_channel_register() (bsc#1221276).
    - CVE-2023-52493: Fixed possible soft lockup in bus/mhi/host (bsc#1221274).
    - CVE-2023-52494: Fixed missing alignment check for event ring read pointer in bus/mhi/host (bsc#1221273).
    - CVE-2023-52497: Fixed data corruption in erofs (bsc#1220879).
    - CVE-2023-52500: Fixed information leaking when processing OPC_INB_SET_CONTROLLER_CONFIG command
    (bsc#1220883).
    - CVE-2023-52501: Fixed possible memory corruption in ring-buffer (bsc#1220885).
    - CVE-2023-52502: Fixed a race condition in nfc_llcp_sock_get() and nfc_llcp_sock_get_sn() (bsc#1220831).
    - CVE-2023-52503: Fixed use-after-free in amdtee_close_session due to race condition with
    amdtee_open_session in tee amdtee (bsc#1220915).
    - CVE-2023-52504: Fixed possible out-of bounds in apply_alternatives() on a 5-level paging machine
    (bsc#1221553).
    - CVE-2023-52507: Fixed possible shift-out-of-bounds in nfc/nci (bsc#1220833).
    - CVE-2023-52508: Fixed null pointer dereference in nvme_fc_io_getuuid() (bsc#1221015).
    - CVE-2023-52509: Fixed a use-after-free issue in ravb_tx_timeout_work() (bsc#1220836).
    - CVE-2023-52510: Fixed a potential UAF in ca8210_probe() (bsc#1220898).
    - CVE-2023-52511: Fixed possible memory corruption in spi/sun6i (bsc#1221012).
    - CVE-2023-52513: Fixed connection failure handling  in RDMA/siw (bsc#1221022).
    - CVE-2023-52515: Fixed possible use-after-free in RDMA/srp (bsc#1221048).
    - CVE-2023-52517: Fixed race between DMA RX transfer completion and RX FIFO drain in spi/sun6i
    (bsc#1221055).
    - CVE-2023-52518: Fixed information leak in bluetooth/hci_codec (bsc#1221056).
    - CVE-2023-52519: Fixed possible overflow in HID/intel-ish-hid/ipc (bsc#1220920).
    - CVE-2023-52520: Fixed reference leak in platform/x86/think-lmi (bsc#1220921).
    - CVE-2023-52523: Fixed wrong redirects to non-TCP sockets in bpf (bsc#1220926).
    - CVE-2023-52524: Fixed possible corruption in nfc/llcp (bsc#1220927).
    - CVE-2023-52525: Fixed out of bounds check mwifiex_process_rx_packet() (bsc#1220840).
    - CVE-2023-52528: Fixed uninit-value access in __smsc75xx_read_reg() (bsc#1220843).
    - CVE-2023-52529: Fixed a potential memory leak in sony_probe() (bsc#1220929).
    - CVE-2023-52532: Fixed a bug in TX CQE error handling (bsc#1220932).
    - CVE-2023-52561: Fixed denial of service due to missing reserved attribute on cont splash memory region
    in arm64 dts qcom sdm845-db845c (bsc#1220935).
    - CVE-2023-52563: Fixed memory leak on ->hpd_notify callback() in drm/meson (bsc#1220937).
    - CVE-2023-52564: Reverted invalid fix for UAF in gsm_cleanup_mux() (bsc#1220938).
    - CVE-2023-52566: Fixed potential use after free in nilfs_gccache_submit_read_data() (bsc#1220940).
    - CVE-2023-52567: Fixed possible Oops in  serial/8250_port: when using IRQ polling (irq = 0)
    (bsc#1220839).
    - CVE-2023-52569: Fixed a bug in btrfs by remoning BUG() after failure to insert delayed dir index item
    (bsc#1220918).
    - CVE-2023-52574: Fixed a bug by hiding new member header_ops (bsc#1220870).
    - CVE-2023-52575: Fixed SBPB enablement for spec_rstack_overflow=off (bsc#1220871).
    - CVE-2023-52576: Fixed potential use after free in memblock_isolate_range() (bsc#1220872).
    - CVE-2023-52582: Fixed possible oops in netfs (bsc#1220878).
    - CVE-2023-52583: Fixed deadlock or deadcode of misusing dget() inside ceph (bsc#1221058).
    - CVE-2023-52587: Fixed mcast list locking in IB/ipoib (bsc#1221082).
    - CVE-2023-52591: Fixed a possible reiserfs filesystem corruption via directory renaming (bsc#1221044).
    - CVE-2023-52594: Fixed potential array-index-out-of-bounds read in ath9k_htc_txstatus() (bsc#1221045).
    - CVE-2023-52595: Fixed possible deadlock in wifi/rt2x00 (bsc#1221046).
    - CVE-2023-52597: Fixed a setting of fpc register in KVM (bsc#1221040).
    - CVE-2023-52598: Fixed wrong setting of fpc register in s390/ptrace (bsc#1221060).
    - CVE-2023-52599: Fixed array-index-out-of-bounds in diNewExt() in jfs (bsc#1221062).
    - CVE-2023-52600: Fixed uaf in jfs_evict_inode() (bsc#1221071).
    - CVE-2023-52601: Fixed array-index-out-of-bounds in dbAdjTree() in jfs (bsc#1221068).
    - CVE-2023-52602: Fixed slab-out-of-bounds Read in dtSearch() in jfs (bsc#1221070).
    - CVE-2023-52603: Fixed array-index-out-of-bounds in dtSplitRoot() (bsc#1221066).
    - CVE-2023-52604: Fixed array-index-out-of-bounds in dbAdjTree() (bsc#1221067).
    - CVE-2023-52605: Fixed a NULL pointer dereference check (bsc#1221039)
    - CVE-2023-52606: Fixed possible kernel stack corruption in powerpc/lib (bsc#1221069).
    - CVE-2023-52607: Fixed a null-pointer-dereference in pgtable_cache_add kasprintf() (bsc#1221061).
    - CVE-2023-52608: Fixed possible race condition in firmware/arm_scmi (bsc#1221375).
    - CVE-2023-52612: Fixed req->dst buffer overflow in crypto/scomp (bsc#1221616).
    - CVE-2023-52615: Fixed page fault dead lock on mmap-ed hwrng (bsc#1221614).
    - CVE-2023-52617: Fixed stdev_release() crash after surprise hot remove (bsc#1221613).
    - CVE-2023-52619: Fixed possible crash when setting number of cpus to an odd number in pstore/ram
    (bsc#1221618).
    - CVE-2023-52621: Fixed missing asserion in bpf (bsc#1222073).
    - CVE-2023-52623: Fixed suspicious RCU usage in SUNRPC (bsc#1222060).
    - CVE-2023-52627: Fixed null pointer dereference due to lack of callback functions in iio adc ad7091r
    (bsc#1222051)
    - CVE-2023-52628: Fixed 4-byte stack OOB write in nftables (bsc#1222117).
    - CVE-2023-52632: Fixed lock dependency warning with srcu in drm/amdkfd (bsc#1222274).
    - CVE-2023-52636: Fixed denial of service due to wrongly init the cursor when preparing sparse read in
    msgr2 in libceph  (bsc#1222247).
    - CVE-2023-52637: Fixed UAF in j1939_sk_match_filter() in can/k1939 (bsc#1222291).
    - CVE-2023-52639: Fixed race during shadow creation in KVM/s390/vsie Fixed (bsc#1222300).
    - CVE-2023-6356: Fixed a NULL pointer dereference in nvmet_tcp_build_pdu_iovec (bsc#1217987).
    - CVE-2023-6535: Fixed a NULL pointer dereference in nvmet_tcp_execute_request (bsc#1217988).
    - CVE-2023-6536: Fixed a NULL pointer dereference in __nvmet_req_complete (bsc#1217989).
    - CVE-2023-7042: Fixed a null-pointer-dereference in ath10k_wmi_tlv_op_pull_mgmt_tx_compl_ev()
    (bsc#1218336).
    - CVE-2023-7192: Fixed a memory leak problem in ctnetlink_create_conntrack in
    net/netfilter/nf_conntrack_netlink.c (bsc#1218479).
    - CVE-2024-0841: Fixed null pointer dereference in hugetlbfs_fill_super() (bsc#1219264).
    - CVE-2024-2201: Fixed information leak in x86/BHI (bsc#1217339).
    - CVE-2024-22099: Fixed a null-pointer-dereference in rfcomm_check_security (bsc#1219170).
    - CVE-2024-23307: Fixed Integer Overflow or Wraparound vulnerability in x86 and ARM md, raid, raid5
    modules (bsc#1219169).
    - CVE-2024-23850: Fixed denial of service due to assertion failure due to subvolume readed before root
    item insertion in btrfs_get_root_ref in btrfs (bsc#1219126).
    - CVE-2024-23850: Fixed double free of anonymous device after snapshot  creation failure (bsc#1219126).
    - CVE-2024-25739: Fixed possible crash in create_empty_lvol() in drivers/mtd/ubi/vtbl.c (bsc#1219834).
    - CVE-2024-25742: Fixed insufficient validation during #VC instruction emulation in x86/sev (bsc#1221725).
    - CVE-2024-26599: Fixed out-of-bounds access in of_pwm_single_xlate() (bsc#1220365).
    - CVE-2024-26600: Fixed NULL pointer dereference for SRP in phy-omap-usb2 (bsc#1220340).
    - CVE-2024-26602: Fixed overall slowdowns with sys_membarrier (bsc1220398).
    - CVE-2024-26612: Fixed Oops in fscache_put_cache() This function dereferences  (bsc#1221291).
    - CVE-2024-26614: Fixed the initialization of accept_queue's spinlocks (bsc#1221293).
    - CVE-2024-26620: Fixed possible device model violation in s390/vfio-ap (bsc#1221298).
    - CVE-2024-26627: Fixed possible hard lockup in scsi (bsc#1221090).
    - CVE-2024-26629: Fixed possible protocol violation via RELEASE_LOCKOWNER in nfsd (bsc#1221379).
    - CVE-2024-26642: Fixed the set of anonymous timeout flag in netfilter nf_tables (bsc#1221830).
    - CVE-2024-26645: Fixed missing visibility when inserting an element into tracing_map (bsc#1222056).
    - CVE-2024-26646: Fixed potential memory corruption when resuming from suspend or hibernation in
    thermal/intel/hfi (bsc#1222070).
    - CVE-2024-26651: Fixed possible oops via malicious devices in sr9800 (bsc#1221337).
    - CVE-2024-26654: Fixed use after free in ALSA/sh/aica (bsc#1222304).
    - CVE-2024-26659: Fixed wrong handling of isoc Babble and Buffer Overrun events in xhci (bsc#1222317).
    - CVE-2024-26660: Fixed buffer overflow in dcn301_stream_encoder_create in drm amd display (bsc#1222266)
    - CVE-2024-26664: Fixed out-of-bounds memory access in create_core_data() in hwmon coretemp (bsc#1222355).
    - CVE-2024-26667: Fixed null pointer reference in dpu_encoder_helper_phys_cleanup in drm/msm/dpu
    (bsc#1222331).
    - CVE-2024-26670: Fixed ARM64_WORKAROUND_SPECULATIVE_UNPRIV_LOAD workaround in kernel arm64 (bsc#1222356).
    - CVE-2024-26680: Fixed denial of service due to DMA mapping for PTP hwts ring in net atlantic
    (bsc#1222427).
    - CVE-2024-26681: Fixed denial of service in nsim_dev_trap_report_work() in netdevsim (bsc#1222431).
    - CVE-2024-26684: Fixed handling of DPP safety error for DMA channels in net stmmac xgmac (bsc#1222445).
    - CVE-2024-26685: Fixed denial of service in end_buffer_async_write() in nilfs2 (bsc#1222437).
    - CVE-2024-26689: Fixed use-after-free in encode_cap_msg() in ceph (bsc#1222503).
    - CVE-2024-26695: Fixed null pointer dereference in __sev_platform_shutdown_locked in crypto ccp
    (bsc#1222373).
    - CVE-2024-26696: Fixed denial of service in nilfs_lookup_dirty_data_buffers() in nilfs2 (bsc#1222549).
    - CVE-2024-26697: Fixed data corruption in dsync block recovery for small block sizes in nilfs2
    (bsc#1222550).
    - CVE-2024-26704: Fixed a double-free of blocks due to wrong extents moved_len in ext4 (bsc#1222422).
    - CVE-2024-26717: Fixed null pointer dereference on failed power up in HID i2c-hid-of (bsc#1222360).
    - CVE-2024-26718: Fixed memory corruption in tasklet_unlock via disabling tasklets in dm-crypt and dm-
    verify (bsc#1222416).
    - CVE-2024-26722: Fixed denial of service in rt5645_jack_detect_work() due to mutex left locked forever in
    ASoC rt5645 (bsc#1222520).
    - CVE-2024-26727: Fixed denial of service due to assertion failure during subvolume creation
    (bsc#1222536).
    - CVE-2024-26733: Fixed an overflow in arp_req_get() in arp (bsc#1222585).
    - CVE-2024-26736: Fixed buffer overflow in afs_update_volume_status() in afs (bsc#1222586).
    - CVE-2024-26737: Fixed use-after-free due to race between bpf_timer_cancel_and_free and bpf_timer_cancel
    in bpf (bsc#1222557).
    - CVE-2024-26743: Fixed memory leak in qedr_create_user_qp error flow in rdma/qedr (bsc#1222677)
    - CVE-2024-26744: Fixed null pointer dereference in srpt_service_guid parameter in rdma/srpt (bsc#1222449)
    - CVE-2024-26745: Fixed null pointer dereference due to IOMMU table not initialized for kdump over SR-IOV
    (bsc#1220492, bsc#1222678).
    - CVE-2024-26747: Fixed null pointer issue when put module's reference in usb roles  (bsc#1222609).
    - CVE-2024-26749: Fixed use-after-free at cdns3_gadget_ep_disable() in usb cdns3 (bsc#1222680).
    - CVE-2024-26751: Fixed denial of service due to gpiod_lookup_table search loop not ending correctly
    (bsc#1222724)
    - CVE-2024-26754: Fixed an use-after-free and null-ptr-deref in gtp_genl_dump_pdp() in gtp  (bsc#1222632).
    - CVE-2024-26760: Fixed null pointer dereference on error case in bio_put() in scsi target pscsi
    (bsc#1222596)
    - CVE-2024-26763: Fixed user corruption via by writing data with O_DIRECT on device in dm-crypt
    (bsc#1222720).
    - CVE-2024-26766: Fixed off-by-one error in sdma.h tx->num_descs in ib/hfi1 (bsc#1222726)
    - CVE-2024-26769: Fixed deadlock on delete association path in nvmet-fc  (bsc#1222727).
    - CVE-2024-26771: Fixed a null pointer dereference on edma_probe in dmaengine ti edma  (bsc#1222610)
    - CVE-2024-26776: Fixed null pointer dereference due to null value returned by interrupt handler in spi
    hisi-sfc-v3xx (bsc#1222764)
    - CVE-2024-26779: Fixed denial of service due to race condition on enabling fast-xmit in wifi mac80211
    (bsc#1222772).
    - CVE-2024-26787: Fixed DMA API overlapping mappings in mmc mmci stm32 (bsc#1222781)
    - CVE-2024-26790: Fixed denial of service on 16 bytes unaligned read in dmaengine fsl-qdma (bsc#1222784)
    - CVE-2024-26793: Fixed an use-after-free and null-ptr-deref in gtp_newlink() in gtp  (bsc#1222428).
    - CVE-2024-26798: Fixed denial of service due to wrongly restore fond data upon failure in fbcon
    (bsc#1222798).
    - CVE-2024-26805: Fixed a kernel-infoleak-after-free in __skb_datagram_iter in netlink  (bsc#1222630).
    - CVE-2024-26807: Fixed memory corruption due to wrong pointer reference in spi cadence-qspi (bsc#1222801)
    - CVE-2024-26848: Fixed denial of service due to endless loop in directory parsing in afs (bsc#1223030).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218321");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221156");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221551");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223068");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035140.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47087");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47091");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47093");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47094");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47096");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47100");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47101");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47102");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47105");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47107");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47108");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47181");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47182");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47183");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47185");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47189");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48626");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48629");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48630");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52447");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52450");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52453");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52454");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52469");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52470");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52474");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52481");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52484");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52486");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52488");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52492");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52493");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52494");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52497");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52500");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52501");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52503");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52504");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52508");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52510");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52511");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52513");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52515");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52517");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52518");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52519");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52520");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52523");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52525");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52528");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52529");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52561");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52563");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52564");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52574");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52575");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52576");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52604");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52606");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52612");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52617");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52621");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52627");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52637");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6356");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-7042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-7192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-2201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23307");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-25739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-25742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26612");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26627");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26629");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26654");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26684");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26689");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26717");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26718");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26722");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26727");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26736");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26745");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26749");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26769");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26771");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26776");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26779");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26787");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26790");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26793");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26848");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26793");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-5.14.21-150500.33.48.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.48.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.48.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.48.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.48.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.48.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.48.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.48.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.48.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.48.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.48.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.48.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.48.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.48.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.48.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.48.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150500.33.48.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150500.33.48.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-azure-5.14.21-150500.33.48.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-azure-5.14.21-150500.33.48.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-azure-5.14.21-150500.33.48.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-azure-5.14.21-150500.33.48.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.48.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.48.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.48.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.48.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-extra-5.14.21-150500.33.48.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-extra-5.14.21-150500.33.48.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150500.33.48.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150500.33.48.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-optional-5.14.21-150500.33.48.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-optional-5.14.21-150500.33.48.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-vdso-5.14.21-150500.33.48.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.48.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.48.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.48.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.48.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-azure-5.14.21-150500.33.48.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-azure-5.14.21-150500.33.48.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150500.33.48.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150500.33.48.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150500.33.48.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150500.33.48.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-azure / dlm-kmp-azure / gfs2-kmp-azure / etc');
}
