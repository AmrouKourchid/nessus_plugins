#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1643-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(197055);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/27");

  script_cve_id(
    "CVE-2019-25160",
    "CVE-2020-36312",
    "CVE-2021-23134",
    "CVE-2021-46904",
    "CVE-2021-46905",
    "CVE-2021-46909",
    "CVE-2021-46938",
    "CVE-2021-46939",
    "CVE-2021-46941",
    "CVE-2021-46950",
    "CVE-2021-46955",
    "CVE-2021-46958",
    "CVE-2021-46960",
    "CVE-2021-46963",
    "CVE-2021-46964",
    "CVE-2021-46966",
    "CVE-2021-46981",
    "CVE-2021-46988",
    "CVE-2021-46990",
    "CVE-2021-46998",
    "CVE-2021-47006",
    "CVE-2021-47015",
    "CVE-2021-47024",
    "CVE-2021-47034",
    "CVE-2021-47045",
    "CVE-2021-47049",
    "CVE-2021-47055",
    "CVE-2021-47056",
    "CVE-2021-47060",
    "CVE-2021-47061",
    "CVE-2021-47063",
    "CVE-2021-47068",
    "CVE-2021-47070",
    "CVE-2021-47071",
    "CVE-2021-47073",
    "CVE-2021-47100",
    "CVE-2021-47101",
    "CVE-2021-47104",
    "CVE-2021-47110",
    "CVE-2021-47112",
    "CVE-2021-47113",
    "CVE-2021-47114",
    "CVE-2021-47117",
    "CVE-2021-47118",
    "CVE-2021-47119",
    "CVE-2021-47131",
    "CVE-2021-47138",
    "CVE-2021-47141",
    "CVE-2021-47142",
    "CVE-2021-47143",
    "CVE-2021-47146",
    "CVE-2021-47149",
    "CVE-2021-47150",
    "CVE-2021-47153",
    "CVE-2021-47159",
    "CVE-2021-47161",
    "CVE-2021-47162",
    "CVE-2021-47165",
    "CVE-2021-47166",
    "CVE-2021-47167",
    "CVE-2021-47168",
    "CVE-2021-47169",
    "CVE-2021-47171",
    "CVE-2021-47173",
    "CVE-2021-47177",
    "CVE-2021-47179",
    "CVE-2021-47180",
    "CVE-2021-47181",
    "CVE-2021-47182",
    "CVE-2021-47183",
    "CVE-2021-47184",
    "CVE-2021-47185",
    "CVE-2021-47188",
    "CVE-2021-47189",
    "CVE-2021-47198",
    "CVE-2021-47202",
    "CVE-2021-47203",
    "CVE-2021-47204",
    "CVE-2021-47205",
    "CVE-2021-47207",
    "CVE-2021-47211",
    "CVE-2021-47216",
    "CVE-2021-47217",
    "CVE-2022-0487",
    "CVE-2022-48619",
    "CVE-2022-48626",
    "CVE-2022-48636",
    "CVE-2022-48650",
    "CVE-2022-48651",
    "CVE-2022-48667",
    "CVE-2022-48668",
    "CVE-2022-48672",
    "CVE-2022-48687",
    "CVE-2022-48688",
    "CVE-2022-48695",
    "CVE-2022-48701",
    "CVE-2022-48702",
    "CVE-2023-0160",
    "CVE-2023-4881",
    "CVE-2023-6270",
    "CVE-2023-6356",
    "CVE-2023-6535",
    "CVE-2023-6536",
    "CVE-2023-7042",
    "CVE-2023-7192",
    "CVE-2023-28746",
    "CVE-2023-35827",
    "CVE-2023-52454",
    "CVE-2023-52469",
    "CVE-2023-52470",
    "CVE-2023-52474",
    "CVE-2023-52476",
    "CVE-2023-52477",
    "CVE-2023-52486",
    "CVE-2023-52488",
    "CVE-2023-52509",
    "CVE-2023-52515",
    "CVE-2023-52524",
    "CVE-2023-52528",
    "CVE-2023-52575",
    "CVE-2023-52583",
    "CVE-2023-52587",
    "CVE-2023-52590",
    "CVE-2023-52591",
    "CVE-2023-52595",
    "CVE-2023-52598",
    "CVE-2023-52607",
    "CVE-2023-52614",
    "CVE-2023-52620",
    "CVE-2023-52628",
    "CVE-2023-52635",
    "CVE-2023-52639",
    "CVE-2023-52644",
    "CVE-2023-52646",
    "CVE-2023-52650",
    "CVE-2023-52652",
    "CVE-2023-52653",
    "CVE-2024-0639",
    "CVE-2024-2201",
    "CVE-2024-22099",
    "CVE-2024-23307",
    "CVE-2024-23848",
    "CVE-2024-24855",
    "CVE-2024-24861",
    "CVE-2024-26614",
    "CVE-2024-26642",
    "CVE-2024-26651",
    "CVE-2024-26671",
    "CVE-2024-26675",
    "CVE-2024-26689",
    "CVE-2024-26704",
    "CVE-2024-26733",
    "CVE-2024-26739",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26747",
    "CVE-2024-26754",
    "CVE-2024-26763",
    "CVE-2024-26771",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26777",
    "CVE-2024-26778",
    "CVE-2024-26779",
    "CVE-2024-26791",
    "CVE-2024-26793",
    "CVE-2024-26805",
    "CVE-2024-26816",
    "CVE-2024-26817",
    "CVE-2024-26839",
    "CVE-2024-26840",
    "CVE-2024-26852",
    "CVE-2024-26855",
    "CVE-2024-26857",
    "CVE-2024-26859",
    "CVE-2024-26876",
    "CVE-2024-26878",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26898",
    "CVE-2024-26901",
    "CVE-2024-26903",
    "CVE-2024-26907",
    "CVE-2024-26922",
    "CVE-2024-26929",
    "CVE-2024-26930",
    "CVE-2024-26931",
    "CVE-2024-26948",
    "CVE-2024-26993",
    "CVE-2024-27008",
    "CVE-2024-27013",
    "CVE-2024-27014",
    "CVE-2024-27043",
    "CVE-2024-27046",
    "CVE-2024-27054",
    "CVE-2024-27072",
    "CVE-2024-27073",
    "CVE-2024-27074",
    "CVE-2024-27075",
    "CVE-2024-27078",
    "CVE-2024-27388"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1643-1");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2024:1643-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:1643-1 advisory.

    The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2019-25160: Fixed out-of-bounds memory accesses in netlabel (bsc#1220394).
    - CVE-2020-36312: Fixed an issue in virt/kvm/kvm_main.c that had a kvm_io_bus_unregister_dev memory leak
    upon a kmalloc failure (bsc#1184509).
    - CVE-2021-23134: Fixed a use-after-free issue in nfc sockets (bsc#1186060).
    - CVE-2021-46904: Fixed NULL pointer dereference during tty device unregistration (bsc#1220416).
    - CVE-2021-46905: Fixed NULL pointer dereference on disconnect regression (bsc#1220418).
    - CVE-2021-46909: Fixed a PCI interrupt mapping in ARM footbridge (bsc#1220442).
    - CVE-2021-46938: Fixed a double free of blk_mq_tag_set in dev remove after table load fails in dm rq
    (bsc#1220554).
    - CVE-2021-46939: Fixed a denial of service in trace_clock_global() in tracing (bsc#1220580).
    - CVE-2021-46941: Fixed core softreset when switch mode in usb dwc3 (bsc#1220628).
    - CVE-2021-46950: Fixed a data corruption bug in raid1 arrays using bitmaps in md/raid1 (bsc#1220662).
    - CVE-2021-46955: Fixed an out-of-bounds read with openvswitch, when fragmenting IPv4 packets
    (bsc#1220513).
    - CVE-2021-46958: Fixed a race between transaction aborts and fsyncs leading to use-after-free in btrfs
    (bsc#1220521).
    - CVE-2021-46960: Fixed a warning on smb2_get_enc_key in cifs (bsc#1220528).
    - CVE-2021-46963: Fixed crash in qla2xxx_mqueuecommand()  (bsc#1220536).
    - CVE-2021-46964: Fixed unreserved extra IRQ vectors in qla2xxx (bsc#1220538).
    - CVE-2021-46966: Fixed potential use-after-free issue in cm_write() (bsc#1220572).
    - CVE-2021-46981: Fixed a NULL pointer in flush_workqueue in nbd (bsc#1220611).
    - CVE-2021-46988: Fixed release page in error path to avoid BUG_ON (bsc#1220706).
    - CVE-2021-46990: Fixed a denial of service when toggling entry flush barrier in powerpc/64s
    (bsc#1220743).
    - CVE-2021-46998: Fixed an use after free bug in enic_hard_start_xmit in ethernet/enic (bsc#1220625).
    - CVE-2021-47006: Fixed wrong check in overflow_handler hook in ARM 9064/1 hw_breakpoint (bsc#1220751).
    - CVE-2021-47015: Fixed a RX consumer index logic in the error path in bnxt_rx_pkt() in bnxt_en
    (bsc#1220794).
    - CVE-2021-47024: Fixed possible memory leak in vsock/virtio when closing socket (bsc#1220637).
    - CVE-2021-47034: Fixed a kernel memory fault for pte update on radix in powerpc/64s (bsc#1220687).
    - CVE-2021-47045: Fixed a null pointer dereference in lpfc_prep_els_iocb() in scsi lpfc (bsc#1220640).
    - CVE-2021-47049: Fixed an after free in __vmbus_open() in hv vmbus (bsc#1220692).
    - CVE-2021-47055: Fixed missing permissions for locking and badblock ioctls in mtd (bsc#1220768).
    - CVE-2021-47056: Fixed a user-memory-access error on vf2pf_lock in crypto (bsc#1220769).
    - CVE-2021-47060: Fixed a bug in KVM by stop looking for coalesced MMIO zones if the bus is destroyed
    (bsc#1220742).
    - CVE-2021-47061: Fixed a bug in KVM by destroy I/O bus devices on unregister failure _after_  sync'ing
    SRCU (bsc#1220745).
    - CVE-2021-47063: Fixed a potential use-after-free during bridge detach in drm bridge/panel (bsc#1220777).
    - CVE-2021-47068: Fixed a use-after-free issue in llcp_sock_bind/connect (bsc#1220739).
    - CVE-2021-47070: Fixed memory leak in error handling paths in uio_hv_generic (bsc#1220829).
    - CVE-2021-47071: Fixed a memory leak in error handling paths in hv_uio_cleanup() in uio_hv_generic
    (bsc#1220846).
    - CVE-2021-47073: Fixed oops on rmmod dell_smbios init_dell_smbios_wmi() (bsc#1220850).
    - CVE-2021-47100: Fixed UAF when uninstall in ipmi (bsc#1220985).
    - CVE-2021-47101: Fixed uninit-value in asix_mdio_read() (bsc#1220987).
    - CVE-2021-47104: Fixed memory leak in qib_user_sdma_queue_pkts() (bsc#1220960).
    - CVE-2021-47110: Fixed possible memory corruption when restoring from hibernation in x86/kvm
    (bsc#1221532).
    - CVE-2021-47112: Fixed possible memory corruption when restoring from hibernation in x86/kvm
    (bsc#1221541).
    - CVE-2021-47113: Abort btrfs rename_exchange if we fail to insert the second ref (bsc#1221543).
    - CVE-2021-47114: Fixed a data corruption by fallocate in ocfs2 (bsc#1221548).
    - CVE-2021-47117: Fixed a crash in ext4_es_cache_extent as ext4_split_extent_at failed in ext4
    (bsc#1221575).
    - CVE-2021-47118: Fixed an use-after-free in init task's struct pid in pid (bsc#1221605).
    - CVE-2021-47119: Fixed a memory leak in ext4_fill_super in ext4 (bsc#1221608).
    - CVE-2021-47131: Fixed a use-after-free after the TLS device goes down and up (bsc#1221545).
    - CVE-2021-47138: Fixed an out-of-bound memory access during clearing filters in cxgb4 (bsc#1221934).
    - CVE-2021-47141: Fixed a null pointer dereference on priv->msix_vectors when driver is unloaded in gve
    (bsc#1221949).
    - CVE-2021-47142: Fixed an use-after-free on ttm->sg in drm/amdgpu (bsc#1221952).
    - CVE-2021-47143: Fixed possible corruption in net/smc after failed device_add() (bsc#1221988).
    - CVE-2021-47149: Fixed a potential null pointer deref in fmvj18x_get_hwinfo() (bsc#1221972).
    - CVE-2021-47150: Fixed the potential memory leak in fec_enet_init() (bsc#1221973).
    - CVE-2021-47153: Fixed wrongly generated interrupt on bus reset in i2c/i801 (bsc#1221969).
    - CVE-2021-47161: Fixed a resource leak in an error handling path in the error handling path of the probe
    function in spi spi-fsl-dspi (bsc#1221966).
    - CVE-2021-47162: Fixed a possible memory leak in tipc_buf_append (bsc#1221977).
    - CVE-2021-47165: Fixed shutdown crash when component not probed in drm/meson (bsc#1221965).
    - CVE-2021-47166: Fixed a data corruption of pg_bytes_written in nfs_do_recoalesce() in nfs (bsc#1221998).
    - CVE-2021-47167: Fixed an oopsable condition in __nfs_pageio_add_request() in nfs (bsc#1221991).
    - CVE-2021-47168: Fixed an incorrect limit in filelayout_decode_layout() in nfs (bsc#1222002).
    - CVE-2021-47169: Fixed a NULL pointer dereference in rp2_probe in serial rp2 (bsc#1222000).
    - CVE-2021-47171: Fixed a memory leak in smsc75xx_bind in net usb (bsc#1221994).
    - CVE-2021-47173: Fixed a memory leak in uss720_probe in misc/uss720 (bsc#1221993).
    - CVE-2021-47177: Fixed a sysfs leak in alloc_iommu() in iommu/vt-d (bsc#1221997).
    - CVE-2021-47179: Fixed a NULL pointer dereference in pnfs_mark_matching_lsegs_return() in nfsv4
    (bsc#1222001).
    - CVE-2021-47180: Fixed a memory leak in nci_allocate_device nfcmrvl_disconnect in nfc nci (bsc#1221999).
    - CVE-2021-47181: Fixed a null pointer dereference caused by calling platform_get_resource()
    (bsc#1222660).
    - CVE-2021-47182: Fixed scsi_mode_sense() buffer length handling (bsc#1222662).
    - CVE-2021-47183: Fixed a null pointer dereference during link down processing in scsi lpfc (bsc#1192145,
    bsc#1222664).
    - CVE-2021-47184: Fixed NULL pointer dereference on VSI filter sync (bsc#1222666).
    - CVE-2021-47185: Fixed a softlockup issue in flush_to_ldisc in tty tty_buffer (bsc#1222669).
    - CVE-2021-47189: Fixed denial of service due to memory ordering issues between normal and ordered work
    functions in btrfs (bsc#1222706).
    - CVE-2021-47202: Fixed NULL pointer dereferences in of_thermal_ functions in thermal (bsc#1222878)
    - CVE-2021-47205: Unregistered clocks/resets when unbinding in sunxi-ng (bsc#1222888).
    - CVE-2021-47207: Fixed a null pointer dereference on pointer block in gus (bsc#1222790).
    - CVE-2021-47211: Fixed a null pointer dereference on pointer cs_desc in usb-audio (bsc#1222869).
    - CVE-2022-0487: Fixed an use-after-free vulnerability in rtsx_usb_ms_drv_remove() in
    drivers/memstick/host/rtsx_usb_ms.c (bsc#1194516).
    - CVE-2022-48619: Fixed a denial-of-service issue in drivers/input/input.c (bsc#1218220).
    - CVE-2022-48626: Fixed a potential use-after-free on remove path moxart (bsc#1220366).
    - CVE-2022-48651: Fixed an out-of-bound bug in ipvlan caused by unset skb->mac_header (bsc#1223513).
    - CVE-2022-48672: Fixed off-by-one error in unflatten_dt_nodes() (bsc#1223931).
    - CVE-2022-48701: Fixed an out-of-bounds bug in __snd_usb_parse_audio_interface() (bsc#1223921).
    - CVE-2022-48702: Fixed out of bounds access in  snd_emu10k1_pcm_channel_alloc() (bsc#1223923).
    - CVE-2023-0160: Fixed deadlock flaw in BPF that could allow a local user to potentially crash the system
    (bsc#1209657).
    - CVE-2023-28746: Fixed Register File Data Sampling (bsc#1213456).
    - CVE-2023-35827: Fixed a use-after-free issue in ravb_tx_timeout_work() (bsc#1212514).
    - CVE-2023-4881: Fixed a out-of-bounds write flaw in the netfilter subsystem that could lead to potential
    information disclosure or a denial of service (bsc#1215221).
    - CVE-2023-52454: Fixed a kernel panic when host sends an invalid H2C PDU length (bsc#1220320).
    - CVE-2023-52469: Fixed a use-after-free in kv_parse_power_table (bsc#1220411).
    - CVE-2023-52470: Fixed null-ptr-deref in radeon_crtc_init() (bsc#1220413).
    - CVE-2023-52474: Fixed a vulnerability with non-PAGE_SIZE-end multi-iovec user SDMA requests
    (bsc#1220445).
    - CVE-2023-52476: Fixed possible unhandled page fault via perf sampling NMI during vsyscall (bsc#1220703).
    - CVE-2023-52477: Fixed USB Hub accesses to uninitialized BOS descriptors (bsc#1220790).
    - CVE-2023-52486: Fixed possible use-after-free in drm (bsc#1221277).
    - CVE-2023-52488: Fixed serial/sc16is7xx convert from _raw_ to _noinc_ regmap functions for FIFO
    (bsc#1221162).
    - CVE-2023-52509: Fixed a use-after-free issue in ravb_tx_timeout_work() (bsc#1220836).
    - CVE-2023-52515: Fixed possible use-after-free in RDMA/srp (bsc#1221048).
    - CVE-2023-52524: Fixed possible corruption in nfc/llcp (bsc#1220927).
    - CVE-2023-52528: Fixed uninit-value access in __smsc75xx_read_reg() (bsc#1220843).
    - CVE-2023-52575: Fixed SBPB enablement for spec_rstack_overflow=off (bsc#1220871).
    - CVE-2023-52583: Fixed deadlock or deadcode of misusing dget() inside ceph (bsc#1221058).
    - CVE-2023-52587: Fixed mcast list locking in IB/ipoib (bsc#1221082).
    - CVE-2023-52590: Fixed a possible ocfs2 filesystem corruption via directory renaming (bsc#1221088).
    - CVE-2023-52591: Fixed a possible reiserfs filesystem corruption via directory renaming (bsc#1221044).
    - CVE-2023-52595: Fixed possible deadlock in wifi/rt2x00 (bsc#1221046).
    - CVE-2023-52598: Fixed wrong setting of fpc register in s390/ptrace (bsc#1221060).
    - CVE-2023-52607: Fixed a null-pointer-dereference in pgtable_cache_add kasprintf() (bsc#1221061).
    - CVE-2023-52614: Fixed PM/devfreq buffer overflow in trans_stat_show (bsc#1221617).
    - CVE-2023-52620: Fixed netfilter/nf_tables to disallow timeout for anonymous sets never used from
    userspace (bsc#1221825).
    - CVE-2023-52628: Fixed 4-byte stack OOB write in nftables (bsc#1222117).
    - CVE-2023-52635: Fixed PM/devfreq to synchronize devfreq_monitor_[start/stop] (bsc#1222294).
    - CVE-2023-52639: Fixed race during shadow creation in KVM/s390/vsie Fixed (bsc#1222300).
    - CVE-2023-52644: Stop/wake correct queue in DMA Tx path when QoS is disabled in b43 (bsc#1222961).
    - CVE-2023-52650: Added missing check for of_find_device_by_node() (bsc#1223770)
    - CVE-2023-52652: Fixed NTB for possible name leak in ntb_register_device() (bsc#1223686).
    - CVE-2023-6270: Fixed a use-after-free issue in aoecmd_cfg_pkts (bsc#1218562).
    - CVE-2023-6356: Fixed a NULL pointer dereference in nvmet_tcp_build_pdu_iovec (bsc#1217987).
    - CVE-2023-6535: Fixed a NULL pointer dereference in nvmet_tcp_execute_request (bsc#1217988).
    - CVE-2023-6536: Fixed a NULL pointer dereference in __nvmet_req_complete (bsc#1217989).
    - CVE-2023-7042: Fixed a null-pointer-dereference in ath10k_wmi_tlv_op_pull_mgmt_tx_compl_ev()
    (bsc#1218336).
    - CVE-2023-7192: Fixed a memory leak problem in ctnetlink_create_conntrack in
    net/netfilter/nf_conntrack_netlink.c (bsc#1218479).
    - CVE-2024-0639: Fixed a denial-of-service vulnerability due to a deadlock found in sctp_auto_asconf_init
    in net/sctp/socket.c (bsc#1218917).
    - CVE-2024-2201: Fixed information leak in x86/BHI (bsc#1217339).
    - CVE-2024-22099: Fixed a null-pointer-dereference in rfcomm_check_security (bsc#1219170).
    - CVE-2024-23307: Fixed Integer Overflow or Wraparound vulnerability in x86 and ARM md, raid, raid5
    modules (bsc#1219169).
    - CVE-2024-23848: Fixed media/cec for possible use-after-free in cec_queue_msg_fh (bsc#1219104).
    - CVE-2024-24855: Fixed race condition in lpfc_unregister_fcf_rescan() that could lead to a kernel panic
    or denial of service issue (bsc#1219618).
    - CVE-2024-24861: Fixed race condition in xc4000_get_frequency() that could lead to malfunction or denial
    of service issue (bsc#1219623).
    - CVE-2024-26614: Fixed the initialization of accept_queue's spinlocks (bsc#1221293).
    - CVE-2024-26642: Fixed the set of anonymous timeout flag in netfilter nf_tables (bsc#1221830).
    - CVE-2024-26671: Fixed blk-mq IO hang from sbitmap wakeup race (bsc#1222357).
    - CVE-2024-26675: Fixed ppp_async to limit MRU to 64K (bsc#1222379).
    - CVE-2024-26689: Fixed a use-after-free in encode_cap_msg() (bsc#1222503).
    - CVE-2024-26704: fixed double-free of blocks due to wrong extents moved_len in ext4 (bsc#1222422).
    - CVE-2024-26733: Fixed an overflow in arp_req_get() in arp (bsc#1222585).
    - CVE-2024-26743: Fixed memory leak in qedr_create_user_qp error flow in rdma/qedr (bsc#1222677)
    - CVE-2024-26744: Fixed null pointer dereference in srpt_service_guid parameter in rdma/srpt (bsc#1222449)
    - CVE-2024-26747: Fixed a NULL pointer issue with USB parent module's reference (bsc#1222609).
    - CVE-2024-26754: Fixed ab use-after-free and null-ptr-deref in gtp_genl_dump_pdp() in gtp (bsc#1222632).
    - CVE-2024-26763: Fixed user corruption via by writing data with O_DIRECT on device in dm-crypt
    (bsc#1222720).
    - CVE-2024-26771: Fixed a null pointer dereference on edma_probe in dmaengine ti edma (bsc#1222610)
    - CVE-2024-26772: Fixed ext4 to avoid allocating blocks from corrupted group in ext4_mb_find_by_goal()
    (bsc#1222613).
    - CVE-2024-26773: Fixed ext4 block allocation from corrupted group in ext4_mb_try_best_found()
    (bsc#1222618).
    - CVE-2024-26777: Error out if pixclock equals zero in fbdev/sis (bsc#1222765)
    - CVE-2024-26778: Error out if pixclock equals zero in fbdev/savage (bsc#1222770)
    - CVE-2024-26779: Fixed a race condition on enabling fast-xmit in mac80211 (bsc#1222772).
    - CVE-2024-26791: Properly validated device names in btrfs dev-replace (bsc#1222793)
    - CVE-2024-26793: fixed use-after-free and null-ptr-deref in gtp_newlink() (bsc#1222428).
    - CVE-2024-26805: Fixed a kernel-infoleak-after-free in __skb_datagram_iter in netlink (bsc#1222630).
    - CVE-2024-26816: Fixed relocations in .notes section when building with CONFIG_XEN_PV=y by ignoring them
    (bsc#1222624).
    - CVE-2024-26817: Fixed amdkfd to use calloc instead of kzalloc to avoid integer overflow (bsc#1222812).
    - CVE-2024-26839: Fixed a memory leak in init_credit_return() (bsc#1222975)
    - CVE-2024-26840: Fixed a memory leak in cachefiles_add_cache() (bsc#1222976).
    - CVE-2024-26852: Fixed net/ipv6 to avoid possible UAF in ip6_route_mpath_notify() (bsc#1223057).
    - CVE-2024-26855: Fixed net/ice potential NULL pointer dereference in ice_bridge_setlink() (bsc#1223051).
    - CVE-2024-26857: Fixed geneve to make sure to pull inner header in geneve_rx() (bsc#1223058).
    - CVE-2024-26859: Prevent access to a freed page in page_pool in bnx2x (bsc#1223049).
    - CVE-2024-26876: Fixed crash on irq during probe, related to adv7511_probe() (bsc#1223119).
    - CVE-2024-26878: Fixed quota for potential NULL pointer dereference (bsc#1223060).
    - CVE-2024-26883: Fixed bpf stackmap overflow check on 32-bit arches (bsc#1223035).
    - CVE-2024-26884: Fixed bpf hashtab overflow check on 32-bit arches (bsc#1223189).
    - CVE-2024-26901: Fixed do_sys_name_to_handle() to use kzalloc() to prevent kernel-infoleak (bsc#1223198).
    - CVE-2024-26907: Fixed a fortify source warning while accessing Eth segment in mlx5 (bsc#1223203).
    - CVE-2024-26922: Validated the parameters of bo mapping operations more clearly (bsc#1223315).
    - CVE-2024-26948: Fixed drm/amd/display by adding dc_state NULL check in dc_state_release (bsc#1223664).
    - CVE-2024-26993: Fixed fs/sysfs reference leak in sysfs_break_active_protection() (bsc#1223693).
    - CVE-2024-27008: Fixed out of bounds access in nv04 (CVE-2024-27008 bsc#1223802).
    - CVE-2024-27013: Fixed tun limit printing rate when illegal packet received by tun device (bsc#1223745).
    - CVE-2024-27014: Fixed net/mlx5e to prevent deadlock while disabling aRFS (bsc#1223735).
    - CVE-2024-27043: Fixed a use-after-free in edia/dvbdev in different places (bsc#1223824).
    - CVE-2024-27046: Fixed nfp/flower handling acti_netdevs allocation failure (bsc#1223827).
    - CVE-2024-27072: Removed useless locks in usbtv_video_free() (bsc#1223837).
    - CVE-2024-27073: Fixed a memory leak in budget_av_attach() (bsc#1223843).
    - CVE-2024-27074: Fixed a memory leak in go7007_load_encoder() (bsc#1223844).
    - CVE-2024-27075: Avoided stack overflow warnings with clang (bsc#1223842).
    - CVE-2024-27078: Fixed a memory leak in tpg_alloc() (bsc#1223781).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1084332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220394");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223119");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223969");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035264.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-25160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46963");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47034");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47060");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47070");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47071");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47100");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47101");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47110");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47112");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47113");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47117");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47118");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47119");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47143");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47146");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47149");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47150");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47153");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47159");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47165");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47167");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47168");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47169");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47171");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47173");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47177");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47181");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47182");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47183");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47185");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47188");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47189");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47203");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47204");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47205");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47207");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47211");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47216");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47217");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0487");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48626");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52454");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52469");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52470");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52474");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52486");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52488");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52515");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52528");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52575");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6356");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-7042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-7192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-2201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23307");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26689");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26771");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26778");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26779");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26793");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26839");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26876");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26993");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27043");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27046");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27054");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27072");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27075");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27388");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23134");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-27043");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-4.12.14-16.182.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-azure-base-4.12.14-16.182.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-azure-devel-4.12.14-16.182.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-devel-azure-4.12.14-16.182.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-source-azure-4.12.14-16.182.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-syms-azure-4.12.14-16.182.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-azure-4.12.14-16.182.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-azure-base-4.12.14-16.182.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-azure-devel-4.12.14-16.182.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-devel-azure-4.12.14-16.182.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-source-azure-4.12.14-16.182.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-syms-azure-4.12.14-16.182.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-azure / kernel-azure-base / kernel-azure-devel / etc');
}
