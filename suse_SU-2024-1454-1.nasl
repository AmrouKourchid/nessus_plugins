#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1454-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(194454);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2020-36780",
    "CVE-2020-36782",
    "CVE-2020-36783",
    "CVE-2021-23134",
    "CVE-2021-46909",
    "CVE-2021-46921",
    "CVE-2021-46930",
    "CVE-2021-46938",
    "CVE-2021-46939",
    "CVE-2021-46943",
    "CVE-2021-46944",
    "CVE-2021-46950",
    "CVE-2021-46951",
    "CVE-2021-46958",
    "CVE-2021-46960",
    "CVE-2021-46961",
    "CVE-2021-46962",
    "CVE-2021-46963",
    "CVE-2021-46971",
    "CVE-2021-46981",
    "CVE-2021-46984",
    "CVE-2021-46988",
    "CVE-2021-46990",
    "CVE-2021-46991",
    "CVE-2021-46992",
    "CVE-2021-46998",
    "CVE-2021-47000",
    "CVE-2021-47006",
    "CVE-2021-47013",
    "CVE-2021-47015",
    "CVE-2021-47020",
    "CVE-2021-47034",
    "CVE-2021-47045",
    "CVE-2021-47049",
    "CVE-2021-47051",
    "CVE-2021-47055",
    "CVE-2021-47056",
    "CVE-2021-47058",
    "CVE-2021-47061",
    "CVE-2021-47063",
    "CVE-2021-47065",
    "CVE-2021-47068",
    "CVE-2021-47069",
    "CVE-2021-47070",
    "CVE-2021-47071",
    "CVE-2021-47073",
    "CVE-2021-47077",
    "CVE-2021-47082",
    "CVE-2021-47109",
    "CVE-2021-47110",
    "CVE-2021-47112",
    "CVE-2021-47114",
    "CVE-2021-47117",
    "CVE-2021-47118",
    "CVE-2021-47119",
    "CVE-2021-47120",
    "CVE-2021-47138",
    "CVE-2021-47139",
    "CVE-2021-47141",
    "CVE-2021-47142",
    "CVE-2021-47144",
    "CVE-2021-47153",
    "CVE-2021-47161",
    "CVE-2021-47165",
    "CVE-2021-47166",
    "CVE-2021-47167",
    "CVE-2021-47168",
    "CVE-2021-47169",
    "CVE-2021-47170",
    "CVE-2021-47171",
    "CVE-2021-47172",
    "CVE-2021-47173",
    "CVE-2021-47177",
    "CVE-2021-47179",
    "CVE-2021-47180",
    "CVE-2021-47181",
    "CVE-2021-47183",
    "CVE-2021-47185",
    "CVE-2021-47189",
    "CVE-2022-0487",
    "CVE-2022-4744",
    "CVE-2022-48626",
    "CVE-2023-0160",
    "CVE-2023-1192",
    "CVE-2023-6270",
    "CVE-2023-6356",
    "CVE-2023-6531",
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
    "CVE-2023-52500",
    "CVE-2023-52509",
    "CVE-2023-52572",
    "CVE-2023-52575",
    "CVE-2023-52583",
    "CVE-2023-52590",
    "CVE-2023-52591",
    "CVE-2023-52607",
    "CVE-2023-52628",
    "CVE-2024-22099",
    "CVE-2024-26600",
    "CVE-2024-26614",
    "CVE-2024-26642",
    "CVE-2024-26704",
    "CVE-2024-26733"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1454-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2024:1454-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:1454-1 advisory.

    The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2020-36780: Fixed a reference leak when pm_runtime_get_sync fails in i2c (bsc#1220556).
    - CVE-2020-36782: Fixed a reference leak when pm_runtime_get_sync fails in i2c imx-lpi2c (bsc#1220560).
    - CVE-2020-36783: Fixed a reference leak when pm_runtime_get_sync fails in i2c img-scb (bsc#1220561).
    - CVE-2021-23134: Fixed a use-after-free issue in nfc sockets (bsc#1186060).
    - CVE-2021-46909: Fixed a PCI interrupt mapping in ARM footbridge (bsc#1220442).
    - CVE-2021-46921: Fixed ordering in queued_write_lock_slowpath (bsc#1220468).
    - CVE-2021-46930: Fixed a list_head check warning caused by uninitialization of list_head in usb mtu3
    (bsc#1220484).
    - CVE-2021-46938: Fixed a double free of blk_mq_tag_set in dev remove after table load fails in dm rq
    (bsc#1220554).
    - CVE-2021-46939: Fixed a denial of service in trace_clock_global() in tracing (bsc#1220580).
    - CVE-2021-46943: Fixed an oops in set_fmt error handling in media: staging/intel-ipu3 (bsc#1220583).
    - CVE-2021-46944: Fixed a memory leak in imu_fmt in media staging/intel-ipu3 (bsc#1220566).
    - CVE-2021-46950: Fixed a data corruption bug in raid1 arrays using bitmaps in md/raid1 (bsc#1220662).
    - CVE-2021-46951: Fixed an integer underflow of efi_tpm_final_log_size in tpm_read_log_efi in tpm efi
    (bsc#1220615).
    - CVE-2021-46958: Fixed a race between transaction aborts and fsyncs leading to use-after-free in btrfs
    (bsc#1220521).
    - CVE-2021-46960: Fixed a warning on smb2_get_enc_key in cifs (bsc#1220528).
    - CVE-2021-46961: Fixed an error on not enabling irqs when handling spurious interrups in irqchip/gic-v3
    (bsc#1220529).
    - CVE-2021-46962: Fixed a resource leak in the remove function in mmc uniphier-sd (bsc#1220532).
    - CVE-2021-46963: Fixed a denial of service in qla2xxx_mqueuecommand() in scsi qla2xxx (bsc#1220536)
    - CVE-2021-46971: Fixed unconditional security_locked_down() call in perf/core (bsc#1220697).
    - CVE-2021-46981: Fixed a NULL pointer in flush_workqueue in nbd (bsc#1220611).
    - CVE-2021-46984: Fixed an out of bounds access in kyber_bio_merge() in kyber (bsc#1220631).
    - CVE-2021-46988: Fixed release page in error path to avoid BUG_ON in userfaultfd (bsc#1220706).
    - CVE-2021-46990: Fixed a denial of service when toggling entry flush barrier in powerpc/64s
    (bsc#1220743).
    - CVE-2021-46991: Fixed a use-after-free in i40e_client_subtask (bsc#1220575).
    - CVE-2021-46992: Fixed a bug to avoid overflows in nft_hash_buckets (bsc#1220638).
    - CVE-2021-46998: Fixed an use after free bug in enic_hard_start_xmit in ethernet/enic (bsc#1220625).
    - CVE-2021-47000: Fixed an inode leak on getattr error in __fh_to_dentry in ceph (bsc#1220669).
    - CVE-2021-47006: Fixed wrong check in overflow_handler hook in ARM 9064/1 hw_breakpoint (bsc#1220751).
    - CVE-2021-47013: Fixed a use after free in emac_mac_tx_buf_send (bsc#1220641).
    - CVE-2021-47015: Fixed a RX consumer index logic in the error path in bnxt_rx_pkt() in bnxt_en
    (bsc#1220794).
    - CVE-2021-47020: Fixed a memory leak in stream config error path in soundwire stream (bsc#1220785).
    - CVE-2021-47034: Fixed a kernel memory fault for pte update on radix in powerpc/64s (bsc#1220687).
    - CVE-2021-47045: Fixed a null pointer dereference in lpfc_prep_els_iocb() in scsi lpfc (bsc#1220640).
    - CVE-2021-47049: Fixed an after free in __vmbus_open() in hv vmbus (bsc#1220692).
    - CVE-2021-47051: Fixed a PM reference leak in lpspi_prepare_xfer_hardware() in spi fsl-lpspi
    (bsc#1220764).
    - CVE-2021-47055: Fixed missing permissions for locking and badblock ioctls in mtd (bsc#1220768).
    - CVE-2021-47056: Fixed a user-memory-access error on vf2pf_lock in crypto (bsc#1220769).
    - CVE-2021-47058: Fixed a possible user-after-free in set debugfs_name in regmap (bsc#1220779).
    - CVE-2021-47061: Fixed a bug in KVM by destroy I/O bus devices on unregister failure _after_  sync'ing
    SRCU (bsc#1220745).
    - CVE-2021-47063: Fixed a potential use-after-free during bridge detach in drm bridge/panel (bsc#1220777).
    - CVE-2021-47065: Fixed an array overrun in rtw_get_tx_power_params() in rtw88 (bsc#1220749).
    - CVE-2021-47068: Fixed a use-after-free issue in llcp_sock_bind/connect (bsc#1220739).
    - CVE-2021-47069: Fixed a crash due to relying on a stack reference past its expiry in ipc/mqueue,
    ipc/msg, ipc/sem (bsc#1220826).
    - CVE-2021-47070: Fixed a memory leak in error handling paths on memory allocated by vmbus_alloc_ring in
    uio_hv_generic (bsc#1220829).
    - CVE-2021-47071: Fixed a memory leak in error handling paths in hv_uio_cleanup() in uio_hv_generic
    (bsc#1220846).
    - CVE-2021-47073: Fixed a oops on rmmod dell_smbios exit_dell_smbios_wmi() in platform/x86 dell-smbios-wmi
    (bsc#1220850).
    - CVE-2021-47077: Fixed a NULL pointer dereference when in shost_data (bsc#1220861).
    - CVE-2021-47082: Fixed a double free in tun_free_netdev in tun (bsc#1220969).
    - CVE-2021-47109: Fixed an overflow in neighbour table in neighbour (bsc#1221534).
    - CVE-2021-47110: Fixed possible memory corruption when restoring from hibernation in x86/kvm
    (bsc#1221532).
    - CVE-2021-47112: Fixed possible memory corruption when restoring from hibernation in x86/kvm
    (bsc#1221541).
    - CVE-2021-47114: Fixed a data corruption by fallocate in ocfs2 (bsc#1221548).
    - CVE-2021-47117: Fixed a crash in ext4_es_cache_extent as ext4_split_extent_at failed in ext4
    (bsc#1221575).
    - CVE-2021-47118: Fixed an use-after-free in init task's struct pid in pid (bsc#1221605).
    - CVE-2021-47119: Fixed a memory leak in ext4_fill_super in ext4 (bsc#1221608).
    - CVE-2021-47120: Fixed a NULL pointer dereference on disconnect in HID magicmouse (bsc#1221606).
    - CVE-2021-47138: Fixed an out-of-bound memory access during clearing filters in cxgb4 (bsc#1221934).
    - CVE-2021-47139: Fixed a race condition that lead to oops in netdevice registration in net hns3
    (bsc#1221935).
    - CVE-2021-47141: Fixed a null pointer dereference on priv->msix_vectors when driver is unloaded in gve
    (bsc#1221949).
    - CVE-2021-47142: Fixed an use-after-free on ttm->sg in drm/amdgpu (bsc#1221952).
    - CVE-2021-47144: Fixed a refcount leak in amdgpufb_create in drm/amd/amdgpu (bsc#1221989).
    - CVE-2021-47153: Fixed an out-of-range memory access during bus reset in the case of a block transaction
    in i2c/i801 (bsc#1221969).
    - CVE-2021-47161: Fixed a resource leak in an error handling path in the error handling path of the probe
    function in spi spi-fsl-dspi (bsc#1221966).
    - CVE-2021-47165: Fixed a NULL pointer dereference when component was not probed during shutdown in
    drm/mesonhe (bsc#1221965).
    - CVE-2021-47166: Fixed a data corruption of pg_bytes_written in nfs_do_recoalesce() in nfs (bsc#1221998).
    - CVE-2021-47167: Fixed an oopsable condition in __nfs_pageio_add_request() in nfs (bsc#1221991).
    - CVE-2021-47168: Fixed an incorrect limit in filelayout_decode_layout() in nfs (bsc#1222002).
    - CVE-2021-47169: Fixed a NULL pointer dereference in rp2_probe in serial rp2 (bsc#1222000).
    - CVE-2021-47170: Fixed a WARN about excessively large memory allocations in usb usbfs (bsc#1222004).
    - CVE-2021-47171: Fixed a memory leak in smsc75xx_bind in net usb (bsc#1221994).
    - CVE-2021-47172: Fixed a potential overflow due to non sequential channel numbers in adc/ad7124
    (bsc#1221992).
    - CVE-2021-47173: Fixed a memory leak in uss720_probe in misc/uss720 (bsc#1221993).
    - CVE-2021-47177: Fixed a sysfs leak in alloc_iommu() in iommu/vt-d (bsc#1221997).
    - CVE-2021-47179: Fixed a NULL pointer dereference in pnfs_mark_matching_lsegs_return() in nfsv4
    (bsc#1222001).
    - CVE-2021-47180: Fixed a memory leak in nci_allocate_device nfcmrvl_disconnect in nfc nci (bsc#1221999).
    - CVE-2021-47181: Fixed a null pointer dereference caused by calling platform_get_resource()
    (bsc#1222660).
    - CVE-2021-47183: Fixed a null pointer dereference during link down processing in scsi lpfc (bsc#1192145,
    bsc#1222664).
    - CVE-2021-47185: Fixed a softlockup issue in flush_to_ldisc in tty tty_buffer (bsc#1222669).
    - CVE-2021-47189: Fixed denial of service due to memory ordering issues between normal and ordered work
    functions in btrfs (bsc#1222706).
    - CVE-2022-0487: Fixed an use-after-free vulnerability in rtsx_usb_ms_drv_remove() in
    drivers/memstick/host/rtsx_usb_ms.c (bsc#1194516).
    - CVE-2022-4744: Fixed a double-free that could lead to DoS or privilege escalation in TUN/TAP device
    driver functionality (bsc#1209635).
    - CVE-2022-48626: Fixed a potential use-after-free on remove path in moxart (bsc#1220366).
    - CVE-2023-0160: Fixed deadlock flaw in BPF that could allow a local user to potentially crash the system
    (bsc#1209657).
    - CVE-2023-1192: Fixed use-after-free in cifs_demultiplex_thread() (bsc#1208995).
    - CVE-2023-28746: Fixed Register File Data Sampling (bsc#1213456).
    - CVE-2023-35827: Fixed a use-after-free issue in ravb_tx_timeout_work() (bsc#1212514).
    - CVE-2023-52454: Fixed a kernel panic when host sends an invalid H2C PDU length in nvmet-tcp
    (bsc#1220320).
    - CVE-2023-52469: Fixed an use-after-free in kv_parse_power_table in drivers/amd/pm (bsc#1220411).
    - CVE-2023-52470: Fixed null-ptr-deref in radeon_crtc_init() (bsc#1220413).
    - CVE-2023-52474: Fixed a data corruption in user SDMA requests in IB/hfi1 (bsc#1220445).
    - CVE-2023-52476: Fixed possible unhandled page fault via perf sampling NMI during vsyscall (bsc#1220703).
    - CVE-2023-52477: Fixed USB Hub accesses to uninitialized BOS descriptors (bsc#1220790).
    - CVE-2023-52500: Fixed information leaking when processing OPC_INB_SET_CONTROLLER_CONFIG command
    (bsc#1220883).
    - CVE-2023-52500: Fixed leaking tags when processing  OPC_INB_SET_CONTROLLER_CONFIG command in scsi in
    pm80xx (bsc#1220883).
    - CVE-2023-52509: Fixed a use-after-free issue in ravb_tx_timeout_work() (bsc#1220836).
    - CVE-2023-52572: Fixed UAF in cifs_demultiplex_thread() in cifs (bsc#1220946).
    - CVE-2023-52575: Fixed SBPB enablement for spec_rstack_overflow=off (bsc#1220871).
    - CVE-2023-52583: Fixed deadlock or deadcode of misusing dget() inside ceph (bsc#1221058).
    - CVE-2023-52590: Fixed a possible ocfs2 filesystem corruption via directory renaming (bsc#1221088).
    - CVE-2023-52591: Fixed a possible reiserfs filesystem corruption via directory renaming (bsc#1221044).
    - CVE-2023-52607: Fixed null-pointer dereference in pgtable_cache_add kasprintf() in powerpc/mm
    (bsc#1221061).
    - CVE-2023-52628: Fixed 4-byte stack OOB write in nftables (bsc#1222117).
    - CVE-2023-6270: Fixed a use-after-free issue in aoecmd_cfg_pkts (bsc#1218562).
    - CVE-2023-6356: Fixed a NULL pointer dereference in nvmet_tcp_build_pdu_iovec (bsc#1217987).
    - CVE-2023-6531: Fixed a use-after-free flaw due to a race problem in the unix garbage collector's
    deletion of SKB races (bsc#1218447).
    - CVE-2023-6535: Fixed a NULL pointer dereference in nvmet_tcp_execute_request (bsc#1217988).
    - CVE-2023-6536: Fixed a NULL pointer dereference in __nvmet_req_complete (bsc#1217989).
    - CVE-2023-7042: Fixed a null pointer dereference in ath10k_wmi_tlv_op_pull_mgmt_tx_compl_ev() in
    drivers/net/wireless/ath/ath10k/wmi-tlv.c in net (bsc#1218336).
    - CVE-2023-7192: Fixed a memory leak problem in ctnetlink_create_conntrack in
    net/netfilter/nf_conntrack_netlink.c (bsc#1218479).
    - CVE-2024-22099: Fixed a null pointer dereference in /net/bluetooth/rfcomm/core.C in bluetooth
    (bsc#1219170).
    - CVE-2024-26600: Fixed null pointer dereference for SRP in phy-omap-usb2 (bsc#1220340).
    - CVE-2024-26614: Fixed the initialization of accept_queue's spinlocks (bsc#1221293).
    - CVE-2024-26642: Fixed the set of anonymous timeout flag in netfilter nf_tables (bsc#1221830).
    - CVE-2024-26704: Fixed a double-free of blocks due to wrong extents moved_len in ext4 (bsc#1222422).
    - CVE-2024-26733: Fixed an overflow in arp_req_get() in arp (bsc#1222585).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222706");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-April/035109.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36782");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36783");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46961");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46963");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46971");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47034");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47065");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47069");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47070");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47071");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47109");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47110");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47112");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47117");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47118");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47119");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47120");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47139");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47144");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47153");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47165");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47167");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47168");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47169");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47170");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47171");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47172");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47173");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47177");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47181");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47183");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47185");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47189");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0487");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48626");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52454");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52469");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52470");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52474");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52500");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52572");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52575");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6356");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-7042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-7192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26733");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23134");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-26704");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150200_24_188-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(2)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP2", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-default-base-5.3.18-150200.24.188.1.150200.9.95.3', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-default-devel-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-devel-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-macros-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-obs-build-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-preempt-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-preempt-devel-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-source-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-syms-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'reiserfs-kmp-default-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'kernel-default-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-base-5.3.18-150200.24.188.1.150200.9.95.3', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-base-5.3.18-150200.24.188.1.150200.9.95.3', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-devel-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-default-devel-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-devel-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-macros-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-obs-build-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-obs-build-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-preempt-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-preempt-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-preempt-devel-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-preempt-devel-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-source-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'kernel-syms-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'kernel-syms-5.3.18-150200.24.188.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'cluster-md-kmp-default-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'dlm-kmp-default-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'gfs2-kmp-default-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'ocfs2-kmp-default-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.2']},
    {'reference':'kernel-default-livepatch-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']},
    {'reference':'kernel-default-livepatch-devel-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']},
    {'reference':'kernel-livepatch-5_3_18-150200_24_188-default-1-150200.5.3.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']},
    {'reference':'kernel-default-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'kernel-default-base-5.3.18-150200.24.188.1.150200.9.95.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'kernel-default-devel-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'kernel-obs-build-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'kernel-syms-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'reiserfs-kmp-default-5.3.18-150200.24.188.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
