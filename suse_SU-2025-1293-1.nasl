#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1293-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(234545);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2017-5753",
    "CVE-2021-46925",
    "CVE-2021-47633",
    "CVE-2021-47645",
    "CVE-2021-47648",
    "CVE-2021-47652",
    "CVE-2022-1016",
    "CVE-2022-1048",
    "CVE-2022-1184",
    "CVE-2022-2977",
    "CVE-2022-3303",
    "CVE-2022-26373",
    "CVE-2022-49046",
    "CVE-2022-49051",
    "CVE-2022-49053",
    "CVE-2022-49058",
    "CVE-2022-49059",
    "CVE-2022-49065",
    "CVE-2022-49066",
    "CVE-2022-49074",
    "CVE-2022-49075",
    "CVE-2022-49084",
    "CVE-2022-49085",
    "CVE-2022-49095",
    "CVE-2022-49098",
    "CVE-2022-49100",
    "CVE-2022-49107",
    "CVE-2022-49109",
    "CVE-2022-49114",
    "CVE-2022-49119",
    "CVE-2022-49120",
    "CVE-2022-49122",
    "CVE-2022-49155",
    "CVE-2022-49156",
    "CVE-2022-49157",
    "CVE-2022-49158",
    "CVE-2022-49159",
    "CVE-2022-49160",
    "CVE-2022-49164",
    "CVE-2022-49191",
    "CVE-2022-49196",
    "CVE-2022-49204",
    "CVE-2022-49209",
    "CVE-2022-49217",
    "CVE-2022-49220",
    "CVE-2022-49226",
    "CVE-2022-49259",
    "CVE-2022-49264",
    "CVE-2022-49271",
    "CVE-2022-49272",
    "CVE-2022-49275",
    "CVE-2022-49280",
    "CVE-2022-49281",
    "CVE-2022-49286",
    "CVE-2022-49287",
    "CVE-2022-49288",
    "CVE-2022-49291",
    "CVE-2022-49292",
    "CVE-2022-49293",
    "CVE-2022-49295",
    "CVE-2022-49297",
    "CVE-2022-49300",
    "CVE-2022-49308",
    "CVE-2022-49313",
    "CVE-2022-49321",
    "CVE-2022-49322",
    "CVE-2022-49330",
    "CVE-2022-49331",
    "CVE-2022-49332",
    "CVE-2022-49337",
    "CVE-2022-49343",
    "CVE-2022-49344",
    "CVE-2022-49347",
    "CVE-2022-49349",
    "CVE-2022-49367",
    "CVE-2022-49370",
    "CVE-2022-49372",
    "CVE-2022-49388",
    "CVE-2022-49389",
    "CVE-2022-49395",
    "CVE-2022-49397",
    "CVE-2022-49404",
    "CVE-2022-49407",
    "CVE-2022-49409",
    "CVE-2022-49413",
    "CVE-2022-49414",
    "CVE-2022-49416",
    "CVE-2022-49421",
    "CVE-2022-49429",
    "CVE-2022-49432",
    "CVE-2022-49433",
    "CVE-2022-49434",
    "CVE-2022-49437",
    "CVE-2022-49443",
    "CVE-2022-49444",
    "CVE-2022-49472",
    "CVE-2022-49488",
    "CVE-2022-49492",
    "CVE-2022-49495",
    "CVE-2022-49497",
    "CVE-2022-49505",
    "CVE-2022-49513",
    "CVE-2022-49516",
    "CVE-2022-49519",
    "CVE-2022-49524",
    "CVE-2022-49526",
    "CVE-2022-49530",
    "CVE-2022-49532",
    "CVE-2022-49538",
    "CVE-2022-49544",
    "CVE-2022-49545",
    "CVE-2022-49546",
    "CVE-2022-49555",
    "CVE-2022-49563",
    "CVE-2022-49564",
    "CVE-2022-49566",
    "CVE-2022-49578",
    "CVE-2022-49581",
    "CVE-2022-49584",
    "CVE-2022-49589",
    "CVE-2022-49605",
    "CVE-2022-49607",
    "CVE-2022-49610",
    "CVE-2022-49611",
    "CVE-2022-49619",
    "CVE-2022-49620",
    "CVE-2022-49623",
    "CVE-2022-49638",
    "CVE-2022-49640",
    "CVE-2022-49641",
    "CVE-2022-49647",
    "CVE-2022-49649",
    "CVE-2022-49657",
    "CVE-2022-49667",
    "CVE-2022-49672",
    "CVE-2022-49673",
    "CVE-2022-49674",
    "CVE-2022-49687",
    "CVE-2022-49707",
    "CVE-2022-49708",
    "CVE-2022-49710",
    "CVE-2022-49711",
    "CVE-2022-49713",
    "CVE-2022-49727",
    "CVE-2022-49733",
    "CVE-2022-49740",
    "CVE-2023-2162",
    "CVE-2023-3567",
    "CVE-2023-52933",
    "CVE-2023-52935",
    "CVE-2023-52973",
    "CVE-2023-52974",
    "CVE-2023-52979",
    "CVE-2023-52997",
    "CVE-2023-53000",
    "CVE-2023-53006",
    "CVE-2023-53007",
    "CVE-2023-53008",
    "CVE-2023-53010",
    "CVE-2023-53015",
    "CVE-2023-53019",
    "CVE-2023-53024",
    "CVE-2023-53031",
    "CVE-2024-35910",
    "CVE-2024-36968",
    "CVE-2024-38559",
    "CVE-2024-41005",
    "CVE-2024-47678",
    "CVE-2024-49571",
    "CVE-2024-49935",
    "CVE-2024-49940",
    "CVE-2024-50269",
    "CVE-2024-50290",
    "CVE-2024-53063",
    "CVE-2024-53124",
    "CVE-2024-53140",
    "CVE-2024-53680",
    "CVE-2024-56633",
    "CVE-2024-56640",
    "CVE-2024-56770",
    "CVE-2024-57900",
    "CVE-2024-57973",
    "CVE-2024-57979",
    "CVE-2024-57996",
    "CVE-2024-58014",
    "CVE-2024-58052",
    "CVE-2024-58071",
    "CVE-2024-58072",
    "CVE-2024-58083",
    "CVE-2025-21703",
    "CVE-2025-21708",
    "CVE-2025-21744",
    "CVE-2025-21759",
    "CVE-2025-21760",
    "CVE-2025-21762",
    "CVE-2025-21763",
    "CVE-2025-21765",
    "CVE-2025-21766",
    "CVE-2025-21776",
    "CVE-2025-21782",
    "CVE-2025-21785",
    "CVE-2025-21791",
    "CVE-2025-21796",
    "CVE-2025-21802",
    "CVE-2025-21821",
    "CVE-2025-21831",
    "CVE-2025-21846",
    "CVE-2025-21848",
    "CVE-2025-21855",
    "CVE-2025-21858",
    "CVE-2025-21865",
    "CVE-2025-21871",
    "CVE-2025-21877",
    "CVE-2025-21891",
    "CVE-2025-21916",
    "CVE-2025-21922",
    "CVE-2025-21934",
    "CVE-2025-21935",
    "CVE-2025-21969",
    "CVE-2025-21993",
    "CVE-2025-21996",
    "CVE-2025-22007"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1293-1");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2025:1293-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2025:1293-1 advisory.

    The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2021-46925: Fixed kernel panic caused by race of smc_sock (bsc#1220466).
    - CVE-2021-47645: media: staging: media: zoran: calculate the right buffer number for zoran_reap_stat_com
    (bsc#1237767).
    - CVE-2021-47648: gpu: host1x: Fix a memory leak in 'host1x_remove()' (bsc#1237725).
    - CVE-2022-49046: i2c: dev: check return value when calling dev_set_name() (bsc#1237842).
    - CVE-2022-49051: net: usb: aqc111: Fix out-of-bounds accesses in RX fixup (bsc#1237903).
    - CVE-2022-49053: scsi: target: tcmu: Fix possible page UAF (bsc#1237918).
    - CVE-2022-49059: nfc: nci: add flush_workqueue to prevent uaf (bsc#1238007).
    - CVE-2022-49074: irqchip/gic-v3: Fix GICR_CTLR.RWP polling (bsc#1237728).
    - CVE-2022-49075: btrfs: fix qgroup reserve overflow the qgroup limit (bsc#1237733).
    - CVE-2022-49084: qede: confirm skb is allocated before using (bsc#1237751).
    - CVE-2022-49107: ceph: fix memory leak in ceph_readdir when note_last_dentry returns error (bsc#1237973).
    - CVE-2022-49109: ceph: fix inode reference leakage in ceph_get_snapdir() (bsc#1237836).
    - CVE-2022-49119: scsi: pm8001: Fix memory leak in pm8001_chip_fw_flash_update_req() (bsc#1237925).
    - CVE-2022-49120: scsi: pm8001: Fix task leak in pm8001_send_abort_all() (bsc#1237969).
    - CVE-2022-49209: bpf, sockmap: Fix memleak in tcp_bpf_sendmsg while sk msg is full (bsc#1238252).
    - CVE-2022-49220: dax: make sure inodes are flushed before destroy cache (bsc#1237936).
    - CVE-2022-49275: can: m_can: m_can_tx_handler(): fix use after free of skb (bsc#1238719).
    - CVE-2022-49286: tpm: use try_get_ops() in tpm-space.c (bsc#1238647).
    - CVE-2022-49292: ALSA: oss: Fix PCM OSS buffer allocation overflow (bsc#1238625).
    - CVE-2022-49308: extcon: Modify extcon device to be created after driver data is set (bsc#1238654).
    - CVE-2022-49331: nfc: st21nfca: fix memory leaks in EVT_TRANSACTION handling (bsc#1237813).
    - CVE-2022-49344: af_unix: Fix a data-race in unix_dgram_peer_wake_me() (bsc#1237988).
    - CVE-2022-49367: net: dsa: mv88e6xxx: Fix refcount leak in mv88e6xxx_mdios_register (bsc#1238447).
    - CVE-2022-49370: firmware: dmi-sysfs: Fix memory leak in dmi_sysfs_register_handle (bsc#1238467).
    - CVE-2022-49372: tcp: tcp_rtx_synack() can be called from process context (bsc#1238251).
    - CVE-2022-49388: ubi: ubi_create_volume: Fix use-after-free when volume creation failed (bsc#1237934).
    - CVE-2022-49395: um: Fix out-of-bounds read in LDT setup (bsc#1237953).
    - CVE-2022-49397: phy: qcom-qmp: fix struct clk leak on probe errors (bsc#1237823).
    - CVE-2022-49404: RDMA/hfi1: Fix potential integer multiplication overflow errors (bsc#1238430).
    - CVE-2022-49416: wifi: mac80211: fix use-after-free in chanctx code (bsc#1238293).
    - CVE-2022-49433: RDMA/hfi1: Prevent use of lock before it is initialized (bsc#1238268).
    - CVE-2022-49472: net: phy: micrel: Allow probing without .driver_data (bsc#1238951).
    - CVE-2022-49488: drm/msm/mdp5: Return error code in mdp5_mixer_release when deadlock (bsc#1238600).
    - CVE-2022-49495: drm/msm/hdmi: check return value after calling platform_get_resource_byname()
    (bsc#1237932).
    - CVE-2022-49497: net: remove two BUG() from skb_checksum_help() (bsc#1238946).
    - CVE-2022-49505: NFC: NULL out the dev->rfkill to prevent UAF (bsc#1238615).
    - CVE-2022-49516: ice: always check VF VSI pointer values (bsc#1238953).
    - CVE-2022-49519: ath10k: skip ath10k_halt during suspend for driver state RESTARTING (bsc#1238943).
    - CVE-2022-49524: media: pci: cx23885: Fix the error handling in cx23885_initdev() (bsc#1238949).
    - CVE-2022-49530: drm/amd/pm: fix double free in si_parse_power_table() (bsc#1238944).
    - CVE-2022-49538: ALSA: jack: Fix mutex call in snd_jack_report() (bsc#1238843).
    - CVE-2022-49544: ipw2x00: Fix potential NULL dereference in libipw_xmit() (bsc#1238721).
    - CVE-2022-49545: ALSA: usb-audio: Cancel pending work at closing a MIDI substream (bsc#1238729).
    - CVE-2022-49546: x86/kexec: Fix double-free of elf header buffer (bsc#1238750).
    - CVE-2022-49563: crypto: qat - add param check for RSA (bsc#1238787).
    - CVE-2022-49564: crypto: qat - add param check for DH (bsc#1238789).
    - CVE-2022-49578: ip: Fix data-races around sysctl_ip_prot_sock. (bsc#1238794).
    - CVE-2022-49581: be2net: Fix buffer overflow in be_get_module_eeprom (bsc#1238540).
    - CVE-2022-49589: kABI: protect mr_ifc_count change (bsc#1238598).
    - CVE-2022-49605: igc: Reinstate IGC_REMOVED logic and implement it properly (bsc#1238433).
    - CVE-2022-49607: perf/core: Fix data race between perf_event_set_output() and perf_mmap_close()
    (bsc#1238817).
    - CVE-2022-49610: KVM: VMX: Prevent RSB underflow before vmenter (bsc#1238952).
    - CVE-2022-49619: net: sfp: fix memory leak in sfp_probe() (bsc#1239003).
    - CVE-2022-49620: net: tipc: fix possible refcount leak in tipc_sk_create() (bsc#1239002).
    - CVE-2022-49640: sysctl: Fix data races in proc_douintvec_minmax() (bsc#1237782).
    - CVE-2022-49641: sysctl: Fix data races in proc_douintvec() (bsc#1237831).
    - CVE-2022-49667: net: bonding: fix use-after-free after 802.3ad slave unbind (bsc#1238282).
    - CVE-2022-49672: net: tun: unlink NAPI from device on destruction (bsc#1238816).
    - CVE-2022-49711: bus: fsl-mc-bus: fix KASAN use-after-free in fsl_mc_bus_remove() (bsc#1238416).
    - CVE-2022-49727: ipv6: Fix signed integer overflow in l2tp_ip6_sendmsg (bsc#1239059).
    - CVE-2022-49740: wifi: brcmfmac: Check the count value of channel spec to prevent out-of-bounds reads
    (bsc#1240233).
    - CVE-2023-52935: mm/khugepaged: fix ->anon_vma race (bsc#1240276).
    - CVE-2023-52997: ipv4: prevent potential spectre v1 gadget in ip_metrics_convert() (bsc#1240303).
    - CVE-2023-53010: bnxt: Do not read past the end of test names (bsc#1240290).
    - CVE-2023-53019: net: mdio: validate parameter addr in mdiobus_get_phy() (bsc#1240286).
    - CVE-2024-35910: kABI fix for tcp: properly terminate timers for kernel sockets (bsc#1224489).
    - CVE-2024-36968: Bluetooth: L2CAP: Fix div-by-zero in l2cap_le_flowctl_init() (bsc#1226130).
    - CVE-2024-38559: scsi: qedf: Ensure the copied buf is NUL terminated (bsc#1226785).
    - CVE-2024-41005: netpoll: Fix race condition in netpoll_owner_active (bsc#1227858).
    - CVE-2024-49571: net/smc: check iparea_offset and ipv6_prefixes_cnt when receiving proposal msg
    (bsc#1235733).
    - CVE-2024-49935: ACPI: PAD: fix crash in exit_round_robin() (bsc#1232370).
    - CVE-2024-49940: l2tp: prevent possible tunnel refcount underflow (bsc#1232812).
    - CVE-2024-50269: usb: musb: sunxi: Fix accessing an released usb phy (bsc#1233458).
    - CVE-2024-53124: net: fix data-races around sk->sk_forward_alloc (bsc#1234074).
    - CVE-2024-53140: netlink: terminate outstanding dump on socket close (bsc#1234222).
    - CVE-2024-53680: ipvs: fix UB due to uninitialized stack access in ip_vs_protocol_init() (bsc#1235715).
    - CVE-2024-56640: net/smc: fix LGR and link use-after-free issue (bsc#1235436).
    - CVE-2024-56770: net/sched: netem: account for backlog updates from child qdisc (bsc#1235637).
    - CVE-2024-57900: ila: serialize calls to nf_register_net_hooks() (bsc#1235973).
    - CVE-2024-57973: rdma/cxgb4: Prevent potential integer overflow on 32bit (bsc#1238531).
    - CVE-2024-57979: kABI workaround for pps changes (bsc#1238521).
    - CVE-2024-57996: net_sched: sch_sfq: do not allow 1 packet limit (bsc#1239076).
    - CVE-2024-58014: wifi: brcmsmac: add gain range check to wlc_phy_iqcal_gainparams_nphy() (bsc#1239109).
    - CVE-2024-58052: drm/amdgpu: Fix potential NULL pointer dereference in atomctrl_get_smc_sclk_range_table
    (bsc#1238986).
    - CVE-2024-58071: team: prevent adding a device which is already a team device lower (bsc#1238970)
    - CVE-2024-58072: wifi: rtlwifi: remove unused check_buddy_priv (bsc#1238964).
    - CVE-2024-58083: KVM: Explicitly verify target vCPU is online in kvm_get_vcpu() (bsc#1239036).
    - CVE-2025-21703: netem: Update sch->q.qlen before qdisc_tree_reduce_backlog() (bsc#1237313).
    - CVE-2025-21708: net: usb: rtl8150: enable basic endpoint checking (bsc#1239087).
    - CVE-2025-21744: wifi: brcmfmac: fix NULL pointer dereference in brcmf_txfinalize() (bsc#1238903).
    - CVE-2025-21759: ipv6: mcast: extend RCU protection in igmp6_send() (bsc#1238738).
    - CVE-2025-21760: ndisc: extend RCU protection in ndisc_send_skb() (bsc#1238763).
    - CVE-2025-21762: arp: use RCU protection in arp_xmit() (bsc#1238780).
    - CVE-2025-21763: neighbour: use RCU protection in __neigh_notify() (bsc#1237897).
    - CVE-2025-21765: ipv6: use RCU protection in ip6_default_advmss() (bsc#1237906).
    - CVE-2025-21766: ipv4: use RCU protection in __ip_rt_update_pmtu() (bsc#1238754).
    - CVE-2025-21776: USB: hub: Ignore non-compliant devices with too many configs or interfaces
    (bsc#1238909).
    - CVE-2025-21782: orangefs: fix a oob in orangefs_debug_write (bsc#1239117).
    - CVE-2025-21785: arm64: cacheinfo: Avoid out-of-bounds write to cacheinfo array (bsc#1238747).
    - CVE-2025-21791: vrf: use RCU protection in l3mdev_l3_out() (bsc#1238512).
    - CVE-2025-21796: nfsd: clear acl_access/acl_default after releasing them (bsc#1238716).
    - CVE-2025-21802: net: hns3: fix oops when unload drivers paralleling (bsc#1238751).
    - CVE-2025-21821: fbdev: omap: use threaded IRQ for LCD DMA (bsc#1239174).
    - CVE-2025-21831: PCI: Avoid putting some root ports into D3 on TUXEDO Sirius Gen1 (bsc#1239039).
    - CVE-2025-21846: acct: perform last write from workqueue (bsc#1239508).
    - CVE-2025-21848: nfp: bpf: Add check for nfp_app_ctrl_msg_alloc() (bsc#1239479).
    - CVE-2025-21865: gtp: Suppress list corruption splat in gtp_net_exit_batch_rtnl() (bsc#1239481).
    - CVE-2025-21871: tee: optee: Fix supplicant wait loop (bsc#1240183).
    - CVE-2025-21877: usbnet: gl620a: fix endpoint checking in genelink_bind() (bsc#1240172).
    - CVE-2025-21891: ipvlan: ensure network headers are in skb linear part (bsc#1240186).
    - CVE-2025-21916: usb: atm: cxacru: fix a flaw in existing endpoint checks (bsc#1240582).
    - CVE-2025-21922: ppp: Fix KMSAN uninit-value warning with bpf (bsc#1240639).
    - CVE-2025-21934: rapidio: fix an API misues when rio_add_net() fails (bsc#1240708).
    - CVE-2025-21935: rapidio: add check for rio_add_net() in rio_scan_alloc_net() (bsc#1240700).
    - CVE-2025-21969: Bluetooth: L2CAP: Fix build errors in some archs (bsc#1240784).
    - CVE-2025-21993: iscsi_ibft: Fix UBSAN shift-out-of-bounds warning in ibft_attr_show_nic() (bsc#1240797).
    - CVE-2025-21996: drm/radeon: fix uninitialized size issue in radeon_vce_cs_parse() (bsc#1240801).
    - CVE-2025-22007: Bluetooth: Fix error code in chan_alloc_skb_cb() (bsc#1240582).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1051510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1054914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1129770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232370");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238257");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240801");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/039011.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-5753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47648");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-26373");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3303");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49046");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49053");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49065");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49066");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49075");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49084");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49100");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49107");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49109");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49119");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49120");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49122");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49159");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49164");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49191");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49196");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49204");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49209");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49217");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49220");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49226");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49259");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49264");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49271");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49272");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49275");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49286");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49287");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49291");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49293");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49295");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49297");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49300");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49308");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49313");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49321");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49322");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49330");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49331");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49332");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49337");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49343");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49344");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49347");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49349");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49367");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49370");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49372");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49388");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49389");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49395");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49397");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49404");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49407");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49409");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49413");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49414");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49416");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49421");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49429");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49432");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49433");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49437");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49443");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49444");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49488");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49492");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49495");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49497");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49513");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49516");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49519");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49526");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49530");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49538");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49544");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49555");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49563");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49564");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49578");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49584");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49589");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49638");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49647");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49649");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49710");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49711");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49727");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53031");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36968");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38559");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50269");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53140");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56770");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58052");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58071");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58072");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58083");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21762");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21765");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21776");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21782");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21785");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21802");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21831");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21993");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-22007");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1048");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-21969");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_255-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-kgraft-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-default-kgraft-devel-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kgraft-patch-4_12_14-122_255-default-1-8.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.255.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.255.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.255.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.255.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.255.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.255.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.255.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.255.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.255.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.255.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
