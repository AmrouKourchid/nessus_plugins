#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2381-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(202177);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id(
    "CVE-2021-4439",
    "CVE-2021-47103",
    "CVE-2021-47191",
    "CVE-2021-47193",
    "CVE-2021-47267",
    "CVE-2021-47270",
    "CVE-2021-47293",
    "CVE-2021-47294",
    "CVE-2021-47297",
    "CVE-2021-47309",
    "CVE-2021-47328",
    "CVE-2021-47354",
    "CVE-2021-47372",
    "CVE-2021-47379",
    "CVE-2021-47407",
    "CVE-2021-47418",
    "CVE-2021-47434",
    "CVE-2021-47445",
    "CVE-2021-47518",
    "CVE-2021-47544",
    "CVE-2021-47566",
    "CVE-2021-47571",
    "CVE-2021-47576",
    "CVE-2021-47587",
    "CVE-2021-47589",
    "CVE-2021-47600",
    "CVE-2021-47602",
    "CVE-2021-47603",
    "CVE-2021-47609",
    "CVE-2021-47617",
    "CVE-2022-48711",
    "CVE-2022-48715",
    "CVE-2022-48722",
    "CVE-2022-48732",
    "CVE-2022-48733",
    "CVE-2022-48740",
    "CVE-2022-48743",
    "CVE-2022-48754",
    "CVE-2022-48756",
    "CVE-2022-48758",
    "CVE-2022-48759",
    "CVE-2022-48760",
    "CVE-2022-48761",
    "CVE-2022-48771",
    "CVE-2022-48772",
    "CVE-2023-5281",
    "CVE-2023-24023",
    "CVE-2023-52622",
    "CVE-2023-52675",
    "CVE-2023-52737",
    "CVE-2023-52752",
    "CVE-2023-52754",
    "CVE-2023-52757",
    "CVE-2023-52762",
    "CVE-2023-52764",
    "CVE-2023-52784",
    "CVE-2023-52808",
    "CVE-2023-52809",
    "CVE-2023-52832",
    "CVE-2023-52834",
    "CVE-2023-52835",
    "CVE-2023-52843",
    "CVE-2023-52845",
    "CVE-2023-52855",
    "CVE-2023-52881",
    "CVE-2024-26633",
    "CVE-2024-26641",
    "CVE-2024-26679",
    "CVE-2024-26687",
    "CVE-2024-26720",
    "CVE-2024-26813",
    "CVE-2024-26845",
    "CVE-2024-26863",
    "CVE-2024-26894",
    "CVE-2024-26928",
    "CVE-2024-26973",
    "CVE-2024-27399",
    "CVE-2024-27410",
    "CVE-2024-35247",
    "CVE-2024-35807",
    "CVE-2024-35822",
    "CVE-2024-35835",
    "CVE-2024-35862",
    "CVE-2024-35863",
    "CVE-2024-35864",
    "CVE-2024-35865",
    "CVE-2024-35867",
    "CVE-2024-35868",
    "CVE-2024-35870",
    "CVE-2024-35886",
    "CVE-2024-35896",
    "CVE-2024-35922",
    "CVE-2024-35925",
    "CVE-2024-35930",
    "CVE-2024-35950",
    "CVE-2024-35956",
    "CVE-2024-35958",
    "CVE-2024-35960",
    "CVE-2024-35962",
    "CVE-2024-35976",
    "CVE-2024-35979",
    "CVE-2024-35997",
    "CVE-2024-35998",
    "CVE-2024-36016",
    "CVE-2024-36017",
    "CVE-2024-36025",
    "CVE-2024-36479",
    "CVE-2024-36592",
    "CVE-2024-36880",
    "CVE-2024-36894",
    "CVE-2024-36915",
    "CVE-2024-36917",
    "CVE-2024-36919",
    "CVE-2024-36923",
    "CVE-2024-36934",
    "CVE-2024-36938",
    "CVE-2024-36940",
    "CVE-2024-36949",
    "CVE-2024-36950",
    "CVE-2024-36960",
    "CVE-2024-36964",
    "CVE-2024-37021",
    "CVE-2024-37354",
    "CVE-2024-38544",
    "CVE-2024-38545",
    "CVE-2024-38546",
    "CVE-2024-38549",
    "CVE-2024-38552",
    "CVE-2024-38553",
    "CVE-2024-38565",
    "CVE-2024-38567",
    "CVE-2024-38578",
    "CVE-2024-38579",
    "CVE-2024-38580",
    "CVE-2024-38597",
    "CVE-2024-38601",
    "CVE-2024-38608",
    "CVE-2024-38618",
    "CVE-2024-38621",
    "CVE-2024-38627",
    "CVE-2024-38659",
    "CVE-2024-38661",
    "CVE-2024-38780"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2381-1");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2024:2381-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:2381-1 advisory.

    The SUSE Linux Enterprise 12 SP5 RT kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2021-47103: net: sock: preserve kabi for sock (bsc#1221010).
    - CVE-2021-47191: Fix out-of-bound read in resp_readcap16() (bsc#1222866).
    - CVE-2021-47267: usb: fix various gadget panics on 10gbps cabling (bsc#1224993).
    - CVE-2021-47270: usb: fix various gadgets null ptr deref on 10gbps cabling (bsc#1224997).
    - CVE-2021-47293: net/sched: act_skbmod: Skip non-Ethernet packets (bsc#1224978).
    - CVE-2021-47294: netrom: Decrease sock refcount when sock timers expire (bsc#1224977).
    - CVE-2021-47297: net: fix uninit-value in caif_seqpkt_sendmsg (bsc#1224976).
    - CVE-2021-47309: net: validate lwtstate->data before returning from skb_tunnel_info() (bsc#1224967).
    - CVE-2021-47354: drm/sched: Avoid data corruptions (bsc#1225140)
    - CVE-2021-47372: net: macb: fix use after free on rmmod (bsc#1225184).
    - CVE-2021-47379: blk-cgroup: fix UAF by grabbing blkcg lock before destroying blkg pd (bsc#1225203).
    - CVE-2021-47407: KVM: x86: Handle SRCU initialization failure during page track init (bsc#1225306).
    - CVE-2021-47418: net_sched: fix NULL deref in fifo_set_limit() (bsc#1225337).
    - CVE-2021-47434: xhci: Fix commad ring abort, write all 64 bits to CRCR register (bsc#1225232).
    - CVE-2021-47445: drm/msm: Fix null pointer dereference on pointer edp (bsc#1225261)
    - CVE-2021-47518: nfc: fix potential NULL pointer deref in nfc_genl_dump_ses_done (bsc#1225372).
    - CVE-2021-47544: tcp: fix page frag corruption on page fault (bsc#1225463).
    - CVE-2021-47566: Fix clearing user buffer by properly using clear_user() (bsc#1225514).
    - CVE-2021-47571: staging: rtl8192e: Fix use after free in _rtl92e_pci_disconnect() (bsc#1225518).
    - CVE-2021-47587: net: systemport: Add global locking for descriptor lifecycle (bsc#1226567).
    - CVE-2021-47602: mac80211: track only QoS data frames for admission control (bsc#1226554).
    - CVE-2021-47609: firmware: arm_scpi: Fix string overflow in SCPI genpd driver (bsc#1226562)
    - CVE-2022-48732: drm/nouveau: fix off by one in BIOS boundary checking (bsc#1226716)
    - CVE-2022-48733: btrfs: fix use-after-free after failure to create a snapshot (bsc#1226718).
    - CVE-2022-48740: selinux: fix double free of cond_list on error paths (bsc#1226699).
    - CVE-2022-48743: net: amd-xgbe: Fix skb data length underflow (bsc#1226705).
    - CVE-2022-48756: drm/msm/dsi: invalid parameter check in msm_dsi_phy_enable (bsc#1226698)
    - CVE-2022-48759: rpmsg: char: Fix race between the release of rpmsg_ctrldev and cdev (bsc#1226711).
    - CVE-2022-48761: usb: xhci-plat: fix crash when suspend if remote wake enable (bsc#1226701).
    - CVE-2022-48772: media: lgdt3306a: Add a check against null-pointer-def (bsc#1226976).
    - CVE-2023-24023: Bluetooth: Add more enc key size check (bsc#1218148).
    - CVE-2023-52622: ext4: avoid online resizing failures due to oversized flex bg (bsc#1222080).
    - CVE-2023-52675: powerpc/imc-pmu: Add a null pointer check in update_events_in_group() (bsc#1224504).
    - CVE-2023-52737: btrfs: lock the inode in shared mode before starting fiemap (bsc#1225484).
    - CVE-2023-52752: smb: client: fix use-after-free bug in cifs_debug_data_proc_show() (bsc#1225487).
    - CVE-2023-52754: media: imon: fix access to invalid resource for the second interface (bsc#1225490).
    - CVE-2023-52757: Fixed potential deadlock when releasing mids (bsc#1225548).
    - CVE-2023-52762: virtio-blk: fix implicit overflow on virtio_max_dma_size (bsc#1225573).
    - CVE-2023-52764: media: gspca: cpia1: shift-out-of-bounds in set_flicker (bsc#1225571).
    - CVE-2023-52784: bonding: stop the device in bond_setup_by_slave() (bsc#1224946).
    - CVE-2023-52832: wifi: mac80211: do not return unset power in ieee80211_get_tx_power() (bsc#1225577).
    - CVE-2023-52834: atl1c: Work around the DMA RX overflow issue (bsc#1225599).
    - CVE-2023-52835: perf/core: Bail out early if the request AUX area is out of bound (bsc#1225602).
    - CVE-2023-52843: llc: verify mac len before reading mac header (bsc#1224951).
    - CVE-2023-52845: tipc: Change nla_policy for bearer-related names to NLA_NUL_STRING (bsc#1225585).
    - CVE-2023-52855: usb: dwc2: fix possible NULL pointer dereference caused by driver concurrency
    (bsc#1225583).
    - CVE-2023-52881: tcp: do not accept ACK of bytes we never sent (bsc#1225611).
    - CVE-2024-26633: ip6_tunnel: fix NEXTHDR_FRAGMENT handling in ip6_tnl_parse_tlv_enc_lim() (bsc#1221647).
    - CVE-2024-26641: ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv() (bsc#1221654).
    - CVE-2024-26679: Fixed read sk->sk_family once in inet_recv_error() (bsc#1222385).
    - CVE-2024-26687: Fixed xen/events close evtchn after mapping cleanup (bsc#1222435).
    - CVE-2024-26720: mm: Avoid overflows in dirty throttling logic (bsc#1222364).
    - CVE-2024-26813: vfio/platform: Create persistent IRQ handlers (bsc#1222809).
    - CVE-2024-26863: hsr: Fix uninit-value access in hsr_get_node() (bsc#1223021).
    - CVE-2024-26894: ACPI: processor_idle: Fix memory leak in acpi_processor_power_exit() (bsc#1223043).
    - CVE-2024-26928: Fixed potential UAF in cifs_debug_files_proc_show() (bsc#1223532).
    - CVE-2024-26973: fat: fix uninitialized field in nostale filehandles (bsc#1223641).
    - CVE-2024-27399: Bluetooth: l2cap: fix null-ptr-deref in l2cap_chan_timeout (bsc#1224177).
    - CVE-2024-27410: Reject iftype change with mesh ID change (bsc#1224432).
    - CVE-2024-35247: fpga: region: add owner module and take its refcount (bsc#1226948).
    - CVE-2024-35807: ext4: fix corruption during on-line resize (bsc#1224735).
    - CVE-2024-35822: usb: udc: remove warning when queue disabled ep (bsc#1224739).
    - CVE-2024-35835: net/mlx5e: fix a double-free in arfs_create_groups (bsc#1224605).
    - CVE-2024-35862: Fixed potential UAF in smb2_is_network_name_deleted() (bsc#1224764).
    - CVE-2024-35863: Fixed potential UAF in is_valid_oplock_break() (bsc#1224763).
    - CVE-2024-35864: Fixed potential UAF in smb2_is_valid_lease_break() (bsc#1224765).
    - CVE-2024-35865: Fixed potential UAF in smb2_is_valid_oplock_break() (bsc#1224668).
    - CVE-2024-35867: Fixed potential UAF in cifs_stats_proc_show() (bsc#1224664).
    - CVE-2024-35868: Fixed potential UAF in cifs_stats_proc_write() (bsc#1224678).
    - CVE-2024-35870: Fixed UAF in smb2_reconnect_server() (bsc#1224672).
    - CVE-2024-35886: ipv6: Fix infinite recursion in fib6_dump_done() (bsc#1224670).
    - CVE-2024-35922: fbmon: prevent division by zero in fb_videomode_from_videomode() (bsc#1224660)
    - CVE-2024-35925: block: prevent division by zero in blk_rq_stat_sum() (bsc#1224661).
    - CVE-2024-35930: scsi: lpfc: Fix possible memory leak in lpfc_rcv_padisc() (bsc#1224651).
    - CVE-2024-35950: drm/client: Fully protect modes with dev->mode_config.mutex (bsc#1224703).
    - CVE-2024-35956: Fixed qgroup prealloc rsv leak in subvolume operations (bsc#1224674)
    - CVE-2024-35958: net: ena: Fix incorrect descriptor free behavior (bsc#1224677).
    - CVE-2024-35960: net/mlx5: Properly link new fs rules into the tree (bsc#1224588).
    - CVE-2024-35976: Validate user input for XDP_{UMEM|COMPLETION}_FILL_RING (bsc#1224575).
    - CVE-2024-35979: raid1: fix use-after-free for original bio in raid1_write_request() (bsc#1224572).
    - CVE-2024-35997: Remove I2C_HID_READ_PENDING flag to prevent lock-up (bsc#1224552).
    - CVE-2024-35998: Fixed lock ordering potential deadlock in cifs_sync_mid_result (bsc#1224549).
    - CVE-2024-36016: tty: n_gsm: fix possible out-of-bounds in gsm0_receive() (bsc#1225642).
    - CVE-2024-36017: rtnetlink: Correct nested IFLA_VF_VLAN_LIST attribute validation (bsc#1225681).
    - CVE-2024-36479: fpga: bridge: add owner module and take its refcount (bsc#1226949).
    - CVE-2024-36592: scsi: lpfc: Move NPIV's transport unregistration to after resource clean up
    (bsc#1225898).
    - CVE-2024-36880: Bluetooth: qca: add missing firmware sanity checks (bsc#1225722).
    - CVE-2024-36894: usb: gadget: f_fs: Fix race between aio_cancel() and AIO request complete (bsc#1225749).
    - CVE-2024-36915: nfc: llcp: fix nfc_llcp_setsockopt() unsafe copies (bsc#1225758).
    - CVE-2024-36917: block: fix overflow in blk_ioctl_discard() (bsc#1225770).
    - CVE-2024-36919: scsi: bnx2fc: Remove spin_lock_bh while releasing resources after upload (bsc#1225767).
    - CVE-2024-36923: fs/9p: fix uninitialized values during inode evict (bsc#1225815).
    - CVE-2024-36934: bna: ensure the copied buf is NUL terminated (bsc#1225760).
    - CVE-2024-36938: Fixed NULL pointer dereference in sk_psock_skb_ingress_enqueue (bsc#1225761).
    - CVE-2024-36940: pinctrl: core: delete incorrect free in pinctrl_enable() (bsc#1225840).
    - CVE-2024-36949: amd/amdkfd: sync all devices to wait all processes being evicted (bsc#1225872)
    - CVE-2024-36950: firewire: ohci: mask bus reset interrupts between ISR and bottom half (bsc#1225895).
    - CVE-2024-36960: drm/vmwgfx: Fix invalid reads in fence signaled events (bsc#1225872)
    - CVE-2024-36964: fs/9p: only translate RWX permissions for plain 9P2000 (bsc#1225866).
    - CVE-2024-37021: fpga: manager: add owner module and take its refcount (bsc#1226950).
    - CVE-2024-37354: btrfs: fix crash on racing fsync and size-extending write into prealloc (bsc#1227101).
    - CVE-2024-38544: RDMA/rxe: Fix seg fault in rxe_comp_queue_pkt (bsc#1226597)
    - CVE-2024-38545: RDMA/hns: Fix UAF for cq async event (bsc#1226595).
    - CVE-2024-38546: drm: vc4: Fix possible null pointer dereference (bsc#1226593).
    - CVE-2024-38549: drm/mediatek: Add 0 size check to mtk_drm_gem_obj (bsc#1226735)
    - CVE-2024-38552: drm/amd/display: Fix potential index out of bounds in color (bsc#1226767)
    - CVE-2024-38553: net: fec: remove .ndo_poll_controller to avoid deadlock (bsc#1226744).
    - CVE-2024-38565: wifi: ar5523: enable proper endpoint verification (bsc#1226747).
    - CVE-2024-38567: wifi: carl9170: add a proper sanity check for endpoints (bsc#1226769).
    - CVE-2024-38578: ecryptfs: Fix buffer size for tag 66 packet (bsc#1226634).
    - CVE-2024-38579: crypto: bcm - Fix pointer arithmetic (bsc#1226637).
    - CVE-2024-38580: epoll: be better about file lifetimes (bsc#1226610).
    - CVE-2024-38597: eth: sungem: remove .ndo_poll_controller to avoid deadlocks (bsc#1226749).
    - CVE-2024-38608: net/mlx5e: Fix netif state handling (bsc#1226746).
    - CVE-2024-38618: ALSA: timer: Set lower bound of start tick time (bsc#1226754).
    - CVE-2024-38621: media: stk1160: fix bounds checking in stk1160_copy_video() (bsc#1226895).
    - CVE-2024-38627: stm class: Fix a double free in stm_register_device() (bsc#1226857).
    - CVE-2024-38659: enic: Validate length of nl attributes in enic_set_vf_port (bsc#1226883).
    - CVE-2024-38661: s390/ap: Fix crash in AP internal function modify_bitmap() (bsc#1226996).
    - CVE-2024-38780: dma-buf/sw-sync: do not enable IRQ from sync_print_obj() (bsc#1226886).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1119113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223043");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225184");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225232");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225261");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227101");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-July/035895.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4439");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47103");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47191");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47193");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47267");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47293");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47294");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47297");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47309");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47328");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47354");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47372");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47379");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47407");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47418");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47445");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47518");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47544");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47576");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47589");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47617");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48711");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48722");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48758");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48761");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48771");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-24023");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52757");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52762");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52808");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52832");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27399");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27410");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35247");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35822");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36479");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37354");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38544");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38549");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38552");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38553");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38578");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38579");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38580");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38618");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38621");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38627");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38780");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5281");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-rt");
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
    {'reference':'cluster-md-kmp-rt-4.12.14-10.191.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'dlm-kmp-rt-4.12.14-10.191.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'gfs2-kmp-rt-4.12.14-10.191.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-devel-rt-4.12.14-10.191.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-4.12.14-10.191.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-base-4.12.14-10.191.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-devel-4.12.14-10.191.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-4.12.14-10.191.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-devel-4.12.14-10.191.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-source-rt-4.12.14-10.191.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-syms-rt-4.12.14-10.191.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'ocfs2-kmp-rt-4.12.14-10.191.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-rt / dlm-kmp-rt / gfs2-kmp-rt / kernel-devel-rt / etc');
}
