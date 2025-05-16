#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2372-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(202100);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/10");

  script_cve_id(
    "CVE-2021-4439",
    "CVE-2021-47089",
    "CVE-2021-47432",
    "CVE-2021-47515",
    "CVE-2021-47534",
    "CVE-2021-47538",
    "CVE-2021-47539",
    "CVE-2021-47555",
    "CVE-2021-47566",
    "CVE-2021-47571",
    "CVE-2021-47572",
    "CVE-2021-47576",
    "CVE-2021-47577",
    "CVE-2021-47578",
    "CVE-2021-47580",
    "CVE-2021-47582",
    "CVE-2021-47583",
    "CVE-2021-47584",
    "CVE-2021-47585",
    "CVE-2021-47586",
    "CVE-2021-47587",
    "CVE-2021-47589",
    "CVE-2021-47592",
    "CVE-2021-47595",
    "CVE-2021-47596",
    "CVE-2021-47597",
    "CVE-2021-47600",
    "CVE-2021-47601",
    "CVE-2021-47602",
    "CVE-2021-47603",
    "CVE-2021-47604",
    "CVE-2021-47605",
    "CVE-2021-47607",
    "CVE-2021-47608",
    "CVE-2021-47609",
    "CVE-2021-47610",
    "CVE-2021-47611",
    "CVE-2021-47612",
    "CVE-2021-47614",
    "CVE-2021-47615",
    "CVE-2021-47616",
    "CVE-2021-47617",
    "CVE-2021-47618",
    "CVE-2021-47619",
    "CVE-2021-47620",
    "CVE-2022-48711",
    "CVE-2022-48712",
    "CVE-2022-48713",
    "CVE-2022-48714",
    "CVE-2022-48715",
    "CVE-2022-48716",
    "CVE-2022-48717",
    "CVE-2022-48718",
    "CVE-2022-48720",
    "CVE-2022-48721",
    "CVE-2022-48722",
    "CVE-2022-48723",
    "CVE-2022-48724",
    "CVE-2022-48725",
    "CVE-2022-48726",
    "CVE-2022-48727",
    "CVE-2022-48728",
    "CVE-2022-48729",
    "CVE-2022-48730",
    "CVE-2022-48732",
    "CVE-2022-48733",
    "CVE-2022-48734",
    "CVE-2022-48735",
    "CVE-2022-48736",
    "CVE-2022-48737",
    "CVE-2022-48738",
    "CVE-2022-48739",
    "CVE-2022-48740",
    "CVE-2022-48743",
    "CVE-2022-48744",
    "CVE-2022-48745",
    "CVE-2022-48746",
    "CVE-2022-48747",
    "CVE-2022-48748",
    "CVE-2022-48749",
    "CVE-2022-48751",
    "CVE-2022-48752",
    "CVE-2022-48753",
    "CVE-2022-48754",
    "CVE-2022-48755",
    "CVE-2022-48756",
    "CVE-2022-48758",
    "CVE-2022-48759",
    "CVE-2022-48760",
    "CVE-2022-48761",
    "CVE-2022-48763",
    "CVE-2022-48765",
    "CVE-2022-48766",
    "CVE-2022-48767",
    "CVE-2022-48768",
    "CVE-2022-48769",
    "CVE-2022-48770",
    "CVE-2022-48771",
    "CVE-2022-48772",
    "CVE-2023-24023",
    "CVE-2023-52622",
    "CVE-2023-52658",
    "CVE-2023-52667",
    "CVE-2023-52670",
    "CVE-2023-52672",
    "CVE-2023-52675",
    "CVE-2023-52735",
    "CVE-2023-52737",
    "CVE-2023-52752",
    "CVE-2023-52766",
    "CVE-2023-52784",
    "CVE-2023-52787",
    "CVE-2023-52800",
    "CVE-2023-52835",
    "CVE-2023-52837",
    "CVE-2023-52843",
    "CVE-2023-52845",
    "CVE-2023-52846",
    "CVE-2023-52869",
    "CVE-2023-52881",
    "CVE-2023-52882",
    "CVE-2023-52884",
    "CVE-2024-26625",
    "CVE-2024-26644",
    "CVE-2024-26720",
    "CVE-2024-26842",
    "CVE-2024-26845",
    "CVE-2024-26923",
    "CVE-2024-26973",
    "CVE-2024-27432",
    "CVE-2024-33619",
    "CVE-2024-35247",
    "CVE-2024-35789",
    "CVE-2024-35790",
    "CVE-2024-35807",
    "CVE-2024-35814",
    "CVE-2024-35835",
    "CVE-2024-35848",
    "CVE-2024-35857",
    "CVE-2024-35861",
    "CVE-2024-35862",
    "CVE-2024-35864",
    "CVE-2024-35869",
    "CVE-2024-35878",
    "CVE-2024-35884",
    "CVE-2024-35886",
    "CVE-2024-35896",
    "CVE-2024-35898",
    "CVE-2024-35900",
    "CVE-2024-35905",
    "CVE-2024-35925",
    "CVE-2024-35950",
    "CVE-2024-35956",
    "CVE-2024-35958",
    "CVE-2024-35960",
    "CVE-2024-35962",
    "CVE-2024-35997",
    "CVE-2024-36005",
    "CVE-2024-36008",
    "CVE-2024-36017",
    "CVE-2024-36020",
    "CVE-2024-36021",
    "CVE-2024-36025",
    "CVE-2024-36477",
    "CVE-2024-36478",
    "CVE-2024-36479",
    "CVE-2024-36890",
    "CVE-2024-36894",
    "CVE-2024-36899",
    "CVE-2024-36900",
    "CVE-2024-36904",
    "CVE-2024-36915",
    "CVE-2024-36916",
    "CVE-2024-36917",
    "CVE-2024-36919",
    "CVE-2024-36934",
    "CVE-2024-36937",
    "CVE-2024-36940",
    "CVE-2024-36945",
    "CVE-2024-36949",
    "CVE-2024-36960",
    "CVE-2024-36964",
    "CVE-2024-36965",
    "CVE-2024-36967",
    "CVE-2024-36969",
    "CVE-2024-36971",
    "CVE-2024-36975",
    "CVE-2024-36978",
    "CVE-2024-37021",
    "CVE-2024-37078",
    "CVE-2024-37354",
    "CVE-2024-38381",
    "CVE-2024-38388",
    "CVE-2024-38390",
    "CVE-2024-38540",
    "CVE-2024-38541",
    "CVE-2024-38544",
    "CVE-2024-38545",
    "CVE-2024-38546",
    "CVE-2024-38547",
    "CVE-2024-38548",
    "CVE-2024-38549",
    "CVE-2024-38550",
    "CVE-2024-38552",
    "CVE-2024-38553",
    "CVE-2024-38555",
    "CVE-2024-38556",
    "CVE-2024-38557",
    "CVE-2024-38559",
    "CVE-2024-38560",
    "CVE-2024-38564",
    "CVE-2024-38565",
    "CVE-2024-38567",
    "CVE-2024-38568",
    "CVE-2024-38571",
    "CVE-2024-38573",
    "CVE-2024-38578",
    "CVE-2024-38579",
    "CVE-2024-38580",
    "CVE-2024-38581",
    "CVE-2024-38582",
    "CVE-2024-38583",
    "CVE-2024-38587",
    "CVE-2024-38590",
    "CVE-2024-38591",
    "CVE-2024-38594",
    "CVE-2024-38597",
    "CVE-2024-38599",
    "CVE-2024-38600",
    "CVE-2024-38601",
    "CVE-2024-38603",
    "CVE-2024-38605",
    "CVE-2024-38608",
    "CVE-2024-38616",
    "CVE-2024-38618",
    "CVE-2024-38619",
    "CVE-2024-38621",
    "CVE-2024-38627",
    "CVE-2024-38630",
    "CVE-2024-38633",
    "CVE-2024-38634",
    "CVE-2024-38635",
    "CVE-2024-38659",
    "CVE-2024-38661",
    "CVE-2024-38780",
    "CVE-2024-39301",
    "CVE-2024-39468",
    "CVE-2024-39469",
    "CVE-2024-39471"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2372-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2024:2372-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2024:2372-1 advisory.

    The SUSE Linux Enterprise 15 SP5 Azure kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2021-47089: kfence: fix memory leak when cat kfence objects (bsc#1220958.
    - CVE-2021-47432: lib/generic-radix-tree.c: Do not overflow in peek() (bsc#1225391).
    - CVE-2021-47515: seg6: fix the iif in the IPv6 socket control block (bsc#1225426).
    - CVE-2021-47538: rxrpc: Fix rxrpc_local leak in rxrpc_lookup_peer() (bsc#1225448).
    - CVE-2021-47539: rxrpc: Fix rxrpc_peer leak in rxrpc_look_up_bundle() (bsc#1225452).
    - CVE-2021-47555: net: vlan: fix underflow for the real_dev refcnt (bsc#1225467).
    - CVE-2021-47566: Fix clearing user buffer by properly using clear_user() (bsc#1225514).
    - CVE-2021-47571: staging: rtl8192e: Fix use after free in _rtl92e_pci_disconnect() (bsc#1225518).
    - CVE-2021-47572: net: nexthop: fix null pointer dereference when IPv6 is not enabled (bsc#1225389).
    - CVE-2022-48716: ASoC: codecs: wcd938x: fix incorrect used of portid (bsc#1226678).
    - CVE-2023-24023: Bluetooth: Add more enc key size check (bsc#1218148).
    - CVE-2023-52622: ext4: avoid online resizing failures due to oversized flex bg (bsc#1222080).
    - CVE-2023-52658: Revert 'net/mlx5: Block entering switchdev mode with ns inconsistency' (bsc#1224719).
    - CVE-2023-52667: net/mlx5e: fix a potential double-free in fs_any_create_groups (bsc#1224603).
    - CVE-2023-52670: rpmsg: virtio: Free driver_override when rpmsg_remove() (bsc#1224696).
    - CVE-2023-52672: pipe: wakeup wr_wait after setting max_usage (bsc#1224614).
    - CVE-2023-52675: powerpc/imc-pmu: Add a null pointer check in update_events_in_group() (bsc#1224504).
    - CVE-2023-52735: bpf, sockmap: Don't let sock_map_{close,destroy,unhash} call itself (bsc#1225475).
    - CVE-2023-52737: btrfs: lock the inode in shared mode before starting fiemap (bsc#1225484).
    - CVE-2023-52752: smb: client: fix use-after-free bug in cifs_debug_data_proc_show() (bsc#1225487).
    - CVE-2023-52784: bonding: stop the device in bond_setup_by_slave() (bsc#1224946).
    - CVE-2023-52787: blk-mq: make sure active queue usage is held for bio_integrity_prep() (bsc#1225105).
    - CVE-2023-52835: perf/core: Bail out early if the request AUX area is out of bound (bsc#1225602).
    - CVE-2023-52837: nbd: fix uaf in nbd_open (bsc#1224935).
    - CVE-2023-52843: llc: verify mac len before reading mac header (bsc#1224951).
    - CVE-2023-52845: tipc: Change nla_policy for bearer-related names to NLA_NUL_STRING (bsc#1225585).
    - CVE-2023-52846: hsr: Prevent use after free in prp_create_tagged_frame() (bsc#1225098).
    - CVE-2023-52869: pstore/platform: Add check for kstrdup (bsc#1225050).
    - CVE-2023-52881: tcp: do not accept ACK of bytes we never sent (bsc#1225611).
    - CVE-2023-52882: clk: sunxi-ng: h6: Reparent CPUX during PLL CPUX rate change (bsc#1225692).
    - CVE-2024-26625: Call sock_orphan() at release time (bsc#1221086)
    - CVE-2024-26644: btrfs: do not abort filesystem when attempting to snapshot deleted subvolume
    (bsc#1221282bsc#1222072).
    - CVE-2024-26720: mm: Avoid overflows in dirty throttling logic (bsc#1222364).
    - CVE-2024-26923: Fixed false-positive lockdep splat for spin_lock() in __unix_gc() (bsc#1223384).
    - CVE-2024-26973: fat: fix uninitialized field in nostale filehandles (git-fixesbsc#1223641).
    - CVE-2024-27432: net: ethernet: mtk_eth_soc: fix PPE hanging issue (bsc#1224716).
    - CVE-2024-35247: fpga: region: add owner module and take its refcount (bsc#1226948).
    - CVE-2024-35789: Check fast rx for non-4addr sta VLAN changes (bsc#1224749).
    - CVE-2024-35790: usb: typec: altmodes/displayport: create sysfs nodes as driver's default device
    attribute group (bsc#1224712).
    - CVE-2024-35807: ext4: fix corruption during on-line resize (bsc#1224735).
    - CVE-2024-35835: net/mlx5e: fix a double-free in arfs_create_groups (bsc#1224605).
    - CVE-2024-35848: eeprom: at24: fix memory corruption race condition (bsc#1224612).
    - CVE-2024-35857: icmp: prevent possible NULL dereferences from icmp_build_probe() (bsc#1224619).
    - CVE-2024-35861: Fixed potential UAF in cifs_signal_cifsd_for_reconnect() (bsc#1224766).
    - CVE-2024-35862: Fixed potential UAF in smb2_is_network_name_deleted() (bsc#1224764).
    - CVE-2024-35864: Fixed potential UAF in smb2_is_valid_lease_break() (bsc#1224765).
    - CVE-2024-35869: smb: client: guarantee refcounted children from parent session (bsc#1224679).
    - CVE-2024-35884: udp: do not accept non-tunnel GSO skbs landing in a tunnel (bsc#1224520).
    - CVE-2024-35886: ipv6: Fix infinite recursion in fib6_dump_done() (bsc#1224670).
    - CVE-2024-35898: netfilter: nf_tables: Fix potential data-race in __nft_flowtable_type_get()
    (bsc#1224498).
    - CVE-2024-35900: netfilter: nf_tables: reject new basechain after table flag update (bsc#1224497).
    - CVE-2024-35925: block: prevent division by zero in blk_rq_stat_sum() (bsc#1224661).
    - CVE-2024-35950: drm/client: Fully protect modes with dev->mode_config.mutex (bsc#1224703).
    - CVE-2024-35958: net: ena: Fix incorrect descriptor free behavior (bsc#1224677).
    - CVE-2024-35960: net/mlx5: Properly link new fs rules into the tree (bsc#1224588).
    - CVE-2024-35997: Remove I2C_HID_READ_PENDING flag to prevent lock-up (bsc#1224552).
    - CVE-2024-36005: netfilter: nf_tables: honor table dormant flag from netdev release event path
    (bsc#1224539).
    - CVE-2024-36008: ipv4: check for NULL idev in ip_route_use_hint() (bsc#1224540).
    - CVE-2024-36017: rtnetlink: Correct nested IFLA_VF_VLAN_LIST attribute validation (bsc#1225681).
    - CVE-2024-36020: i40e: fix vf may be used uninitialized in this function warning (bsc#1225698).
    - CVE-2024-36021: net: hns3: fix kernel crash when devlink reload during pf initialization (bsc#1225699).
    - CVE-2024-36478: null_blk: fix null-ptr-dereference while configuring 'power' and 'submit_queues'
    (bsc#1226841).
    - CVE-2024-36479: fpga: bridge: add owner module and take its refcount (bsc#1226949).
    - CVE-2024-36890: mm/slab: make __free(kfree) accept error pointers (bsc#1225714).
    - CVE-2024-36894: usb: gadget: f_fs: Fix race between aio_cancel() and AIO request complete (bsc#1225749).
    - CVE-2024-36899: gpiolib: cdev: Fix use after free in lineinfo_changed_notify (bsc#1225737).
    - CVE-2024-36900: net: hns3: fix kernel crash when devlink reload during initialization (bsc#1225726).
    - CVE-2024-36904: tcp: Use refcount_inc_not_zero() in tcp_twsk_unique() (bsc#1225732).
    - CVE-2024-36915: nfc: llcp: fix nfc_llcp_setsockopt() unsafe copies (bsc#1225758).
    - CVE-2024-36916: blk-iocost: avoid out of bounds shift (bsc#1225759).
    - CVE-2024-36917: block: fix overflow in blk_ioctl_discard() (bsc#1225770).
    - CVE-2024-36919: scsi: bnx2fc: Remove spin_lock_bh while releasing resources after upload (bsc#1225767).
    - CVE-2024-36934: bna: ensure the copied buf is NUL terminated (bsc#1225760).
    - CVE-2024-36937: xdp: use flags field to disambiguate broadcast redirect (bsc#1225834).
    - CVE-2024-36940: pinctrl: core: delete incorrect free in pinctrl_enable() (bsc#1225840).
    - CVE-2024-36945: net/smc: fix neighbour and rtable leak in smc_ib_find_route() (bsc#1225823).
    - CVE-2024-36949: amd/amdkfd: sync all devices to wait all processes being evicted (bsc#1225872)
    - CVE-2024-36964: fs/9p: only translate RWX permissions for plain 9P2000 (bsc#1225866).
    - CVE-2024-36971: net: fix __dst_negative_advice() race (bsc#1226145).
    - CVE-2024-36978: net: sched: sch_multiq: fix possible OOB write in multiq_tune() (bsc#1226514).
    - CVE-2024-37021: fpga: manager: add owner module and take its refcount (bsc#1226950).
    - CVE-2024-37078: nilfs2: fix potential kernel bug due to lack of writeback flag waiting (bsc#1227066).
    - CVE-2024-37354: btrfs: fix crash on racing fsync and size-extending write into prealloc (bsc#1227101).
    - CVE-2024-38545: RDMA/hns: Fix UAF for cq async event (bsc#1226595).
    - CVE-2024-38553: net: fec: remove .ndo_poll_controller to avoid deadlock (bsc#1226744).
    - CVE-2024-38555: net/mlx5: Discard command completions in internal error (bsc#1226607).
    - CVE-2024-38556: net/mlx5: Add a timeout to acquire the command queue semaphore (bsc#1226774).
    - CVE-2024-38557: net/mlx5: Reload only IB representors upon lag disable/enable (bsc#1226781).
    - CVE-2024-38559: scsi: qedf: Ensure the copied buf is NUL terminated (bsc#1226785).
    - CVE-2024-38560: scsi: bfa: Ensure the copied buf is NUL terminated (bsc#1226786).
    - CVE-2024-38564: bpf: Add BPF_PROG_TYPE_CGROUP_SKB attach type enforcement in BPF_LINK_CREATE
    (bsc#1226789).
    - CVE-2024-38568: drivers/perf: hisi: hns3: Fix out-of-bound access when valid event group (bsc#1226771).
    - CVE-2024-38578: ecryptfs: Fix buffer size for tag 66 packet (bsc#1226634,).
    - CVE-2024-38580: epoll: be better about file lifetimes (bsc#1226610).
    - CVE-2024-38594: net: stmmac: move the EST lock to struct stmmac_priv (bsc#1226734).
    - CVE-2024-38597: eth: sungem: remove .ndo_poll_controller to avoid deadlocks (bsc#1226749).
    - CVE-2024-38603: drivers/perf: hisi: hns3: Actually use devm_add_action_or_reset() (bsc#1226842).
    - CVE-2024-38608: net/mlx5e: Fix netif state handling (bsc#1226746).
    - CVE-2024-38627: stm class: Fix a double free in stm_register_device() (bsc#1226857).
    - CVE-2024-38659: enic: Validate length of nl attributes in enic_set_vf_port (bsc#1226883).
    - CVE-2024-38661: s390/ap: Fix crash in AP internal function modify_bitmap() (bsc#1226996).
    - CVE-2024-38780: dma-buf/sw-sync: do not enable IRQ from sync_print_obj() (bsc#1226886).
    - CVE-2024-39301: net/9p: fix uninit-value in p9_client_rpc() (bsc#1226994).
    - CVE-2024-39468: smb: client: fix deadlock in smb2_find_smb_tcon() (bsc#1227103.
    - CVE-2024-39469: nilfs2: fix nilfs_empty_dir() misjudgment and long loop on I/O errors (bsc#1226992).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224603");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226603");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227274");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-July/035868.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4439");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47432");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47515");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47534");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47538");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47539");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47555");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47572");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47576");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47577");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47578");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47580");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47584");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47585");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47589");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47596");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47604");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47612");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47617");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47618");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48711");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48712");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48714");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48716");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48717");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48718");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48721");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48722");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48724");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48725");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48726");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48727");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48728");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48729");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48734");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48736");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48738");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48745");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48749");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48755");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48758");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48761");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48765");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48767");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48768");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48769");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48770");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48771");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-24023");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52658");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52787");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52869");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26625");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27432");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-33619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35247");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35790");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35869");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36478");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36479");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36971");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37354");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38381");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38388");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38390");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38540");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38544");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38547");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38549");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38550");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38552");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38553");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38555");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38556");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38557");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38559");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38560");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38564");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38568");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38573");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38578");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38579");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38580");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38618");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38621");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38627");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38630");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38634");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39468");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39469");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39471");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38630");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/10");

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
    {'reference':'kernel-azure-5.14.21-150500.33.60.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.60.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.60.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.60.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.60.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.60.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.60.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.60.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.60.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.60.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.60.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.60.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.60.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.60.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.60.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.60.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150500.33.60.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'cluster-md-kmp-azure-5.14.21-150500.33.60.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-azure-5.14.21-150500.33.60.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-azure-5.14.21-150500.33.60.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-azure-5.14.21-150500.33.60.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-azure-5.14.21-150500.33.60.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.60.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-5.14.21-150500.33.60.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.60.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-devel-5.14.21-150500.33.60.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-extra-5.14.21-150500.33.60.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-extra-5.14.21-150500.33.60.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150500.33.60.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-livepatch-devel-5.14.21-150500.33.60.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-optional-5.14.21-150500.33.60.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-optional-5.14.21-150500.33.60.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-azure-vdso-5.14.21-150500.33.60.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-devel-azure-5.14.21-150500.33.60.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-source-azure-5.14.21-150500.33.60.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.60.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-azure-5.14.21-150500.33.60.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-azure-5.14.21-150500.33.60.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-azure-5.14.21-150500.33.60.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150500.33.60.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-azure-5.14.21-150500.33.60.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150500.33.60.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-azure-5.14.21-150500.33.60.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
