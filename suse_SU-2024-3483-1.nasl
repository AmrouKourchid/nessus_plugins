#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3483-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(207884);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/30");

  script_cve_id(
    "CVE-2021-4204",
    "CVE-2021-4441",
    "CVE-2021-47106",
    "CVE-2021-47517",
    "CVE-2021-47546",
    "CVE-2022-0500",
    "CVE-2022-4382",
    "CVE-2022-23222",
    "CVE-2022-38457",
    "CVE-2022-40133",
    "CVE-2022-48645",
    "CVE-2022-48706",
    "CVE-2022-48808",
    "CVE-2022-48865",
    "CVE-2022-48868",
    "CVE-2022-48869",
    "CVE-2022-48870",
    "CVE-2022-48871",
    "CVE-2022-48872",
    "CVE-2022-48873",
    "CVE-2022-48875",
    "CVE-2022-48878",
    "CVE-2022-48880",
    "CVE-2022-48881",
    "CVE-2022-48882",
    "CVE-2022-48883",
    "CVE-2022-48884",
    "CVE-2022-48885",
    "CVE-2022-48886",
    "CVE-2022-48887",
    "CVE-2022-48888",
    "CVE-2022-48889",
    "CVE-2022-48890",
    "CVE-2022-48891",
    "CVE-2022-48893",
    "CVE-2022-48896",
    "CVE-2022-48898",
    "CVE-2022-48899",
    "CVE-2022-48903",
    "CVE-2022-48904",
    "CVE-2022-48905",
    "CVE-2022-48906",
    "CVE-2022-48907",
    "CVE-2022-48909",
    "CVE-2022-48910",
    "CVE-2022-48912",
    "CVE-2022-48913",
    "CVE-2022-48914",
    "CVE-2022-48915",
    "CVE-2022-48916",
    "CVE-2022-48917",
    "CVE-2022-48918",
    "CVE-2022-48919",
    "CVE-2022-48920",
    "CVE-2022-48921",
    "CVE-2022-48923",
    "CVE-2022-48924",
    "CVE-2022-48925",
    "CVE-2022-48926",
    "CVE-2022-48927",
    "CVE-2022-48928",
    "CVE-2022-48929",
    "CVE-2022-48930",
    "CVE-2022-48931",
    "CVE-2022-48932",
    "CVE-2022-48934",
    "CVE-2022-48937",
    "CVE-2022-48938",
    "CVE-2022-48939",
    "CVE-2022-48940",
    "CVE-2022-48941",
    "CVE-2022-48942",
    "CVE-2022-48943",
    "CVE-2023-3610",
    "CVE-2023-52458",
    "CVE-2023-52489",
    "CVE-2023-52498",
    "CVE-2023-52581",
    "CVE-2023-52859",
    "CVE-2023-52887",
    "CVE-2023-52889",
    "CVE-2023-52893",
    "CVE-2023-52894",
    "CVE-2023-52896",
    "CVE-2023-52898",
    "CVE-2023-52899",
    "CVE-2023-52900",
    "CVE-2023-52901",
    "CVE-2023-52904",
    "CVE-2023-52905",
    "CVE-2023-52906",
    "CVE-2023-52907",
    "CVE-2023-52908",
    "CVE-2023-52909",
    "CVE-2023-52910",
    "CVE-2023-52911",
    "CVE-2023-52912",
    "CVE-2023-52913",
    "CVE-2024-26631",
    "CVE-2024-26668",
    "CVE-2024-26669",
    "CVE-2024-26677",
    "CVE-2024-26735",
    "CVE-2024-26808",
    "CVE-2024-26812",
    "CVE-2024-26835",
    "CVE-2024-26851",
    "CVE-2024-27010",
    "CVE-2024-27011",
    "CVE-2024-27016",
    "CVE-2024-27024",
    "CVE-2024-27079",
    "CVE-2024-27403",
    "CVE-2024-31076",
    "CVE-2024-35897",
    "CVE-2024-35902",
    "CVE-2024-35945",
    "CVE-2024-35971",
    "CVE-2024-36009",
    "CVE-2024-36013",
    "CVE-2024-36270",
    "CVE-2024-36286",
    "CVE-2024-36489",
    "CVE-2024-36929",
    "CVE-2024-36933",
    "CVE-2024-36936",
    "CVE-2024-36962",
    "CVE-2024-38554",
    "CVE-2024-38602",
    "CVE-2024-38662",
    "CVE-2024-39489",
    "CVE-2024-40905",
    "CVE-2024-40978",
    "CVE-2024-40980",
    "CVE-2024-40995",
    "CVE-2024-41000",
    "CVE-2024-41007",
    "CVE-2024-41009",
    "CVE-2024-41011",
    "CVE-2024-41016",
    "CVE-2024-41020",
    "CVE-2024-41022",
    "CVE-2024-41035",
    "CVE-2024-41036",
    "CVE-2024-41038",
    "CVE-2024-41039",
    "CVE-2024-41042",
    "CVE-2024-41045",
    "CVE-2024-41056",
    "CVE-2024-41060",
    "CVE-2024-41062",
    "CVE-2024-41065",
    "CVE-2024-41068",
    "CVE-2024-41073",
    "CVE-2024-41079",
    "CVE-2024-41080",
    "CVE-2024-41087",
    "CVE-2024-41088",
    "CVE-2024-41089",
    "CVE-2024-41092",
    "CVE-2024-41093",
    "CVE-2024-41095",
    "CVE-2024-41097",
    "CVE-2024-41098",
    "CVE-2024-42069",
    "CVE-2024-42074",
    "CVE-2024-42076",
    "CVE-2024-42077",
    "CVE-2024-42080",
    "CVE-2024-42082",
    "CVE-2024-42085",
    "CVE-2024-42086",
    "CVE-2024-42087",
    "CVE-2024-42089",
    "CVE-2024-42090",
    "CVE-2024-42092",
    "CVE-2024-42095",
    "CVE-2024-42097",
    "CVE-2024-42098",
    "CVE-2024-42101",
    "CVE-2024-42104",
    "CVE-2024-42106",
    "CVE-2024-42107",
    "CVE-2024-42110",
    "CVE-2024-42114",
    "CVE-2024-42115",
    "CVE-2024-42119",
    "CVE-2024-42120",
    "CVE-2024-42121",
    "CVE-2024-42126",
    "CVE-2024-42127",
    "CVE-2024-42130",
    "CVE-2024-42137",
    "CVE-2024-42139",
    "CVE-2024-42142",
    "CVE-2024-42143",
    "CVE-2024-42148",
    "CVE-2024-42152",
    "CVE-2024-42155",
    "CVE-2024-42156",
    "CVE-2024-42157",
    "CVE-2024-42158",
    "CVE-2024-42162",
    "CVE-2024-42223",
    "CVE-2024-42225",
    "CVE-2024-42228",
    "CVE-2024-42229",
    "CVE-2024-42230",
    "CVE-2024-42232",
    "CVE-2024-42236",
    "CVE-2024-42237",
    "CVE-2024-42238",
    "CVE-2024-42239",
    "CVE-2024-42240",
    "CVE-2024-42244",
    "CVE-2024-42246",
    "CVE-2024-42247",
    "CVE-2024-42268",
    "CVE-2024-42271",
    "CVE-2024-42274",
    "CVE-2024-42276",
    "CVE-2024-42277",
    "CVE-2024-42280",
    "CVE-2024-42281",
    "CVE-2024-42283",
    "CVE-2024-42284",
    "CVE-2024-42285",
    "CVE-2024-42286",
    "CVE-2024-42287",
    "CVE-2024-42288",
    "CVE-2024-42289",
    "CVE-2024-42291",
    "CVE-2024-42292",
    "CVE-2024-42295",
    "CVE-2024-42301",
    "CVE-2024-42302",
    "CVE-2024-42308",
    "CVE-2024-42309",
    "CVE-2024-42310",
    "CVE-2024-42311",
    "CVE-2024-42312",
    "CVE-2024-42313",
    "CVE-2024-42315",
    "CVE-2024-42318",
    "CVE-2024-42319",
    "CVE-2024-42320",
    "CVE-2024-42322",
    "CVE-2024-43816",
    "CVE-2024-43818",
    "CVE-2024-43819",
    "CVE-2024-43821",
    "CVE-2024-43823",
    "CVE-2024-43829",
    "CVE-2024-43830",
    "CVE-2024-43831",
    "CVE-2024-43834",
    "CVE-2024-43837",
    "CVE-2024-43839",
    "CVE-2024-43841",
    "CVE-2024-43842",
    "CVE-2024-43846",
    "CVE-2024-43849",
    "CVE-2024-43853",
    "CVE-2024-43854",
    "CVE-2024-43856",
    "CVE-2024-43858",
    "CVE-2024-43860",
    "CVE-2024-43861",
    "CVE-2024-43863",
    "CVE-2024-43866",
    "CVE-2024-43867",
    "CVE-2024-43871",
    "CVE-2024-43872",
    "CVE-2024-43873",
    "CVE-2024-43879",
    "CVE-2024-43880",
    "CVE-2024-43882",
    "CVE-2024-43883",
    "CVE-2024-43884",
    "CVE-2024-43889",
    "CVE-2024-43892",
    "CVE-2024-43893",
    "CVE-2024-43894",
    "CVE-2024-43895",
    "CVE-2024-43899",
    "CVE-2024-43900",
    "CVE-2024-43902",
    "CVE-2024-43903",
    "CVE-2024-43904",
    "CVE-2024-43905",
    "CVE-2024-43907",
    "CVE-2024-43908",
    "CVE-2024-43909",
    "CVE-2024-44938",
    "CVE-2024-44939",
    "CVE-2024-44947"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3483-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2024:3483-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:3483-1 advisory.

    The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2024-44947: Initialize beyond-EOF page contents before setting uptodate (bsc#1229454).
    - CVE-2024-36936: Touch soft lockup during memory accept (bsc#1225773).
    - CVE-2022-48706: Do proper cleanup if IFCVF init fails (bsc#1225524).
    - CVE-2024-43883: Do not drop references before new references are gained (bsc#1229707).
    - CVE-2024-41062: Sync sock recv cb and release (bsc#1228576).
    - CVE-2024-43861: Fix memory leak for not ip packets (bsc#1229500).
    - CVE-2024-36270: Fix reference in patches.suse/netfilter-tproxy-bail-out-if-IP-has-been-disabled-on.patch
    (bsc#1226798)
    - CVE-2023-52489: Fix race in accessing memory_section->usage (bsc#1221326).
    - CVE-2024-43893: Check uartclk for zero to avoid divide by zero (bsc#1229759).
    - CVE-2024-43821: Fix a possible null pointer dereference (bsc#1229315).
    - CVE-2024-43900: Avoid use-after-free in load_firmware_cb() (bsc#1229756).
    - CVE-2024-44938: Fix shift-out-of-bounds in dbDiscardAG (bsc#1229792).
    - CVE-2024-44939: Fix null ptr deref in dtInsertEntry (bsc#1229820).
    - CVE-2024-41087: Fix double free on error (CVE-2024-41087,bsc#1228466).
    - CVE-2024-42277: Avoid NULL deref in sprd_iommu_hw_en (bsc#1229409).
    - CVE-2024-43902: Add null checker before passing variables (bsc#1229767).
    - CVE-2024-43904: Add null checks for 'stream' and 'plane' before dereferencing (bsc#1229768)
    - CVE-2024-43880: Put back removed metod in struct objagg_ops (bsc#1229481).
    - CVE-2024-43884: Add error handling to pair_device() (bsc#1229739)
    - CVE-2024-43899: Fix null pointer deref in dcn20_resource.c (bsc#1229754).
    - CVE-2022-48920: Get rid of warning on transaction commit when using flushoncommit (bsc#1229658).
    - CVE-2023-52906: Fix warning during failed attribute validation (bsc#1229527).
    - CVE-2024-43882: Fixed ToCToU between perm check and set-uid/gid usage. (bsc#1229503)
    - CVE-2024-43866: Always drain health in shutdown callback (bsc#1229495).
    - CVE-2024-26812: Struct virqfd kABI workaround (bsc#1222808).
    - CVE-2022-48912: Fix use-after-free in __nf_register_net_hook() (bsc#1229641)
    - CVE-2024-27010: Fix mirred deadlock on device recursion (bsc#1223720).
    - CVE-2022-48906: Correctly set DATA_FIN timeout when number of retransmits is large (bsc#1229605)
    - CVE-2024-42155: Wipe copies of protected- and secure-keys (bsc#1228733).
    - CVE-2024-42156: Wipe copies of clear-key structures on failure (bsc#1228722).
    - CVE-2023-52899: Add exception protection processing for vd in axi_chan_handle_err function
    (bsc#1229569).
    - CVE-2024-42158: Use kfree_sensitive() to fix Coccinelle warnings (bsc#1228720).
    - CVE-2024-26631: Fix data-race in ipv6_mc_down / mld_ifc_work (bsc#1221630).
    - CVE-2024-43873: Always initialize seqpacket_allow (bsc#1229488)
    - CVE-2024-40905: Fix possible race in __fib6_drop_pcpu_from() (bsc#1227761)
    - CVE-2024-39489: Fix memleak in seg6_hmac_init_algo (bsc#1227623)
    - CVE-2021-47106: Fix use-after-free in nft_set_catchall_destroy() (bsc#1220962)
    - CVE-2021-47517: Fix panic when interrupt coaleceing is set via ethtool (bsc#1225428).
    - CVE-2024-36489: Fix missing memory barrier in tls_init (bsc#1226874)
    - CVE-2024-41020: Fix fcntl/close race recovery compat path (bsc#1228427).
    - CVE-2024-27079: Fix NULL domain on device release (bsc#1223742).
    - CVE-2024-35897: Discard table flag update with pending basechain deletion (bsc#1224510).
    - CVE-2024-27403: Restore const specifier in flow_offload_route_init() (bsc#1224415).
    - CVE-2024-27011: Fix memleak in map from abort path (bsc#1223803).
    - CVE-2024-43819: Reject memory region operations for ucontrol VMs (bsc#1229290 git-fixes).
    - CVE-2024-26668: Reject configurations that cause integer overflow (bsc#1222335).
    - CVE-2024-26835: Set dormant flag on hook register failure (bsc#1222967).
    - CVE-2024-26808: Handle NETDEV_UNREGISTER for inet/ingress basechain (bsc#1222634).
    - CVE-2024-27016: Validate pppoe header (bsc#1223807).
    - CVE-2024-35945: Prevent nullptr exceptions on ISR (bsc#1224639).
    - CVE-2023-52581: Fix memleak when more than 255 elements expired (bsc#1220877).
    - CVE-2024-36013: Fix slab-use-after-free in l2cap_connect() (bsc#1225578).
    - CVE-2024-43837: Fix updating attached freplace prog in prog_array map (bsc#1229297).
    - CVE-2024-42291: Add a per-VF limit on number of FDIR filters (bsc#1229374).
    - CVE-2024-42268: Fix missing lock on sync reset reload (bsc#1229391).
    - CVE-2024-43834: Fix invalid wait context of page_pool_destroy() (bsc#1229314)
    - CVE-2024-36286: Acquire rcu_read_lock() in instance_destroy_rcu() (bsc#1226801)
    - CVE-2024-26851: Add protection for bmp length out of range (bsc#1223074)
    - CVE-2024-42157: Wipe sensitive data on failure (bsc#1228727 CVE-2024-42157 git-fixes).
    - CVE-2024-26677: Blacklist e7870cf13d20 (' Fix delayed ACKs to not set the reference serial number')
    (bsc#1222387)
    - CVE-2024-36009: Blacklist 467324bcfe1a ('ax25: Fix netdev refcount issue') (bsc#1224542)
    - CVE-2023-52859: Fix use-after-free when register pmu fails (bsc#1225582).
    - CVE-2024-42280: Fix a use after free in hfcmulti_tx() (bsc#1229388)
    - CVE-2024-42284: Return non-zero value from tipc_udp_addr2str() on error (bsc#1229382)
    - CVE-2024-42283: Initialize all fields in dumped nexthops (bsc#1229383)
    - CVE-2024-42312: Always initialize i_uid/i_gid (bsc#1229357)
    - CVE-2024-43854: Initialize integrity buffer to zero before writing it to media (bsc#1229345)
    - CVE-2024-42322: Properly dereference pe in ip_vs_add_service (bsc#1229347)
    - CVE-2024-42308: Update DRM patch reference (bsc#1229411)
    - CVE-2024-42301: Fix the array out-of-bounds risk (bsc#1229407).
    - CVE-2024-42318: Do not lose track of restrictions on cred_transfer (bsc#1229351).
    - CVE-2024-26669: Fix chain template offload (bsc#1222350).
    - CVE-2023-52889: Fix null pointer deref when receiving skb during sock creation (bsc#1229287,).
    - CVE-2022-48645: Move enetc_set_psfp() out of the common enetc_set_features() (bsc#1223508).
    - CVE-2024-41007: Use signed arithmetic in tcp_rtx_probe0_timed_out() (bsc#1227863).
    - CVE-2024-36933: Use correct mac_offset to unwind gso skb in nsh_gso_segment() (bsc#1225832).
    - CVE-2024-42295: Handle inconsistent state in nilfs_btnode_create_block() (bsc#1229370).
    - CVE-2024-42319: Move devm_mbox_controller_register() after devm_pm_runtime_enable() (bsc#1229350).
    - CVE-2024-43860: Skip over memory region when node value is NULL (bsc#1229319).
    - CVE-2024-43831: Handle invalid decoder vsi (bsc#1229309).
    - CVE-2024-43849: Protect locator_addr with the main mutex (bsc#1229307).
    - CVE-2024-43841: Do not use strlen() in const context (bsc#1229304).
    - CVE-2024-43839: Adjust 'name' buf size of bna_tcb and bna_ccb structures (bsc#1229301).
    - CVE-2024-41088: Fix infinite loop when xmit fails (bsc#1228469).
    - CVE-2024-42281: Fix a segment issue when downgrading gso_size (bsc#1229386).
    - CVE-2024-42271: Fixed a use after free in iucv_sock_close(). (bsc#1229400)
    - CVE-2024-41080: Fix possible deadlock in io_register_iowq_max_workers() (bsc#1228616).
    - CVE-2024-42246: Remap EPERM in case of connection failure in xs_tcp_setup_socket (bsc#1228989).
    - CVE-2024-42232: Fixed a race between delayed_work() and ceph_monc_stop(). (bsc#1228959)
    - CVE-2024-26735: Fix possible use-after-free and null-ptr-deref (bsc#1222372).
    - CVE-2024-42106: Initialize pad field in struct inet_diag_req_v2 (bsc#1228493).
    - CVE-2024-38662: Cover verifier checks for mutating sockmap/sockhash (bsc#1226885).
    - CVE-2024-42110: Move ntb_netdev_rx_handler() to call netif_rx() from __netif_rx() (bsc#1228501).
    - CVE-2024-42247: Avoid unaligned 64-bit memory accesses (bsc#1228988).
    - CVE-2022-48865: Fix kernel panic when enabling bearer (bsc#1228065).
    - CVE-2023-52498: Fix possible deadlocks in core system-wide PM code (bsc#1221269).
    - CVE-2024-41068: Fix sclp_init() cleanup on failure (bsc#1228579).
    - CVE-2022-48808: Fix panic when DSA master device unbinds on shutdown (bsc#1227958).
    - CVE-2024-42095: Fix Errata i2310 with RX FIFO level check (bsc#1228446).
    - CVE-2024-40978: Fix crash while reading debugfs attribute (bsc#1227929).
    - CVE-2024-42107: Do not process extts if PTP is disabled (bsc#1228494).
    - CVE-2024-42139: Fix improper extts handling (bsc#1228503).
    - CVE-2024-42148: Fix multiple UBSAN array-index-out-of-bounds (bsc#1228487).
    - CVE-2024-42142: E-switch, Create ingress ACL when needed (bsc#1228491).
    - CVE-2024-42162: Account for stopped queues when reading NIC stats (bsc#1228706).
    - CVE-2024-42082: Remove WARN() from __xdp_reg_mem_model() (bsc#1228482).
    - CVE-2024-41042: Prefer nft_chain_validate (bsc#1228526).
    - CVE-2023-3610: Fixed use-after-free vulnerability in nf_tables can be exploited to achieve local
    privilege escalation (bsc#1213580).
    - CVE-2024-42228: Using uninitialized value *size when calling amdgpu_vce_cs_reloc (bsc#1228667).
    - CVE-2024-40995: Fix possible infinite loop in tcf_idr_check_alloc() (bsc#1227830).
    - CVE-2024-38602: Merge repeat codes in ax25_dev_device_down() (git-fixes CVE-2024-38602 bsc#1226613).
    - CVE-2024-38554: Fix reference count leak issue of net_device (bsc#1226742).
    - CVE-2024-36929: Reject skb_copy(_expand) for fraglist GSO skbs (bsc#1225814).
    - CVE-2024-41009: Fix overrunning reservations in ringbuf (bsc#1228020).
    - CVE-2024-27024: Fix WARNING in rds_conn_connect_if_down (bsc#1223777).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196261");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225352");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229359");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229370");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229603");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230413");
  # https://lists.suse.com/pipermail/sle-updates/2024-September/037089.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80b4718d");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4204");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4441");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47106");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47517");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0500");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23222");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38457");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40133");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4382");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48706");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48808");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48869");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48888");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48913");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52458");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52489");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52498");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52913");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26677");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26808");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27403");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-31076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35971");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36286");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36489");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38554");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39489");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40980");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41022");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41035");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41036");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41038");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41039");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41060");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41065");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41080");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41087");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41088");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41092");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41093");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42069");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42080");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42086");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42087");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42092");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42101");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42106");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42107");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42110");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42115");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42119");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42120");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42121");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42126");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42127");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42130");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42137");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42139");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42143");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42152");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42223");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42225");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42228");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42230");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42232");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42236");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42237");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42238");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42239");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42240");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42246");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42247");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42268");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42271");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42274");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42276");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42277");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42283");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42284");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42286");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42287");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42291");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42295");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42302");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42308");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42309");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42310");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42311");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42313");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42315");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42318");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42319");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42320");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42322");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43818");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43830");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43831");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43839");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43892");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44947");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23222");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-43900");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150500_55_80-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
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
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-64kb-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.80.2.150500.6.35.6', 'sp':'5', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.80.2.150500.6.35.6', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.80.2.150500.6.35.6', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.80.2.150500.6.35.6', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-extra-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-extra-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.80.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.80.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.80.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.80.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'reiserfs-kmp-default-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.80.2.150500.6.35.6', 'sp':'5', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.80.2.150500.6.35.6', 'sp':'5', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.80.2.150500.6.35.6', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.80.2.150500.6.35.6', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.80.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.80.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.80.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.80.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'reiserfs-kmp-default-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-legacy-release-15.5', 'sles-release-15.5']},
    {'reference':'cluster-md-kmp-64kb-5.14.21-150500.55.80.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-64kb-5.14.21-150500.55.80.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-allwinner-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-altera-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-amazon-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-amd-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-amlogic-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-apm-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-apple-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-arm-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-broadcom-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-cavium-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-exynos-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-freescale-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-hisilicon-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-lg-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-marvell-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-mediatek-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-nvidia-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-qcom-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-renesas-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-rockchip-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-socionext-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-sprd-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-xilinx-5.14.21-150500.55.80.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-64kb-5.14.21-150500.55.80.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.80.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.80.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-64kb-extra-5.14.21-150500.55.80.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-64kb-livepatch-devel-5.14.21-150500.55.80.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-64kb-optional-5.14.21-150500.55.80.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-debug-5.14.21-150500.55.80.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-debug-devel-5.14.21-150500.55.80.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-debug-livepatch-devel-5.14.21-150500.55.80.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-debug-vdso-5.14.21-150500.55.80.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.80.2.150500.6.35.6', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.80.2.150500.6.35.6', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-base-rebuild-5.14.21-150500.55.80.2.150500.6.35.6', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-base-rebuild-5.14.21-150500.55.80.2.150500.6.35.6', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-extra-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-livepatch-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-livepatch-devel-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-optional-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-vdso-5.14.21-150500.55.80.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-kvmsmall-5.14.21-150500.55.80.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-kvmsmall-5.14.21-150500.55.80.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-kvmsmall-devel-5.14.21-150500.55.80.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-kvmsmall-devel-5.14.21-150500.55.80.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-kvmsmall-livepatch-devel-5.14.21-150500.55.80.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-kvmsmall-livepatch-devel-5.14.21-150500.55.80.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-kvmsmall-vdso-5.14.21-150500.55.80.2', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.80.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-obs-qa-5.14.21-150500.55.80.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-source-vanilla-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.80.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.80.2', 'cpu':'s390x', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-64kb-5.14.21-150500.55.80.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-default-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-64kb-5.14.21-150500.55.80.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-64kb-5.14.21-150500.55.80.2', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-default-5.14.21-150500.55.80.2', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.5']},
    {'reference':'kernel-default-livepatch-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']},
    {'reference':'kernel-default-livepatch-devel-5.14.21-150500.55.80.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']},
    {'reference':'kernel-livepatch-5_14_21-150500_55_80-default-1-150500.11.3.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']},
    {'reference':'kernel-default-extra-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-extra-5.14.21-150500.55.80.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.5', 'sled-release-15.5', 'sles-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-64kb / cluster-md-kmp-default / dlm-kmp-64kb / etc');
}
