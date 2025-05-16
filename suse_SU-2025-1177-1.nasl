#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1177-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(234057);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id(
    "CVE-2023-52831",
    "CVE-2023-52926",
    "CVE-2023-52927",
    "CVE-2024-26634",
    "CVE-2024-26873",
    "CVE-2024-35826",
    "CVE-2024-35910",
    "CVE-2024-38606",
    "CVE-2024-41005",
    "CVE-2024-41077",
    "CVE-2024-41149",
    "CVE-2024-42307",
    "CVE-2024-43820",
    "CVE-2024-46736",
    "CVE-2024-46782",
    "CVE-2024-46796",
    "CVE-2024-47408",
    "CVE-2024-47794",
    "CVE-2024-49571",
    "CVE-2024-49924",
    "CVE-2024-49940",
    "CVE-2024-49994",
    "CVE-2024-50056",
    "CVE-2024-50126",
    "CVE-2024-50140",
    "CVE-2024-50152",
    "CVE-2024-50290",
    "CVE-2024-52559",
    "CVE-2024-53057",
    "CVE-2024-53063",
    "CVE-2024-53140",
    "CVE-2024-53163",
    "CVE-2024-53680",
    "CVE-2024-54683",
    "CVE-2024-56638",
    "CVE-2024-56640",
    "CVE-2024-56702",
    "CVE-2024-56703",
    "CVE-2024-56718",
    "CVE-2024-56719",
    "CVE-2024-56751",
    "CVE-2024-56758",
    "CVE-2024-56770",
    "CVE-2024-57807",
    "CVE-2024-57834",
    "CVE-2024-57900",
    "CVE-2024-57947",
    "CVE-2024-57973",
    "CVE-2024-57974",
    "CVE-2024-57978",
    "CVE-2024-57980",
    "CVE-2024-57981",
    "CVE-2024-57986",
    "CVE-2024-57990",
    "CVE-2024-57993",
    "CVE-2024-57996",
    "CVE-2024-57997",
    "CVE-2024-57999",
    "CVE-2024-58002",
    "CVE-2024-58005",
    "CVE-2024-58006",
    "CVE-2024-58007",
    "CVE-2024-58009",
    "CVE-2024-58011",
    "CVE-2024-58012",
    "CVE-2024-58013",
    "CVE-2024-58014",
    "CVE-2024-58017",
    "CVE-2024-58019",
    "CVE-2024-58020",
    "CVE-2024-58034",
    "CVE-2024-58051",
    "CVE-2024-58052",
    "CVE-2024-58054",
    "CVE-2024-58055",
    "CVE-2024-58056",
    "CVE-2024-58057",
    "CVE-2024-58058",
    "CVE-2024-58061",
    "CVE-2024-58063",
    "CVE-2024-58069",
    "CVE-2024-58072",
    "CVE-2024-58076",
    "CVE-2024-58078",
    "CVE-2024-58079",
    "CVE-2024-58080",
    "CVE-2024-58083",
    "CVE-2024-58085",
    "CVE-2024-58086",
    "CVE-2025-21631",
    "CVE-2025-21635",
    "CVE-2025-21659",
    "CVE-2025-21671",
    "CVE-2025-21693",
    "CVE-2025-21701",
    "CVE-2025-21703",
    "CVE-2025-21704",
    "CVE-2025-21706",
    "CVE-2025-21708",
    "CVE-2025-21711",
    "CVE-2025-21714",
    "CVE-2025-21718",
    "CVE-2025-21723",
    "CVE-2025-21726",
    "CVE-2025-21727",
    "CVE-2025-21731",
    "CVE-2025-21732",
    "CVE-2025-21734",
    "CVE-2025-21735",
    "CVE-2025-21736",
    "CVE-2025-21738",
    "CVE-2025-21739",
    "CVE-2025-21741",
    "CVE-2025-21742",
    "CVE-2025-21743",
    "CVE-2025-21744",
    "CVE-2025-21745",
    "CVE-2025-21749",
    "CVE-2025-21750",
    "CVE-2025-21753",
    "CVE-2025-21756",
    "CVE-2025-21759",
    "CVE-2025-21760",
    "CVE-2025-21761",
    "CVE-2025-21762",
    "CVE-2025-21763",
    "CVE-2025-21764",
    "CVE-2025-21765",
    "CVE-2025-21766",
    "CVE-2025-21772",
    "CVE-2025-21773",
    "CVE-2025-21775",
    "CVE-2025-21776",
    "CVE-2025-21779",
    "CVE-2025-21780",
    "CVE-2025-21781",
    "CVE-2025-21782",
    "CVE-2025-21784",
    "CVE-2025-21785",
    "CVE-2025-21791",
    "CVE-2025-21793",
    "CVE-2025-21794",
    "CVE-2025-21796",
    "CVE-2025-21804",
    "CVE-2025-21810",
    "CVE-2025-21815",
    "CVE-2025-21819",
    "CVE-2025-21820",
    "CVE-2025-21821",
    "CVE-2025-21823",
    "CVE-2025-21825",
    "CVE-2025-21828",
    "CVE-2025-21829",
    "CVE-2025-21830",
    "CVE-2025-21831",
    "CVE-2025-21832",
    "CVE-2025-21835",
    "CVE-2025-21838",
    "CVE-2025-21844",
    "CVE-2025-21846",
    "CVE-2025-21847",
    "CVE-2025-21848",
    "CVE-2025-21850",
    "CVE-2025-21855",
    "CVE-2025-21856",
    "CVE-2025-21857",
    "CVE-2025-21858",
    "CVE-2025-21859",
    "CVE-2025-21861",
    "CVE-2025-21862",
    "CVE-2025-21864",
    "CVE-2025-21865",
    "CVE-2025-21866",
    "CVE-2025-21869",
    "CVE-2025-21870",
    "CVE-2025-21871",
    "CVE-2025-21876",
    "CVE-2025-21877",
    "CVE-2025-21878",
    "CVE-2025-21883",
    "CVE-2025-21885",
    "CVE-2025-21886",
    "CVE-2025-21888",
    "CVE-2025-21890",
    "CVE-2025-21891",
    "CVE-2025-21892"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1177-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2025:1177-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2025:1177-1 advisory.

    The SUSE Linux Enterprise 15 SP6 Azure kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2023-52927: netfilter: allow exp not to be removed in nf_ct_find_expectation (bsc#1239644).
    - CVE-2024-35910: tcp: properly terminate timers for kernel sockets (bsc#1224489).
    - CVE-2024-41005: netpoll: Fix race condition in netpoll_owner_active (bsc#1227858).
    - CVE-2024-46782: ila: call nf_unregister_net_hooks() sooner (bsc#1230769).
    - CVE-2024-47408: net/smc: check smcd_v2_ext_offset when receiving proposal msg (bsc#1235711).
    - CVE-2024-47794: kABI: bpf: Prevent tailcall infinite loop caused by freplace kABI workaround
    (bsc#1235712).
    - CVE-2024-49571: net/smc: check iparea_offset and ipv6_prefixes_cnt when receiving proposal msg
    (bsc#1235733).
    - CVE-2024-49940: kABI fix for l2tp: prevent possible tunnel refcount underflow (bsc#1232812).
    - CVE-2024-50056: usb: gadget: uvc: Fix ERR_PTR dereference in uvc_v4l2.c (bsc#1232389).
    - CVE-2024-50140: net: sched: use RCU read-side critical section in taprio_dump() (bsc#1233060).
    - CVE-2024-53057: net/sched: stop qdisc_tree_reduce_backlog on TC_H_ROOT (bsc#1233551).
    - CVE-2024-53140: netlink: terminate outstanding dump on socket close (bsc#1234222).
    - CVE-2024-53680: ipvs: fix UB due to uninitialized stack access in ip_vs_protocol_init() (bsc#1235715).
    - CVE-2024-54683: netfilter: IDLETIMER: Fix for possible ABBA deadlock (bsc#1235729).
    - CVE-2024-56638: kABI fix for 'netfilter: nft_inner: incorrect percpu area handling under softirq'
    (bsc#1235524).
    - CVE-2024-56640: net/smc: fix LGR and link use-after-free issue (bsc#1235436).
    - CVE-2024-56702: bpf: Add tracepoints with null-able arguments (bsc#1235501).
    - CVE-2024-56703: ipv6: Fix soft lockups in fib6_select_path under high next hop churn (bsc#1235455).
    - CVE-2024-56718: net/smc: protect link down work from execute after lgr freed (bsc#1235589).
    - CVE-2024-56719: net: stmmac: fix TSO DMA API usage causing oops (bsc#1235591).
    - CVE-2024-56751: ipv6: release nexthop on device removal (bsc#1234936).
    - CVE-2024-56758: btrfs: check folio mapping after unlock in relocate_one_folio() (bsc#1235621).
    - CVE-2024-56770: net/sched: netem: account for backlog updates from child qdisc (bsc#1235637).
    - CVE-2024-57900: ila: serialize calls to nf_register_net_hooks() (bsc#1235973).
    - CVE-2024-57947: netfilter: nf_set_pipapo: fix initial map fill (bsc#1236333).
    - CVE-2024-57974: udp: Deal with race between UDP socket address change and rehash (bsc#1238532).
    - CVE-2024-57996: net_sched: sch_sfq: do not allow 1 packet limit (bsc#1239076).
    - CVE-2024-58012: ASoC: SOF: Intel: hda-dai: Ensure DAI widget is valid during params (bsc#1239104).
    - CVE-2024-58019: nvkm/gsp: correctly advance the read pointer of GSP message queue (bsc#1238997).
    - CVE-2024-58083: KVM: Explicitly verify target vCPU is online in kvm_get_vcpu() (bsc#1239036).
    - CVE-2025-21635: rds: sysctl: rds_tcp_{rcv,snd}buf: avoid using current->nsproxy (bsc#1236111).
    - CVE-2025-21659: netdev: prevent accessing NAPI instances from another namespace (bsc#1236206).
    - CVE-2025-21693: mm: zswap: properly synchronize freeing resources during CPU hotunplug (bsc#1237029).
    - CVE-2025-21701: net: avoid race between device unregistration and ethnl ops (bsc#1237164).
    - CVE-2025-21703: netem: Update sch->q.qlen before qdisc_tree_reduce_backlog() (bsc#1237313).
    - CVE-2025-21706: mptcp: pm: only set fullmesh for subflow endp (bsc#1238528).
    - CVE-2025-21739: kABI: ufshcd: add ufshcd_dealloc_host back (bsc#1238506).
    - CVE-2025-21753: btrfs: fix use-after-free when attempting to join an aborted transaction (bsc#1237875).
    - CVE-2025-21759: ipv6: mcast: extend RCU protection in igmp6_send() (bsc#1238738).
    - CVE-2025-21760: ndisc: extend RCU protection in ndisc_send_skb() (bsc#1238763).
    - CVE-2025-21761: openvswitch: use RCU protection in ovs_vport_cmd_fill_info() (bsc#1238775).
    - CVE-2025-21762: arp: use RCU protection in arp_xmit() (bsc#1238780).
    - CVE-2025-21763: neighbour: use RCU protection in __neigh_notify() (bsc#1237897).
    - CVE-2025-21765: ipv6: use RCU protection in ip6_default_advmss() (bsc#1237906).
    - CVE-2025-21766: ipv4: use RCU protection in __ip_rt_update_pmtu() (bsc#1238754).
    - CVE-2025-21791: vrf: use RCU protection in l3mdev_l3_out() (bsc#1238512).
    - CVE-2025-21825: selftests/bpf: Add test case for the freeing of bpf_timer (bsc#1238971).
    - CVE-2025-21844: smb: client: Add check for next_buffer in receive_encrypted_standard() (bsc#1239512).
    - CVE-2025-21848: nfp: bpf: Add check for nfp_app_ctrl_msg_alloc() (bsc#1239479).
    - CVE-2025-21856: s390/ism: add release function for struct device (bsc#1239486).
    - CVE-2025-21857: net/sched: cls_api: fix error handling causing NULL dereference (bsc#1239478).
    - CVE-2025-21861: mm/migrate_device: do not add folio to be freed to LRU in migrate_device_finalize()
    (bsc#1239483).
    - CVE-2025-21862: drop_monitor: fix incorrect initialization order (bsc#1239474).
    - CVE-2025-21864: kABI fix for tcp: drop secpath at the same time as we currently drop (bsc#1239482).
    - CVE-2025-21865: gtp: Suppress list corruption splat in gtp_net_exit_batch_rtnl() (bsc#1239481).
    - CVE-2025-21870: ASoC: SOF: ipc4-topology: Harden loops for looking up ALH copiers (bsc#1240191).
    - CVE-2025-21871: tee: optee: Fix supplicant wait loop (bsc#1240183).
    - CVE-2025-21883: ice: Fix deinitializing VF in error path (bsc#1240189).
    - CVE-2025-21890: idpf: fix checksums set in idpf_rx_rsc() (bsc#1240173).
    - CVE-2025-21891: ipvlan: ensure network headers are in skb linear part (bsc#1240186).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229311");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232421");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233551");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240173");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240334");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-April/020670.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80764b58");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52831");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26634");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38606");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41149");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42307");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43820");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46736");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46782");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47408");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47794");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49994");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50126");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50140");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50152");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-52559");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53057");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53140");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53163");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-54683");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56638");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56718");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56719");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56758");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56770");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57980");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57986");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57993");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58034");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58052");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58054");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58057");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58069");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58072");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58080");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58083");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58086");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21706");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21711");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21714");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21718");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21726");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21727");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21731");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21734");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21736");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21738");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21741");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21745");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21749");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21750");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21761");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21762");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21765");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21776");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21779");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21781");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21782");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21785");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21793");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21794");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21820");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21825");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21830");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21831");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21832");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21844");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21869");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21876");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21888");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21892");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21858");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/09");

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

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-azure-6.4.0-150600.8.34.2', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.34.2', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.34.2', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.34.2', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-devel-azure-6.4.0-150600.8.34.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-source-azure-6.4.0-150600.8.34.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.34.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.34.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.34.2', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.34.2', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.34.2', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.34.2', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-devel-azure-6.4.0-150600.8.34.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-source-azure-6.4.0-150600.8.34.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.34.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.34.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-public-cloud-release-15.6', 'sles-release-15.6']},
    {'reference':'cluster-md-kmp-azure-6.4.0-150600.8.34.2', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'cluster-md-kmp-azure-6.4.0-150600.8.34.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dlm-kmp-azure-6.4.0-150600.8.34.2', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dlm-kmp-azure-6.4.0-150600.8.34.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'gfs2-kmp-azure-6.4.0-150600.8.34.2', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'gfs2-kmp-azure-6.4.0-150600.8.34.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.34.2', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-6.4.0-150600.8.34.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.34.2', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-devel-6.4.0-150600.8.34.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-extra-6.4.0-150600.8.34.2', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-extra-6.4.0-150600.8.34.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-optional-6.4.0-150600.8.34.2', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-optional-6.4.0-150600.8.34.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-azure-vdso-6.4.0-150600.8.34.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-devel-azure-6.4.0-150600.8.34.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-source-azure-6.4.0-150600.8.34.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.34.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-syms-azure-6.4.0-150600.8.34.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kselftests-kmp-azure-6.4.0-150600.8.34.2', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kselftests-kmp-azure-6.4.0-150600.8.34.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ocfs2-kmp-azure-6.4.0-150600.8.34.2', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ocfs2-kmp-azure-6.4.0-150600.8.34.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'reiserfs-kmp-azure-6.4.0-150600.8.34.2', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'reiserfs-kmp-azure-6.4.0-150600.8.34.2', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
