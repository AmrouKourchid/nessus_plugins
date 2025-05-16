#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4364-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(213129);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2021-47416",
    "CVE-2021-47534",
    "CVE-2021-47594",
    "CVE-2022-3435",
    "CVE-2022-45934",
    "CVE-2022-48664",
    "CVE-2022-48674",
    "CVE-2022-48879",
    "CVE-2022-48946",
    "CVE-2022-48947",
    "CVE-2022-48948",
    "CVE-2022-48949",
    "CVE-2022-48951",
    "CVE-2022-48953",
    "CVE-2022-48954",
    "CVE-2022-48955",
    "CVE-2022-48956",
    "CVE-2022-48957",
    "CVE-2022-48958",
    "CVE-2022-48959",
    "CVE-2022-48960",
    "CVE-2022-48961",
    "CVE-2022-48962",
    "CVE-2022-48966",
    "CVE-2022-48967",
    "CVE-2022-48968",
    "CVE-2022-48969",
    "CVE-2022-48970",
    "CVE-2022-48971",
    "CVE-2022-48972",
    "CVE-2022-48973",
    "CVE-2022-48975",
    "CVE-2022-48977",
    "CVE-2022-48978",
    "CVE-2022-48979",
    "CVE-2022-48980",
    "CVE-2022-48981",
    "CVE-2022-48982",
    "CVE-2022-48983",
    "CVE-2022-48985",
    "CVE-2022-48987",
    "CVE-2022-48988",
    "CVE-2022-48989",
    "CVE-2022-48990",
    "CVE-2022-48991",
    "CVE-2022-48992",
    "CVE-2022-48994",
    "CVE-2022-48995",
    "CVE-2022-48997",
    "CVE-2022-48999",
    "CVE-2022-49000",
    "CVE-2022-49002",
    "CVE-2022-49003",
    "CVE-2022-49005",
    "CVE-2022-49006",
    "CVE-2022-49007",
    "CVE-2022-49010",
    "CVE-2022-49011",
    "CVE-2022-49012",
    "CVE-2022-49014",
    "CVE-2022-49015",
    "CVE-2022-49016",
    "CVE-2022-49017",
    "CVE-2022-49019",
    "CVE-2022-49020",
    "CVE-2022-49021",
    "CVE-2022-49022",
    "CVE-2022-49023",
    "CVE-2022-49024",
    "CVE-2022-49025",
    "CVE-2022-49026",
    "CVE-2022-49027",
    "CVE-2022-49028",
    "CVE-2022-49029",
    "CVE-2022-49031",
    "CVE-2022-49032",
    "CVE-2023-2166",
    "CVE-2023-6270",
    "CVE-2023-28327",
    "CVE-2023-52766",
    "CVE-2023-52800",
    "CVE-2023-52881",
    "CVE-2023-52915",
    "CVE-2023-52917",
    "CVE-2023-52918",
    "CVE-2023-52919",
    "CVE-2023-52921",
    "CVE-2023-52922",
    "CVE-2024-26782",
    "CVE-2024-26906",
    "CVE-2024-26953",
    "CVE-2024-27043",
    "CVE-2024-35888",
    "CVE-2024-35937",
    "CVE-2024-35980",
    "CVE-2024-36244",
    "CVE-2024-36484",
    "CVE-2024-36883",
    "CVE-2024-36886",
    "CVE-2024-36905",
    "CVE-2024-36953",
    "CVE-2024-36954",
    "CVE-2024-36957",
    "CVE-2024-38577",
    "CVE-2024-38589",
    "CVE-2024-38615",
    "CVE-2024-39476",
    "CVE-2024-40965",
    "CVE-2024-40997",
    "CVE-2024-41016",
    "CVE-2024-41023",
    "CVE-2024-41049",
    "CVE-2024-42131",
    "CVE-2024-42145",
    "CVE-2024-42226",
    "CVE-2024-42253",
    "CVE-2024-43817",
    "CVE-2024-43897",
    "CVE-2024-44931",
    "CVE-2024-44932",
    "CVE-2024-44947",
    "CVE-2024-44958",
    "CVE-2024-44964",
    "CVE-2024-44995",
    "CVE-2024-45016",
    "CVE-2024-45025",
    "CVE-2024-46678",
    "CVE-2024-46681",
    "CVE-2024-46716",
    "CVE-2024-46719",
    "CVE-2024-46754",
    "CVE-2024-46770",
    "CVE-2024-46775",
    "CVE-2024-46777",
    "CVE-2024-46800",
    "CVE-2024-46802",
    "CVE-2024-46804",
    "CVE-2024-46805",
    "CVE-2024-46807",
    "CVE-2024-46809",
    "CVE-2024-46810",
    "CVE-2024-46811",
    "CVE-2024-46812",
    "CVE-2024-46813",
    "CVE-2024-46814",
    "CVE-2024-46815",
    "CVE-2024-46816",
    "CVE-2024-46817",
    "CVE-2024-46818",
    "CVE-2024-46819",
    "CVE-2024-46821",
    "CVE-2024-46826",
    "CVE-2024-46828",
    "CVE-2024-46834",
    "CVE-2024-46835",
    "CVE-2024-46840",
    "CVE-2024-46841",
    "CVE-2024-46842",
    "CVE-2024-46848",
    "CVE-2024-46849",
    "CVE-2024-46853",
    "CVE-2024-46854",
    "CVE-2024-46855",
    "CVE-2024-46857",
    "CVE-2024-46859",
    "CVE-2024-46864",
    "CVE-2024-46871",
    "CVE-2024-47660",
    "CVE-2024-47661",
    "CVE-2024-47663",
    "CVE-2024-47664",
    "CVE-2024-47665",
    "CVE-2024-47667",
    "CVE-2024-47668",
    "CVE-2024-47669",
    "CVE-2024-47670",
    "CVE-2024-47671",
    "CVE-2024-47672",
    "CVE-2024-47673",
    "CVE-2024-47674",
    "CVE-2024-47679",
    "CVE-2024-47682",
    "CVE-2024-47684",
    "CVE-2024-47685",
    "CVE-2024-47692",
    "CVE-2024-47693",
    "CVE-2024-47695",
    "CVE-2024-47696",
    "CVE-2024-47697",
    "CVE-2024-47698",
    "CVE-2024-47699",
    "CVE-2024-47701",
    "CVE-2024-47704",
    "CVE-2024-47705",
    "CVE-2024-47706",
    "CVE-2024-47707",
    "CVE-2024-47709",
    "CVE-2024-47710",
    "CVE-2024-47712",
    "CVE-2024-47713",
    "CVE-2024-47718",
    "CVE-2024-47720",
    "CVE-2024-47723",
    "CVE-2024-47727",
    "CVE-2024-47728",
    "CVE-2024-47730",
    "CVE-2024-47735",
    "CVE-2024-47737",
    "CVE-2024-47738",
    "CVE-2024-47739",
    "CVE-2024-47742",
    "CVE-2024-47745",
    "CVE-2024-47747",
    "CVE-2024-47748",
    "CVE-2024-47749",
    "CVE-2024-47756",
    "CVE-2024-47757",
    "CVE-2024-49850",
    "CVE-2024-49851",
    "CVE-2024-49852",
    "CVE-2024-49855",
    "CVE-2024-49858",
    "CVE-2024-49860",
    "CVE-2024-49861",
    "CVE-2024-49863",
    "CVE-2024-49866",
    "CVE-2024-49867",
    "CVE-2024-49868",
    "CVE-2024-49870",
    "CVE-2024-49871",
    "CVE-2024-49875",
    "CVE-2024-49877",
    "CVE-2024-49879",
    "CVE-2024-49881",
    "CVE-2024-49882",
    "CVE-2024-49883",
    "CVE-2024-49884",
    "CVE-2024-49886",
    "CVE-2024-49890",
    "CVE-2024-49891",
    "CVE-2024-49892",
    "CVE-2024-49894",
    "CVE-2024-49895",
    "CVE-2024-49896",
    "CVE-2024-49897",
    "CVE-2024-49899",
    "CVE-2024-49900",
    "CVE-2024-49901",
    "CVE-2024-49902",
    "CVE-2024-49903",
    "CVE-2024-49905",
    "CVE-2024-49906",
    "CVE-2024-49907",
    "CVE-2024-49908",
    "CVE-2024-49909",
    "CVE-2024-49911",
    "CVE-2024-49912",
    "CVE-2024-49913",
    "CVE-2024-49914",
    "CVE-2024-49917",
    "CVE-2024-49918",
    "CVE-2024-49919",
    "CVE-2024-49920",
    "CVE-2024-49921",
    "CVE-2024-49922",
    "CVE-2024-49923",
    "CVE-2024-49924",
    "CVE-2024-49925",
    "CVE-2024-49929",
    "CVE-2024-49930",
    "CVE-2024-49933",
    "CVE-2024-49934",
    "CVE-2024-49935",
    "CVE-2024-49936",
    "CVE-2024-49938",
    "CVE-2024-49939",
    "CVE-2024-49945",
    "CVE-2024-49946",
    "CVE-2024-49947",
    "CVE-2024-49949",
    "CVE-2024-49950",
    "CVE-2024-49954",
    "CVE-2024-49955",
    "CVE-2024-49957",
    "CVE-2024-49958",
    "CVE-2024-49959",
    "CVE-2024-49960",
    "CVE-2024-49962",
    "CVE-2024-49963",
    "CVE-2024-49965",
    "CVE-2024-49966",
    "CVE-2024-49967",
    "CVE-2024-49968",
    "CVE-2024-49969",
    "CVE-2024-49973",
    "CVE-2024-49974",
    "CVE-2024-49975",
    "CVE-2024-49981",
    "CVE-2024-49982",
    "CVE-2024-49983",
    "CVE-2024-49985",
    "CVE-2024-49989",
    "CVE-2024-49991",
    "CVE-2024-49993",
    "CVE-2024-49995",
    "CVE-2024-49996",
    "CVE-2024-50000",
    "CVE-2024-50001",
    "CVE-2024-50002",
    "CVE-2024-50003",
    "CVE-2024-50006",
    "CVE-2024-50007",
    "CVE-2024-50008",
    "CVE-2024-50009",
    "CVE-2024-50013",
    "CVE-2024-50014",
    "CVE-2024-50017",
    "CVE-2024-50019",
    "CVE-2024-50024",
    "CVE-2024-50025",
    "CVE-2024-50026",
    "CVE-2024-50028",
    "CVE-2024-50031",
    "CVE-2024-50033",
    "CVE-2024-50035",
    "CVE-2024-50041",
    "CVE-2024-50044",
    "CVE-2024-50045",
    "CVE-2024-50046",
    "CVE-2024-50047",
    "CVE-2024-50048",
    "CVE-2024-50049",
    "CVE-2024-50055",
    "CVE-2024-50058",
    "CVE-2024-50059",
    "CVE-2024-50061",
    "CVE-2024-50062",
    "CVE-2024-50063",
    "CVE-2024-50067",
    "CVE-2024-50073",
    "CVE-2024-50074",
    "CVE-2024-50077",
    "CVE-2024-50078",
    "CVE-2024-50081",
    "CVE-2024-50082",
    "CVE-2024-50089",
    "CVE-2024-50093",
    "CVE-2024-50095",
    "CVE-2024-50096",
    "CVE-2024-50098",
    "CVE-2024-50099",
    "CVE-2024-50103",
    "CVE-2024-50108",
    "CVE-2024-50110",
    "CVE-2024-50115",
    "CVE-2024-50116",
    "CVE-2024-50117",
    "CVE-2024-50124",
    "CVE-2024-50125",
    "CVE-2024-50127",
    "CVE-2024-50128",
    "CVE-2024-50131",
    "CVE-2024-50134",
    "CVE-2024-50135",
    "CVE-2024-50138",
    "CVE-2024-50141",
    "CVE-2024-50146",
    "CVE-2024-50147",
    "CVE-2024-50148",
    "CVE-2024-50150",
    "CVE-2024-50153",
    "CVE-2024-50154",
    "CVE-2024-50155",
    "CVE-2024-50156",
    "CVE-2024-50160",
    "CVE-2024-50167",
    "CVE-2024-50171",
    "CVE-2024-50179",
    "CVE-2024-50180",
    "CVE-2024-50182",
    "CVE-2024-50183",
    "CVE-2024-50184",
    "CVE-2024-50186",
    "CVE-2024-50187",
    "CVE-2024-50188",
    "CVE-2024-50189",
    "CVE-2024-50192",
    "CVE-2024-50194",
    "CVE-2024-50195",
    "CVE-2024-50196",
    "CVE-2024-50198",
    "CVE-2024-50201",
    "CVE-2024-50205",
    "CVE-2024-50208",
    "CVE-2024-50209",
    "CVE-2024-50215",
    "CVE-2024-50218",
    "CVE-2024-50229",
    "CVE-2024-50230",
    "CVE-2024-50232",
    "CVE-2024-50233",
    "CVE-2024-50234",
    "CVE-2024-50236",
    "CVE-2024-50237",
    "CVE-2024-50249",
    "CVE-2024-50255",
    "CVE-2024-50259",
    "CVE-2024-50261",
    "CVE-2024-50264",
    "CVE-2024-50265",
    "CVE-2024-50267",
    "CVE-2024-50268",
    "CVE-2024-50269",
    "CVE-2024-50271",
    "CVE-2024-50273",
    "CVE-2024-50274",
    "CVE-2024-50279",
    "CVE-2024-50282",
    "CVE-2024-50287",
    "CVE-2024-50289",
    "CVE-2024-50290",
    "CVE-2024-50292",
    "CVE-2024-50295",
    "CVE-2024-50298",
    "CVE-2024-50301",
    "CVE-2024-50302",
    "CVE-2024-53052",
    "CVE-2024-53058",
    "CVE-2024-53059",
    "CVE-2024-53060",
    "CVE-2024-53061",
    "CVE-2024-53063",
    "CVE-2024-53066",
    "CVE-2024-53068",
    "CVE-2024-53079",
    "CVE-2024-53085",
    "CVE-2024-53088",
    "CVE-2024-53104",
    "CVE-2024-53110"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4364-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/26");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : kernel (SUSE-SU-2024:4364-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 host has packages installed that are affected by
multiple vulnerabilities as referenced in the SUSE-SU-2024:4364-1 advisory.

    The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2021-47594: mptcp: never allow the PM to close a listener subflow (bsc#1226560).
    - CVE-2022-48879: efi: fix NULL-deref in init error path (bsc#1229556).
    - CVE-2022-48956: ipv6: avoid use-after-free in ip6_fragment() (bsc#1231893).
    - CVE-2022-48957: dpaa2-switch: Fix memory leak in dpaa2_switch_acl_entry_add() and
    dpaa2_switch_acl_entry_remove() (bsc#1231973).
    - CVE-2022-48958: ethernet: aeroflex: fix potential skb leak in greth_init_rings() (bsc#1231889).
    - CVE-2022-48959: net: dsa: sja1105: fix memory leak in sja1105_setup_devlink_regions() (bsc#1231976).
    - CVE-2022-48960: net: hisilicon: Fix potential use-after-free in hix5hd2_rx() (bsc#1231979).
    - CVE-2022-48962: net: hisilicon: Fix potential use-after-free in hisi_femac_rx() (bsc#1232286).
    - CVE-2022-48966: net: mvneta: Fix an out of bounds check (bsc#1232191).
    - CVE-2022-48980: net: dsa: sja1105: avoid out of bounds access in sja1105_init_l2_policing()
    (bsc#1232233).
    - CVE-2022-48983: io_uring: Fix a null-ptr-deref in io_tctx_exit_cb() (bsc#1231959).
    - CVE-2022-48991: mm/khugepaged: fix collapse_pte_mapped_thp() to allow anon_vma (bsc#1232070).
    - CVE-2022-49015: net: hsr: Fix potential use-after-free (bsc#1231938).
    - CVE-2022-49017: tipc: re-fetch skb cb after tipc_msg_validate (bsc#1232004).
    - CVE-2022-49020: net/9p: Fix a potential socket leak in p9_socket_open (bsc#1232175).
    - CVE-2024-26782: mptcp: fix double-free on socket dismantle (bsc#1222590).
    - CVE-2024-26906: Fixed invalid vsyscall page read for copy_from_kernel_nofault() (bsc#1223202).
    - CVE-2024-26953: net: esp: fix bad handling of pages from page_pool (bsc#1223656).
    - CVE-2024-35888: erspan: make sure erspan_base_hdr is present in skb->head (bsc#1224518).
    - CVE-2024-35937: wifi: cfg80211: check A-MSDU format more carefully (bsc#1224526).
    - CVE-2024-36244: net/sched: taprio: extend minimum interval restriction to entire cycle too
    (bsc#1226797).
    - CVE-2024-36883: net: fix out-of-bounds access in ops_init (bsc#1225725).
    - CVE-2024-36886: tipc: fix UAF in error path (bsc#1225730).
    - CVE-2024-36905: tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV sockets (bsc#1225742).
    - CVE-2024-36954: tipc: fix a possible memleak in tipc_buf_append (bsc#1225764).
    - CVE-2024-36957: octeontx2-af: avoid off-by-one read from userspace (bsc#1225762).
    - CVE-2024-38589: netrom: fix possible dead-lock in nr_rt_ioctl() (bsc#1226748).
    - CVE-2024-38615: cpufreq: exit() callback is optional (bsc#1226592).
    - CVE-2024-39476: md/raid5: fix deadlock that raid5d() wait for itself to clear MD_SB_CHANGE_PENDING
    (bsc#1227437).
    - CVE-2024-40965: i2c: lpi2c: Avoid calling clk_get_rate during transfer (bsc#1227885).
    - CVE-2024-40997: cpufreq: amd-pstate: fix memory leak on CPU EPP exit (bsc#1227853).
    - CVE-2024-41023: sched/deadline: Fix task_struct reference leak (bsc#1228430).
    - CVE-2024-42226: Prevent potential failure in handle_tx_event() for Transfer events without TRB
    (bsc#1228709).
    - CVE-2024-42253: gpio: pca953x: fix pca953x_irq_bus_sync_unlock race (bsc#1229005).
    - CVE-2024-44931: gpio: prevent potential speculation leaks in gpio_device_get_desc() (bsc#1229837).
    - CVE-2024-44932: idpf: fix UAFs when destroying the queues (bsc#1229808).
    - CVE-2024-44958: sched/smt: Fix unbalance sched_smt_present dec/inc (bsc#1230179).
    - CVE-2024-44964: idpf: fix memory leaks and crashes while performing a soft reset (bsc#1230220).
    - CVE-2024-44995: net: hns3: fix a deadlock problem when config TC during resetting (bsc#1230231).
    - CVE-2024-45016: netem: fix return value if duplicate enqueue fails (bsc#1230429).
    - CVE-2024-45025: fix bitmap corruption on close_range() with CLOSE_RANGE_UNSHARE (bsc#1230456).
    - CVE-2024-46678: bonding: change ipsec_lock from spin lock to mutex (bsc#1230550).
    - CVE-2024-46681: pktgen: use cpus_read_lock() in pg_net_init() (bsc#1230558).
    - CVE-2024-46716: dmaengine: altera-msgdma: properly free descriptor in msgdma_free_descriptor
    (bsc#1230715).
    - CVE-2024-46754: bpf: Remove tst_run from lwt_seg6local_prog_ops (bsc#1230801).
    - CVE-2024-46770: ice: Add netif_device_attach/detach into PF reset flow (bsc#1230763).
    - CVE-2024-46775: drm/amd/display: Validate function returns (bsc#1230774).
    - CVE-2024-46777: udf: Avoid excessive partition lengths (bsc#1230773).
    - CVE-2024-46800: sch/netem: fix use after free in netem_dequeue (bsc#1230827).
    - CVE-2024-46809: drm/amd/display: Check BIOS images before it is used (bsc#1231148).
    - CVE-2024-46811: drm/amd/display: Fix index may exceed array range within fpu_update_bw_bounding_box
    (bsc#1231179).
    - CVE-2024-46813: drm/amd/display: Check link_index before accessing dc->links (bsc#1231191).
    - CVE-2024-46814: drm/amd/display: Check msg_id before processing transcation (bsc#1231193).
    - CVE-2024-46815: drm/amd/display: Check num_valid_sets before accessing reader_wm_sets (bsc#1231195).
    - CVE-2024-46816: drm/amd/display: Stop amdgpu_dm initialize when link nums greater than max_links
    (bsc#1231197).
    - CVE-2024-46817: drm/amd/display: Stop amdgpu_dm initialize when stream nums greater than 6
    (bsc#1231200).
    - CVE-2024-46818: drm/amd/display: Check gpio_id before used as array index (bsc#1231203).
    - CVE-2024-46826: ELF: fix kernel.randomize_va_space double read (bsc#1231115).
    - CVE-2024-46828: uprobes: fix kernel info leak via '[uprobes]' vma (bsc#1231114).
    - CVE-2024-46834: ethtool: fail closed if we can't get max channel used in indirection tables
    (bsc#1231096).
    - CVE-2024-46840: btrfs: clean up our handling of refs == 0 in snapshot delete (bsc#1231105).
    - CVE-2024-46841: btrfs: do not BUG_ON on ENOMEM from btrfs_lookup_extent_info() in walk_down_proc()
    (bsc#1231094).
    - CVE-2024-46848: perf/x86/intel: Limit the period on Haswell (bsc#1231072).
    - CVE-2024-46849: ASoC: meson: axg-card: fix 'use-after-free' (bsc#1231073).
    - CVE-2024-46854: net: dpaa: Pad packets to ETH_ZLEN (bsc#1231084).
    - CVE-2024-46855: netfilter: nft_socket: fix sk refcount leaks (bsc#1231085).
    - CVE-2024-46857: net/mlx5: Fix bridge mode operations when there are no VFs (bsc#1231087).
    - CVE-2024-47660: fsnotify: clear PARENT_WATCHED flags lazily (bsc#1231439).
    - CVE-2024-47661: drm/amd/display: Avoid overflow from uint32_t to uint8_t (bsc#1231496).
    - CVE-2024-47664: spi: hisi-kunpeng: Add verification for the max_frequency provided by the firmware
    (bsc#1231442).
    - CVE-2024-47668: lib/generic-radix-tree.c: Fix rare race in __genradix_ptr_alloc() (bsc#1231502).
    - CVE-2024-47672: wifi: iwlwifi: mvm: do not wait for tx queues if firmware is dead (bsc#1231540).
    - CVE-2024-47673: wifi: iwlwifi: mvm: pause TCM when the firmware is stopped (bsc#1231539).
    - CVE-2024-47674: mm: avoid leaving partial pfn mappings around in error case (bsc#1231673).
    - CVE-2024-47679: vfs: fix race between evice_inodes() and find_inode()&iput() (bsc#1231930).
    - CVE-2024-47684: tcp: check skb is non-NULL in tcp_rto_delta_us() (bsc#1231987).
    - CVE-2024-47685: netfilter: nf_reject_ipv6: fix nf_reject_ip6_tcphdr_put() (bsc#1231998).
    - CVE-2024-47692: nfsd: return -EINVAL when namelen is 0 (bsc#1231857).
    - CVE-2024-47701: ext4: explicitly exit when ext4_find_inline_entry returns an error (bsc#1231920).
    - CVE-2024-47704: drm/amd/display: Check link_res->hpo_dp_link_enc before using it (bsc#1231944).
    - CVE-2024-47705: block: fix potential invalid pointer dereference in blk_add_partition (bsc#1231872).
    - CVE-2024-47706: block, bfq: fix possible UAF for bfqq->bic with merge chain (bsc#1231942).
    - CVE-2024-47707: ipv6: avoid possible NULL deref in rt6_uncached_list_flush_dev() (bsc#1231935).
    - CVE-2024-47710: sock_map: Add a cond_resched() in sock_hash_free() (bsc#1232049).
    - CVE-2024-47720: drm/amd/display: Add null check for set_output_gamma in dcn30_set_output_transfer_func
    (bsc#1232043).
    - CVE-2024-47727: x86/tdx: Fix 'in-kernel MMIO' check (bsc#1232116).
    - CVE-2024-47730: crypto: hisilicon/qm - inject error before stopping queue (bsc#1232075).
    - CVE-2024-47738: wifi: mac80211: do not use rate mask for offchannel TX either (bsc#1232114).
    - CVE-2024-47739: padata: use integer wrap around to prevent deadlock on seq_nr overflow (bsc#1232124).
    - CVE-2024-47745: mm: split critical region in remap_file_pages() and invoke LSMs in between
    (bsc#1232135).
    - CVE-2024-47747: net: seeq: Fix use after free vulnerability in ether3 Driver Due to Race Condition
    (bsc#1232145).
    - CVE-2024-47748: vhost_vdpa: assign irq bypass producer token correctly (bsc#1232174).
    - CVE-2024-47757: nilfs2: fix potential oob read in nilfs_btree_check_delete() (bsc#1232187).
    - CVE-2024-49858: efistub/tpm: Use ACPI reclaim memory for event log to avoid corruption (bsc#1232251).
    - CVE-2024-49860: ACPI: sysfs: validate return type of _STR method (bsc#1231861).
    - CVE-2024-49866: tracing/timerlat: Fix a race during cpuhp processing (bsc#1232259).
    - CVE-2024-49868: btrfs: fix a NULL pointer dereference when failed to start a new trasacntion
    (bsc#1232272).
    - CVE-2024-49881: ext4: update orig_path in ext4_find_extent() (bsc#1232201).
    - CVE-2024-49882: ext4: fix double brelse() the buffer of the extents path (bsc#1232200).
    - CVE-2024-49883: ext4: aovid use-after-free in ext4_ext_insert_extent() (bsc#1232199).
    - CVE-2024-49886: platform/x86: ISST: Fix the KASAN report slab-out-of-bounds bug (bsc#1232196).
    - CVE-2024-49890: drm/amd/pm: ensure the fw_info is not null before using it (bsc#1232217).
    - CVE-2024-49892: drm/amd/display: Initialize get_bytes_per_element's default to 1 (bsc#1232220).
    - CVE-2024-49896: drm/amd/display: Check stream before comparing them (bsc#1232221).
    - CVE-2024-49897: drm/amd/display: Check phantom_stream before it is used (bsc#1232355).
    - CVE-2024-49899: drm/amd/display: Initialize denominators' default to 1 (bsc#1232358).
    - CVE-2024-49901: drm/msm/adreno: Assign msm_gpu->pdev earlier to avoid nullptrs (bsc#1232305).
    - CVE-2024-49906: drm/amd/display: Check null pointer before try to access it (bsc#1232332).
    - CVE-2024-49909: drm/amd/display: Add NULL check for function pointer in dcn32_set_output_transfer_func
    (bsc#1232337).
    - CVE-2024-49911: drm/amd/display: Add NULL check for function pointer in dcn20_set_output_transfer_func
    (bsc#1232366).
    - CVE-2024-49914: drm/amd/display: Add null check for pipe_ctx->plane_state in (bsc#1232369).
    - CVE-2024-49917: drm/amd/display: Add NULL check for clk_mgr and clk_mgr->funcs in dcn30_init_hw
    (bsc#1231965).
    - CVE-2024-49918: drm/amd/display: Add null check for head_pipe in
    dcn32_acquire_idle_pipe_for_head_pipe_in_layer (bsc#1231967).
    - CVE-2024-49919: drm/amd/display: Add null check for head_pipe in dcn201_acquire_free_pipe_for_layer
    (bsc#1231968).
    - CVE-2024-49920: drm/amd/display: Check null pointers before multiple uses (bsc#1232313).
    - CVE-2024-49921: drm/amd/display: Check null pointers before used (bsc#1232371).
    - CVE-2024-49922: drm/amd/display: Check null pointers before using them (bsc#1232374).
    - CVE-2024-49923: drm/amd/display: Pass non-null to dcn20_validate_apply_pipe_split_flags (bsc#1232361).
    - CVE-2024-49925: fbdev: efifb: Register sysfs groups through driver core (bsc#1232224)
    - CVE-2024-49929: wifi: iwlwifi: mvm: avoid NULL pointer dereference (bsc#1232253).
    - CVE-2024-49930: wifi: ath11k: fix array out-of-bound access in SoC stats (bsc#1232260).
    - CVE-2024-49933: blk_iocost: fix more out of bound shifts (bsc#1232368).
    - CVE-2024-49934: fs/inode: Prevent dump_mapping() accessing invalid dentry.d_name.name (bsc#1232387).
    - CVE-2024-49936: net/xen-netback: prevent UAF in xenvif_flush_hash() (bsc#1232424).
    - CVE-2024-49939: wifi: rtw89: avoid to add interface to list twice when SER (bsc#1232381).
    - CVE-2024-49945: net/ncsi: Disable the ncsi work before freeing the associated structure (bsc#1232165).
    - CVE-2024-49946: ppp: do not assume bh is held in ppp_channel_bridge_input() (bsc#1232164).
    - CVE-2024-49949: net: avoid potential underflow in qdisc_pkt_len_init() with UFO (bsc#1232160).
    - CVE-2024-49950: Bluetooth: L2CAP: Fix uaf in l2cap_connect (bsc#1232159).
    - CVE-2024-49954: static_call: Replace pointless WARN_ON() in static_call_module_notify() (bsc#1232155).
    - CVE-2024-49955: ACPI: battery: Fix possible crash when unregistering a battery hook (bsc#1232154).
    - CVE-2024-49958: ocfs2: reserve space for inline xattr before attaching reflink tree (bsc#1232151).
    - CVE-2024-49959: jbd2: stop waiting for space when jbd2_cleanup_journal_tail() returns error
    (bsc#1232149).
    - CVE-2024-49960: ext4: fix timer use-after-free on failed mount (bsc#1232395).
    - CVE-2024-49967: ext4: no need to continue when the number of entries is 1 (bsc#1232140).
    - CVE-2024-49968: ext4: fix error message when rejecting the default hash (bsc#1232264).
    - CVE-2024-49969: drm/amd/display: Fix index out of bounds in DCN30 color transformation (bsc#1232519).
    - CVE-2024-49973: r8169: add tally counter fields added with RTL8125 (bsc#1232105).
    - CVE-2024-49974: NFSD: Force all NFSv4.2 COPY requests to be synchronous (bsc#1232383).
    - CVE-2024-49975: uprobes: fix kernel info leak via '[uprobes]' vma (bsc#1232104).
    - CVE-2024-49983: ext4: drop ppath from ext4_ext_replay_update_ex() to avoid double-free (bsc#1232096).
    - CVE-2024-49989: drm/amd/display: fix double free issue during amdgpu module unload (bsc#1232483).
    - CVE-2024-49991: drm/amdkfd: amdkfd_free_gtt_mem clear the correct pointer (bsc#1232282).
    - CVE-2024-49993: iommu/vt-d: Fix potential lockup if qi_submit_sync called with 0 count (bsc#1232316).
    - CVE-2024-49995: tipc: guard against string buffer overrun (bsc#1232432).
    - CVE-2024-49996: cifs: Fix buffer overflow when parsing NFS reparse points (bsc#1232089).
    - CVE-2024-50000: net/mlx5e: Fix NULL deref in mlx5e_tir_builder_alloc() (bsc#1232085).
    - CVE-2024-50001: net/mlx5: Fix error path in multi-packet WQE transmit (bsc#1232084).
    - CVE-2024-50002: static_call: Handle module init failure correctly in static_call_del_module()
    (bsc#1232083).
    - CVE-2024-50006: ext4: fix i_data_sem unlock order in ext4_ind_migrate() (bsc#1232442).
    - CVE-2024-50009: cpufreq: amd-pstate: add check for cpufreq_cpu_get's return value (bsc#1232318).
    - CVE-2024-50014: ext4: fix access to uninitialised lock in fc replay path (bsc#1232446).
    - CVE-2024-50019: kthread: unpark only parked kthread (bsc#1231990).
    - CVE-2024-50024: net: Fix an unsafe loop on the list (bsc#1231954).
    - CVE-2024-50028: thermal: core: Reference count the zone in thermal_zone_get_by_id() (bsc#1231950).
    - CVE-2024-50033: slip: make slhc_remember() more robust against malicious packets (bsc#1231914).
    - CVE-2024-50035: ppp: fix ppp_async_encode() illegal access (bsc#1232392).
    - CVE-2024-50041: i40e: Fix macvlan leak by synchronizing access to mac_filter_hash (bsc#1231907).
    - CVE-2024-50045: netfilter: br_netfilter: fix panic with metadata_dst skb (bsc#1231903).
    - CVE-2024-50046: kabi fix for NFSv4: Prevent NULL-pointer dereference in nfs42_complete_copies()
    (bsc#1231902).
    - CVE-2024-50047: smb: client: fix UAF in async decryption (bsc#1232418).
    - CVE-2024-50048: fbcon: Fix a NULL pointer dereference issue in fbcon_putcs (bsc#1232310).
    - CVE-2024-50055: driver core: bus: Fix double free in driver API bus_register() (bsc#1232329).
    - CVE-2024-50058: serial: protect uart_port_dtr_rts() in uart_shutdown() too (bsc#1232285).
    - CVE-2024-50059: ntb: ntb_hw_switchtec: Fix use after free vulnerability in switchtec_ntb_remove due to
    race condition (bsc#1232345).
    - CVE-2024-50061: i3c: master: cdns: Fix use after free vulnerability in cdns_i3c_master Driver Due to
    Race Condition (bsc#1232263).
    - CVE-2024-50063: kABI: bpf: struct bpf_map kABI workaround (bsc#1232435).
    - CVE-2024-50073: tty: n_gsm: Fix use-after-free in gsm_cleanup_mux (bsc#1232520).
    - CVE-2024-50081: blk-mq: setup queue ->tag_set before initializing hctx (bsc#1232501).
    - CVE-2024-50082: blk-rq-qos: fix crash on rq_qos_wait vs. rq_qos_wake_function race (bsc#1232500).
    - CVE-2024-50089: unicode: Do not special case ignorable code points (bsc#1232860).
    - CVE-2024-50093: thermal: intel: int340x: processor: Fix warning during module unload (bsc#1232877).
    - CVE-2024-50098: scsi: ufs: core: Set SDEV_OFFLINE when UFS is shut down (bsc#1232881).
    - CVE-2024-50108: drm/amd/display: Disable PSR-SU on Parade 08-01 TCON too (bsc#1232884).
    - CVE-2024-50110: xfrm: fix one more kernel-infoleak in algo dumping (bsc#1232885).
    - CVE-2024-50115: KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory (bsc#1232919).
    - CVE-2024-50125: Bluetooth: SCO: Fix UAF on sco_sock_timeout (bsc#1232928).
    - CVE-2024-50127: net: sched: fix use-after-free in taprio_change() (bsc#1232907).
    - CVE-2024-50128: net: wwan: fix global oob in wwan_rtnl_policy (bsc#1232905).
    - CVE-2024-50134: drm/vboxvideo: Replace fake VLA at end of vbva_mouse_pointer_shape (bsc#1232890).
    - CVE-2024-50135: nvme-pci: fix race condition between reset and nvme_dev_disable() (bsc#1232888).
    - CVE-2024-50138: bpf: Use raw_spinlock_t in ringbuf (bsc#1232935).
    - CVE-2024-50146: net/mlx5e: Do not call cleanup on profile rollback failure (bsc#1233056).
    - CVE-2024-50147: net/mlx5: Fix command bitmask initialization (bsc#1233067).
    - CVE-2024-50153: scsi: target: core: Fix null-ptr-deref in target_alloc_device() (bsc#1233061).
    - CVE-2024-50154: tcp: Fix use-after-free of nreq in reqsk_timer_handler() (bsc#1233070).
    - CVE-2024-50167: be2net: fix potential memory leak in be_xmit() (bsc#1233049).
    - CVE-2024-50171: net: systemport: fix potential memory leak in bcm_sysport_xmit() (bsc#1233057).
    - CVE-2024-50182: secretmem: disable memfd_secret() if arch cannot set direct map (bsc#1233129).
    - CVE-2024-50184: virtio_pmem: Check device status before requesting flush (bsc#1233135).
    - CVE-2024-50186: net: explicitly clear the sk pointer, when pf->create fails (bsc#1233110).
    - CVE-2024-50188: net: phy: dp83869: fix memory corruption when enabling fiber (bsc#1233107).
    - CVE-2024-50192: irqchip/gic-v4: Correctly deal with set_affinity on lazily-mapped VPEs (bsc#1233106).
    - CVE-2024-50195: posix-clock: posix-clock: Fix unbalanced locking in pc_clock_settime() (bsc#1233103).
    - CVE-2024-50196: pinctrl: ocelot: fix system hang on level based interrupts (bsc#1233113).
    - CVE-2024-50205: ALSA: firewire-lib: Avoid division by zero in apply_constraint_to_size() (bsc#1233293).
    - CVE-2024-50208: RDMA/bnxt_re: Fix a bug while setting up Level-2 PBL pages (bsc#1233117).
    - CVE-2024-50229: nilfs2: fix potential deadlock with newly created symlinks (bsc#1233205).
    - CVE-2024-50230: nilfs2: fix kernel bug due to missing clearing of checked flag (bsc#1233206).
    - CVE-2024-50259: netdevsim: Add trailing zero to terminate the string in
    nsim_nexthop_bucket_activity_write() (bsc#1233214).
    - CVE-2024-50261: macsec: Fix use-after-free while sending the offloading packet (bsc#1233253).
    - CVE-2024-50264: vsock/virtio: Initialization of the dangling pointer occurring in vsk->trans
    (bsc#1233453).
    - CVE-2024-50267: usb: serial: io_edgeport: fix use after free in debug printk (bsc#1233456).
    - CVE-2024-50271: signal: restore the override_rlimit logic (bsc#1233460).
    - CVE-2024-50273: btrfs: reinitialize delayed ref list after deleting it from the list (bsc#1233462).
    - CVE-2024-50274: idpf: avoid vport access in idpf_get_link_ksettings (bsc#1233463).
    - CVE-2024-50279: dm cache: fix out-of-bounds access to the dirty bitset when resizing (bsc#1233468).
    - CVE-2024-50289: media: av7110: fix a spectre vulnerability (bsc#1233478).
    - CVE-2024-50295: net: arc: fix the device for dma_map_single/dma_unmap_single (bsc#1233484).
    - CVE-2024-50298: net: enetc: allocate vf_state during PF probes (bsc#1233487).
    - CVE-2024-53052: io_uring/rw: fix missing NOWAIT check for O_DIRECT start write (bsc#1233548).
    - CVE-2024-53058: net: stmmac: TSO: Fix unbalanced DMA map/unmap for non-paged SKB data (bsc#1233552).
    - CVE-2024-53061: media: s5p-jpeg: prevent buffer overflows (bsc#1233555).
    - CVE-2024-53063: media: dvbdev: prevent the risk of out of memory access (bsc#1233557).
    - CVE-2024-53068: firmware: arm_scmi: Fix slab-use-after-free in scmi_bus_notifier() (bsc#1233561).
    - CVE-2024-53079: mm/thp: fix deferred split unqueue naming and locking (bsc#1233570).
    - CVE-2024-53088: i40e: fix race condition by adding filter's intermediate sync state (bsc#1233580).
    - CVE-2024-53104: media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format
    (bsc#1234025).
    - CVE-2024-53110: vp_vdpa: fix id_table array not null terminated error (bsc#1234085).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1054914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1082555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228119");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231083");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232043");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232083");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232119");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232124");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232151");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232232");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232352");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232359");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232362");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232370");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232394");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233110");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233129");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234108");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-December/020019.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d70561b");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47416");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47534");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-45934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48961");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48968");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48970");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48971");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48980");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48983");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48985");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48987");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48994");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49003");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49022");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49023");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49026");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49027");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49029");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49031");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49032");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28327");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26782");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27043");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35888");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35980");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36484");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38577");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38589");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41023");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42226");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42253");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46716");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46719");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46770");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46802");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46818");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47665");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47682");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47684");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47699");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47705");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47706");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47709");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47710");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47712");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47718");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47727");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47728");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47738");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47745");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47749");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47757");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49892");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49913");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49963");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49968");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49983");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49985");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49993");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50003");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50026");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50031");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50033");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50035");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50044");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50046");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50047");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50067");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50081");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50093");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50096");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50103");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50108");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50110");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50115");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50116");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50117");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50127");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50128");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50146");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50147");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50150");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50153");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50167");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50171");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50182");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50183");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50186");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50187");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50188");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50189");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50194");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50195");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50196");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50205");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50208");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50209");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50215");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50218");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50230");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50232");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50234");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50236");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50237");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50249");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50255");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50259");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50261");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50264");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50265");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50267");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50268");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50269");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50271");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50273");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50274");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50279");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50282");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50287");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50295");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50298");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50302");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53052");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53060");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53066");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53088");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53110");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150500_55_88-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump");
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
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-64kb-5.14.21-150500.55.88.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.88.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.88.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.88.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.88.1.150500.6.39.4', 'sp':'5', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.88.1.150500.6.39.4', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.88.1.150500.6.39.4', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.88.1.150500.6.39.4', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.88.1', 'sp':'5', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.88.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'reiserfs-kmp-default-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.88.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.88.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.88.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.88.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.88.1.150500.6.39.4', 'sp':'5', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.88.1.150500.6.39.4', 'sp':'5', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.88.1.150500.6.39.4', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.88.1.150500.6.39.4', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.88.1', 'sp':'5', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.88.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'reiserfs-kmp-default-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-legacy-release-15.5', 'sles-release-15.5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.5']},
    {'reference':'kernel-default-livepatch-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']},
    {'reference':'kernel-default-livepatch-devel-5.14.21-150500.55.88.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']},
    {'reference':'kernel-livepatch-5_14_21-150500_55_88-default-1-150500.11.5.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
