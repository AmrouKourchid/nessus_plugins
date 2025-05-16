#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4318-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(213016);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2023-6270",
    "CVE-2023-52766",
    "CVE-2023-52778",
    "CVE-2023-52800",
    "CVE-2023-52881",
    "CVE-2023-52917",
    "CVE-2023-52918",
    "CVE-2023-52919",
    "CVE-2023-52920",
    "CVE-2023-52921",
    "CVE-2023-52922",
    "CVE-2024-26596",
    "CVE-2024-26703",
    "CVE-2024-26741",
    "CVE-2024-26758",
    "CVE-2024-26761",
    "CVE-2024-26767",
    "CVE-2024-26782",
    "CVE-2024-26864",
    "CVE-2024-26943",
    "CVE-2024-26953",
    "CVE-2024-27017",
    "CVE-2024-27026",
    "CVE-2024-27043",
    "CVE-2024-27407",
    "CVE-2024-35888",
    "CVE-2024-35980",
    "CVE-2024-36000",
    "CVE-2024-36031",
    "CVE-2024-36244",
    "CVE-2024-36484",
    "CVE-2024-36883",
    "CVE-2024-36886",
    "CVE-2024-36905",
    "CVE-2024-36920",
    "CVE-2024-36927",
    "CVE-2024-36954",
    "CVE-2024-36968",
    "CVE-2024-38576",
    "CVE-2024-38577",
    "CVE-2024-38589",
    "CVE-2024-38599",
    "CVE-2024-40914",
    "CVE-2024-41016",
    "CVE-2024-41023",
    "CVE-2024-41031",
    "CVE-2024-41047",
    "CVE-2024-41082",
    "CVE-2024-42102",
    "CVE-2024-42145",
    "CVE-2024-44932",
    "CVE-2024-44958",
    "CVE-2024-44964",
    "CVE-2024-44995",
    "CVE-2024-45016",
    "CVE-2024-45025",
    "CVE-2024-46678",
    "CVE-2024-46680",
    "CVE-2024-46681",
    "CVE-2024-46721",
    "CVE-2024-46754",
    "CVE-2024-46765",
    "CVE-2024-46766",
    "CVE-2024-46770",
    "CVE-2024-46775",
    "CVE-2024-46777",
    "CVE-2024-46788",
    "CVE-2024-46797",
    "CVE-2024-46800",
    "CVE-2024-46802",
    "CVE-2024-46803",
    "CVE-2024-46804",
    "CVE-2024-46805",
    "CVE-2024-46806",
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
    "CVE-2024-46825",
    "CVE-2024-46826",
    "CVE-2024-46827",
    "CVE-2024-46828",
    "CVE-2024-46830",
    "CVE-2024-46831",
    "CVE-2024-46834",
    "CVE-2024-46835",
    "CVE-2024-46836",
    "CVE-2024-46840",
    "CVE-2024-46841",
    "CVE-2024-46842",
    "CVE-2024-46843",
    "CVE-2024-46845",
    "CVE-2024-46846",
    "CVE-2024-46848",
    "CVE-2024-46849",
    "CVE-2024-46851",
    "CVE-2024-46852",
    "CVE-2024-46853",
    "CVE-2024-46854",
    "CVE-2024-46855",
    "CVE-2024-46857",
    "CVE-2024-46859",
    "CVE-2024-46860",
    "CVE-2024-46861",
    "CVE-2024-46864",
    "CVE-2024-46870",
    "CVE-2024-46871",
    "CVE-2024-47658",
    "CVE-2024-47660",
    "CVE-2024-47661",
    "CVE-2024-47662",
    "CVE-2024-47663",
    "CVE-2024-47664",
    "CVE-2024-47665",
    "CVE-2024-47666",
    "CVE-2024-47667",
    "CVE-2024-47668",
    "CVE-2024-47669",
    "CVE-2024-47670",
    "CVE-2024-47671",
    "CVE-2024-47672",
    "CVE-2024-47673",
    "CVE-2024-47674",
    "CVE-2024-47675",
    "CVE-2024-47679",
    "CVE-2024-47681",
    "CVE-2024-47682",
    "CVE-2024-47684",
    "CVE-2024-47685",
    "CVE-2024-47686",
    "CVE-2024-47687",
    "CVE-2024-47688",
    "CVE-2024-47692",
    "CVE-2024-47693",
    "CVE-2024-47695",
    "CVE-2024-47696",
    "CVE-2024-47697",
    "CVE-2024-47698",
    "CVE-2024-47699",
    "CVE-2024-47701",
    "CVE-2024-47702",
    "CVE-2024-47703",
    "CVE-2024-47704",
    "CVE-2024-47705",
    "CVE-2024-47706",
    "CVE-2024-47707",
    "CVE-2024-47709",
    "CVE-2024-47710",
    "CVE-2024-47712",
    "CVE-2024-47713",
    "CVE-2024-47714",
    "CVE-2024-47715",
    "CVE-2024-47718",
    "CVE-2024-47719",
    "CVE-2024-47720",
    "CVE-2024-47723",
    "CVE-2024-47727",
    "CVE-2024-47728",
    "CVE-2024-47730",
    "CVE-2024-47731",
    "CVE-2024-47732",
    "CVE-2024-47735",
    "CVE-2024-47737",
    "CVE-2024-47738",
    "CVE-2024-47739",
    "CVE-2024-47741",
    "CVE-2024-47742",
    "CVE-2024-47743",
    "CVE-2024-47744",
    "CVE-2024-47745",
    "CVE-2024-47747",
    "CVE-2024-47748",
    "CVE-2024-47749",
    "CVE-2024-47750",
    "CVE-2024-47751",
    "CVE-2024-47752",
    "CVE-2024-47753",
    "CVE-2024-47754",
    "CVE-2024-47756",
    "CVE-2024-47757",
    "CVE-2024-49850",
    "CVE-2024-49851",
    "CVE-2024-49852",
    "CVE-2024-49853",
    "CVE-2024-49855",
    "CVE-2024-49858",
    "CVE-2024-49860",
    "CVE-2024-49861",
    "CVE-2024-49862",
    "CVE-2024-49863",
    "CVE-2024-49864",
    "CVE-2024-49866",
    "CVE-2024-49867",
    "CVE-2024-49868",
    "CVE-2024-49870",
    "CVE-2024-49871",
    "CVE-2024-49874",
    "CVE-2024-49875",
    "CVE-2024-49877",
    "CVE-2024-49878",
    "CVE-2024-49879",
    "CVE-2024-49881",
    "CVE-2024-49882",
    "CVE-2024-49883",
    "CVE-2024-49884",
    "CVE-2024-49886",
    "CVE-2024-49888",
    "CVE-2024-49890",
    "CVE-2024-49891",
    "CVE-2024-49892",
    "CVE-2024-49894",
    "CVE-2024-49895",
    "CVE-2024-49896",
    "CVE-2024-49897",
    "CVE-2024-49898",
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
    "CVE-2024-49925",
    "CVE-2024-49928",
    "CVE-2024-49929",
    "CVE-2024-49930",
    "CVE-2024-49931",
    "CVE-2024-49933",
    "CVE-2024-49934",
    "CVE-2024-49935",
    "CVE-2024-49936",
    "CVE-2024-49937",
    "CVE-2024-49938",
    "CVE-2024-49939",
    "CVE-2024-49944",
    "CVE-2024-49945",
    "CVE-2024-49946",
    "CVE-2024-49947",
    "CVE-2024-49949",
    "CVE-2024-49950",
    "CVE-2024-49952",
    "CVE-2024-49953",
    "CVE-2024-49954",
    "CVE-2024-49955",
    "CVE-2024-49957",
    "CVE-2024-49958",
    "CVE-2024-49959",
    "CVE-2024-49960",
    "CVE-2024-49961",
    "CVE-2024-49962",
    "CVE-2024-49963",
    "CVE-2024-49965",
    "CVE-2024-49966",
    "CVE-2024-49967",
    "CVE-2024-49968",
    "CVE-2024-49969",
    "CVE-2024-49972",
    "CVE-2024-49973",
    "CVE-2024-49974",
    "CVE-2024-49975",
    "CVE-2024-49976",
    "CVE-2024-49981",
    "CVE-2024-49982",
    "CVE-2024-49983",
    "CVE-2024-49985",
    "CVE-2024-49986",
    "CVE-2024-49987",
    "CVE-2024-49989",
    "CVE-2024-49991",
    "CVE-2024-49993",
    "CVE-2024-49995",
    "CVE-2024-49996",
    "CVE-2024-50000",
    "CVE-2024-50001",
    "CVE-2024-50002",
    "CVE-2024-50003",
    "CVE-2024-50004",
    "CVE-2024-50006",
    "CVE-2024-50007",
    "CVE-2024-50008",
    "CVE-2024-50009",
    "CVE-2024-50012",
    "CVE-2024-50013",
    "CVE-2024-50014",
    "CVE-2024-50015",
    "CVE-2024-50017",
    "CVE-2024-50019",
    "CVE-2024-50020",
    "CVE-2024-50021",
    "CVE-2024-50022",
    "CVE-2024-50023",
    "CVE-2024-50024",
    "CVE-2024-50025",
    "CVE-2024-50026",
    "CVE-2024-50027",
    "CVE-2024-50028",
    "CVE-2024-50031",
    "CVE-2024-50033",
    "CVE-2024-50035",
    "CVE-2024-50040",
    "CVE-2024-50041",
    "CVE-2024-50042",
    "CVE-2024-50044",
    "CVE-2024-50045",
    "CVE-2024-50046",
    "CVE-2024-50047",
    "CVE-2024-50048",
    "CVE-2024-50049",
    "CVE-2024-50055",
    "CVE-2024-50058",
    "CVE-2024-50059",
    "CVE-2024-50060",
    "CVE-2024-50061",
    "CVE-2024-50062",
    "CVE-2024-50063",
    "CVE-2024-50064",
    "CVE-2024-50067",
    "CVE-2024-50069",
    "CVE-2024-50073",
    "CVE-2024-50074",
    "CVE-2024-50075",
    "CVE-2024-50076",
    "CVE-2024-50077",
    "CVE-2024-50078",
    "CVE-2024-50080",
    "CVE-2024-50081",
    "CVE-2024-50082",
    "CVE-2024-50084",
    "CVE-2024-50087",
    "CVE-2024-50088",
    "CVE-2024-50089",
    "CVE-2024-50093",
    "CVE-2024-50095",
    "CVE-2024-50096",
    "CVE-2024-50098",
    "CVE-2024-50099",
    "CVE-2024-50100",
    "CVE-2024-50101",
    "CVE-2024-50102",
    "CVE-2024-50103",
    "CVE-2024-50108",
    "CVE-2024-50110",
    "CVE-2024-50115",
    "CVE-2024-50116",
    "CVE-2024-50117",
    "CVE-2024-50121",
    "CVE-2024-50124",
    "CVE-2024-50125",
    "CVE-2024-50127",
    "CVE-2024-50128",
    "CVE-2024-50130",
    "CVE-2024-50131",
    "CVE-2024-50134",
    "CVE-2024-50135",
    "CVE-2024-50136",
    "CVE-2024-50138",
    "CVE-2024-50139",
    "CVE-2024-50141",
    "CVE-2024-50145",
    "CVE-2024-50146",
    "CVE-2024-50147",
    "CVE-2024-50148",
    "CVE-2024-50150",
    "CVE-2024-50153",
    "CVE-2024-50154",
    "CVE-2024-50155",
    "CVE-2024-50156",
    "CVE-2024-50157",
    "CVE-2024-50158",
    "CVE-2024-50159",
    "CVE-2024-50160",
    "CVE-2024-50166",
    "CVE-2024-50167",
    "CVE-2024-50169",
    "CVE-2024-50171",
    "CVE-2024-50172",
    "CVE-2024-50175",
    "CVE-2024-50176",
    "CVE-2024-50177",
    "CVE-2024-50179",
    "CVE-2024-50180",
    "CVE-2024-50181",
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
    "CVE-2024-50200",
    "CVE-2024-50201",
    "CVE-2024-50205",
    "CVE-2024-50208",
    "CVE-2024-50209",
    "CVE-2024-50210",
    "CVE-2024-50215",
    "CVE-2024-50216",
    "CVE-2024-50218",
    "CVE-2024-50221",
    "CVE-2024-50224",
    "CVE-2024-50225",
    "CVE-2024-50229",
    "CVE-2024-50230",
    "CVE-2024-50231",
    "CVE-2024-50232",
    "CVE-2024-50233",
    "CVE-2024-50234",
    "CVE-2024-50235",
    "CVE-2024-50236",
    "CVE-2024-50237",
    "CVE-2024-50240",
    "CVE-2024-50245",
    "CVE-2024-50246",
    "CVE-2024-50248",
    "CVE-2024-50249",
    "CVE-2024-50250",
    "CVE-2024-50252",
    "CVE-2024-50255",
    "CVE-2024-50257",
    "CVE-2024-50261",
    "CVE-2024-50264",
    "CVE-2024-50265",
    "CVE-2024-50267",
    "CVE-2024-50268",
    "CVE-2024-50269",
    "CVE-2024-50271",
    "CVE-2024-50273",
    "CVE-2024-50274",
    "CVE-2024-50275",
    "CVE-2024-50276",
    "CVE-2024-50279",
    "CVE-2024-50282",
    "CVE-2024-50287",
    "CVE-2024-50289",
    "CVE-2024-50290",
    "CVE-2024-50292",
    "CVE-2024-50295",
    "CVE-2024-50296",
    "CVE-2024-50298",
    "CVE-2024-50301",
    "CVE-2024-50302",
    "CVE-2024-53042",
    "CVE-2024-53043",
    "CVE-2024-53045",
    "CVE-2024-53048",
    "CVE-2024-53051",
    "CVE-2024-53052",
    "CVE-2024-53055",
    "CVE-2024-53056",
    "CVE-2024-53058",
    "CVE-2024-53059",
    "CVE-2024-53060",
    "CVE-2024-53061",
    "CVE-2024-53063",
    "CVE-2024-53066",
    "CVE-2024-53068",
    "CVE-2024-53072",
    "CVE-2024-53074",
    "CVE-2024-53076",
    "CVE-2024-53079",
    "CVE-2024-53081",
    "CVE-2024-53082",
    "CVE-2024-53085",
    "CVE-2024-53088",
    "CVE-2024-53093",
    "CVE-2024-53094",
    "CVE-2024-53095",
    "CVE-2024-53096",
    "CVE-2024-53100",
    "CVE-2024-53101",
    "CVE-2024-53104",
    "CVE-2024-53106",
    "CVE-2024-53108",
    "CVE-2024-53110",
    "CVE-2024-53112",
    "CVE-2024-53114",
    "CVE-2024-53121",
    "CVE-2024-53138"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4318-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/26");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2024:4318-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:4318-1 advisory.

    The SUSE Linux Enterprise 15 SP6 kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2024-53095: smb: client: Fix use-after-free of network namespace (bsc#1233642).
    - CVE-2023-52778: mptcp: deal with large GSO size (bsc#1224948).
    - CVE-2023-52920: bpf: support non-r10 register spill/fill to/from stack in precision tracking
    (bsc#1232823).
    - CVE-2023-6270: aoe: fix the potential use-after-free problem in more places (bsc#1218562).
    - CVE-2024-26596: net: dsa: fix netdev_priv() dereference before check on non-DSA netdevice events
    (bsc#1220355).
    - CVE-2024-26741: dccp/tcp: Unhash sk from ehash for tb2 alloc failure after check_estalblished()
    (bsc#1222587).
    - CVE-2024-26782: mptcp: fix double-free on socket dismantle (bsc#1222590).
    - CVE-2024-26953: net: esp: fix bad handling of pages from page_pool (bsc#1223656).
    - CVE-2024-27017: netfilter: nft_set_pipapo: walk over current view on netlink dump (bsc#1223733).
    - CVE-2024-35888: erspan: make sure erspan_base_hdr is present in skb->head (bsc#1224518).
    - CVE-2024-36000: mm/hugetlb: fix missing hugetlb_lock for resv uncharge (bsc#1224548).
    - CVE-2024-36244: net/sched: taprio: extend minimum interval restriction to entire cycle too
    (bsc#1226797).
    - CVE-2024-36883: net: fix out-of-bounds access in ops_init (bsc#1225725).
    - CVE-2024-36886: tipc: fix UAF in error path (bsc#1225730).
    - CVE-2024-36905: tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV sockets (bsc#1225742).
    - CVE-2024-36927: ipv4: Fix uninit-value access in __ip_make_skb() (bsc#1225813).
    - CVE-2024-36954: tipc: fix a possible memleak in tipc_buf_append (bsc#1225764).
    - CVE-2024-36968: Bluetooth: L2CAP: Fix div-by-zero in l2cap_le_flowctl_init() (bsc#1226130).
    - CVE-2024-38589: netrom: fix possible dead-lock in nr_rt_ioctl() (bsc#1226748).
    - CVE-2024-40914: mm/huge_memory: do not unpoison huge_zero_folio (bsc#1227842).
    - CVE-2024-41023: sched/deadline: Fix task_struct reference leak (bsc#1228430).
    - CVE-2024-41031: mm/filemap: skip to create PMD-sized page cache if needed (bsc#1228454).
    - CVE-2024-41082: nvme-fabrics: use reserved tag for reg read/write command  (bsc#1228620).
    - CVE-2024-42102: Revert 'mm/writeback: fix possible divide-by-zero in wb_dirty_limits(), again'
    (bsc#1233132).
    - CVE-2024-44958: sched/smt: Fix unbalance sched_smt_present dec/inc (bsc#1230179).
    - CVE-2024-44995: net: hns3: fix a deadlock problem when config TC during resetting (bsc#1230231).
    - CVE-2024-45016: netem: fix return value if duplicate enqueue fails (bsc#1230429).
    - CVE-2024-45025: fix bitmap corruption on close_range() with CLOSE_RANGE_UNSHARE (bsc#1230456).
    - CVE-2024-46678: bonding: change ipsec_lock from spin lock to mutex (bsc#1230550).
    - CVE-2024-46680: Bluetooth: btnxpuart: Fix random crash seen while removing driver (bsc#1230557).
    - CVE-2024-46681: pktgen: use cpus_read_lock() in pg_net_init() (bsc#1230558).
    - CVE-2024-46721: pparmor: fix possible NULL pointer dereference (bsc#1230710)
    - CVE-2024-46754: bpf: Remove tst_run from lwt_seg6local_prog_ops (bsc#1230801).
    - CVE-2024-46765: ice: protect XDP configuration with a mutex (bsc#1230807).
    - CVE-2024-46766: ice: move netif_queue_set_napi to rtnl-protected sections (bsc#1230762).
    - CVE-2024-46770: ice: Add netif_device_attach/detach into PF reset flow (bsc#1230763).
    - CVE-2024-46775: drm/amd/display: Validate function returns (bsc#1230774).
    - CVE-2024-46777: udf: Avoid excessive partition lengths (bsc#1230773).
    - CVE-2024-46800: sch/netem: fix use after free in netem_dequeue (bsc#1230827).
    - CVE-2024-46813: drm/amd/display: Check link_index before accessing dc->links (bsc#1231191).
    - CVE-2024-46816: drm/amd/display: Stop amdgpu_dm initialize when link nums greater than max_links
    (bsc#1231197).
    - CVE-2024-46826: ELF: fix kernel.randomize_va_space double read (bsc#1231115).
    - CVE-2024-46828: sched: sch_cake: fix bulk flow accounting logic for host fairness (bsc#1231114).
    - CVE-2024-46831: net: microchip: vcap: Fix use-after-free error in kunit test (bsc#1231117).
    - CVE-2024-46834: ethtool: fail closed if we can't get max channel used in indirection tables
    (bsc#1231096).
    - CVE-2024-46840: btrfs: clean up our handling of refs == 0 in snapshot delete (bsc#1231105).
    - CVE-2024-46841: btrfs: do not BUG_ON on ENOMEM from btrfs_lookup_extent_info() in walk_down_proc()
    (bsc#1231094).
    - CVE-2024-46843: scsi: ufs: core: Remove SCSI host only if added (bsc#1231100).
    - CVE-2024-46854: net: dpaa: Pad packets to ETH_ZLEN (bsc#1231084).
    - CVE-2024-46855: netfilter: nft_socket: fix sk refcount leaks (bsc#1231085).
    - CVE-2024-46857: net/mlx5: Fix bridge mode operations when there are no VFs (bsc#1231087).
    - CVE-2024-46870: drm/amd/display: Disable DMCUB timeout for DCN35 (bsc#1231435).
    - CVE-2024-47658: crypto: stm32/cryp - call finalize with bh disabled (bsc#1231436).
    - CVE-2024-47660: fsnotify: clear PARENT_WATCHED flags lazily (bsc#1231439).
    - CVE-2024-47664: spi: hisi-kunpeng: Add verification for the max_frequency provided by the firmware
    (bsc#1231442).
    - CVE-2024-47674: mm: avoid leaving partial pfn mappings around in error case (bsc#1231673).
    - CVE-2024-47679: vfs: fix race between evice_inodes() and find_inode()&iput() (bsc#1231930).
    - CVE-2024-47684: tcp: check skb is non-NULL in tcp_rto_delta_us() (bsc#1231987).
    - CVE-2024-47685: netfilter: nf_reject_ipv6: fix nf_reject_ip6_tcphdr_put() (bsc#1231998).
    - CVE-2024-47687: vdpa/mlx5: Fix invalid mr resource destroy (bsc#1232003).
    - CVE-2024-47692: nfsd: return -EINVAL when namelen is 0 (bsc#1231857).
    - CVE-2024-47701: ext4: avoid OOB when system.data xattr changes underneath the filesystem (bsc#1231920).
    - CVE-2024-47703: bpf, lsm: add check for BPF LSM return value (bsc#1231946).
    - CVE-2024-47704: drm/amd/display: Check link_res->hpo_dp_link_enc before using it (bsc#1231944).
    - CVE-2024-47705: block: fix potential invalid pointer dereference in blk_add_partition (bsc#1231872).
    - CVE-2024-47706: block, bfq: fix possible UAF for bfqq->bic with merge chain (bsc#1231942).
    - CVE-2024-47707: ipv6: avoid possible NULL deref in rt6_uncached_list_flush_dev() (bsc#1231935).
    - CVE-2024-47710: sock_map: Add a cond_resched() in sock_hash_free() (bsc#1232049).
    - CVE-2024-47727: x86/tdx: Fix 'in-kernel MMIO' check (bsc#1232116).
    - CVE-2024-47730: crypto: hisilicon/qm - inject error before stopping queue (bsc#1232075).
    - CVE-2024-47731: drivers/perf: Fix ali_drw_pmu driver interrupt status clearing (bsc#1232117).
    - CVE-2024-47739: padata: use integer wrap around to prevent deadlock on seq_nr overflow (bsc#1232124).
    - CVE-2024-47741: btrfs: fix race setting file private on concurrent lseek using same fd (bsc#1231869).
    - CVE-2024-47745: mm: call the security_mmap_file() LSM hook in remap_file_pages() (bsc#1232135).
    - CVE-2024-47747: net: seeq: Fix use after free vulnerability in ether3 Driver Due to Race Condition
    (bsc#1232145).
    - CVE-2024-47752: media: mediatek: vcodec: Fix H264 stateless decoder smatch warning (bsc#1232130).
    - CVE-2024-47753: media: mediatek: vcodec: Fix VP8 stateless decoder smatch warning (bsc#1231868).
    - CVE-2024-47754: media: mediatek: vcodec: Fix H264 multi stateless decoder smatch warning (bsc#1232131).
    - CVE-2024-49852: scsi: elx: libefc: Fix potential use after free in efc_nport_vport_del() (bsc#1232819).
    - CVE-2024-49864: rxrpc: Fix a race between socket set up and I/O thread creation (bsc#1232256).
    - CVE-2024-49867: btrfs: wait for fixup workers before stopping cleaner kthread during umount
    (bsc#1232262).
    - CVE-2024-49868: btrfs: fix a NULL pointer dereference when failed to start a new trasacntion
    (bsc#1232272).
    - CVE-2024-49881: ext4: update orig_path in ext4_find_extent() (bsc#1232201).
    - CVE-2024-49882: ext4: fix double brelse() the buffer of the extents path (bsc#1232200).
    - CVE-2024-49883: ext4: aovid use-after-free in ext4_ext_insert_extent() (bsc#1232199).
    - CVE-2024-49888: bpf: Fix a sdiv overflow issue (bsc#1232208).
    - CVE-2024-49890: drm/amd/pm: ensure the fw_info is not null before using it (bsc#1232217).
    - CVE-2024-49892: drm/amd/display: Initialize get_bytes_per_element's default to 1 (bsc#1232220).
    - CVE-2024-49894: drm/amd/display: Fix index out of bounds in degamma hardware format translation
    (bsc#1232354).
    - CVE-2024-49895: drm/amd/display: Fix index out of bounds in DCN30 degamma hardware format translation
    (bsc#1232352).
    - CVE-2024-49896: drm/amd/display: Check stream before comparing them (bsc#1232221).
    - CVE-2024-49897: drm/amd/display: Check phantom_stream before it is used (bsc#1232355).
    - CVE-2024-49898: drm/amd/display: Check null-initialized variables (bsc#1232222).
    - CVE-2024-49899: drm/amd/display: Initialize denominators' default to 1 (bsc#1232358).
    - CVE-2024-49901: drm/msm/adreno: Assign msm_gpu->pdev earlier to avoid nullptrs (bsc#1232305).
    - CVE-2024-49906: drm/amd/display: Check null pointer before try to access it (bsc#1232332).
    - CVE-2024-49907: drm/amd/display: Check null pointers before using dc->clk_mgr (bsc#1232334).
    - CVE-2024-49908: drm/amd/display: Add null check for 'afb' in amdgpu_dm_update_cursor (bsc#1232335).
    - CVE-2024-49909: drm/amd/display: Add NULL check for function pointer in dcn32_set_output_transfer_func
    (bsc#1232337).
    - CVE-2024-49911: drm/amd/display: Add NULL check for function pointer in dcn20_set_output_transfer_func
    (bsc#1232366).
    - CVE-2024-49912: drm/amd/display: Handle null 'stream_status' in 'planes_changed_for_existing_stream'
    (bsc#1232367).
    - CVE-2024-49913: drm/amd/display: Add null check for top_pipe_to_program in commit_planes_for_stream
    (bsc#1232307).
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
    - CVE-2024-49933: blk_iocost: fix more out of bound shifts (bsc#1232368).
    - CVE-2024-49934: fs/inode: Prevent dump_mapping() accessing invalid dentry.d_name.name (bsc#1232387).
    - CVE-2024-49936: net/xen-netback: prevent UAF in xenvif_flush_hash() (bsc#1232424).
    - CVE-2024-49944: sctp: set sk_state back to CLOSED if autobind fails in sctp_listen_start (bsc#1232166).
    - CVE-2024-49945: net/ncsi: Disable the ncsi work before freeing the associated structure (bsc#1232165).
    - CVE-2024-49946: ppp: do not assume bh is held in ppp_channel_bridge_input() (bsc#1232164).
    - CVE-2024-49949: net: avoid potential underflow in qdisc_pkt_len_init() with UFO (bsc#1232160).
    - CVE-2024-49950: Bluetooth: L2CAP: Fix uaf in l2cap_connect (bsc#1232159).
    - CVE-2024-49952: netfilter: nf_tables: prevent nf_skb_duplicated corruption (bsc#1232157).
    - CVE-2024-49953: net/mlx5e: Fix crash caused by calling __xfrm_state_delete() twice (bsc#1232156).
    - CVE-2024-49954: static_call: Replace pointless WARN_ON() in static_call_module_notify() (bsc#1232155).
    - CVE-2024-49958: ocfs2: reserve space for inline xattr before attaching reflink tree (bsc#1232151).
    - CVE-2024-49959: jbd2: stop waiting for space when jbd2_cleanup_journal_tail() returns error
    (bsc#1232149).
    - CVE-2024-49960: ext4: fix timer use-after-free on failed mount (bsc#1232395).
    - CVE-2024-49967: ext4: no need to continue when the number of entries is 1 (bsc#1232140).
    - CVE-2024-49968: ext4: filesystems without casefold feature cannot be mounted with siphash (bsc#1232264).
    - CVE-2024-49969: drm/amd/display: Fix index out of bounds in DCN30 color transformation (bsc#1232519).
    - CVE-2024-49972: drm/amd/display: Deallocate DML memory if allocation fails (bsc#1232315).
    - CVE-2024-49973: r8169: add tally counter fields added with RTL8125 (bsc#1232105).
    - CVE-2024-49974: NFSD: Force all NFSv4.2 COPY requests to be synchronous (bsc#1232383).
    - CVE-2024-49983: ext4: drop ppath from ext4_ext_replay_update_ex() to avoid double-free (bsc#1232096).
    - CVE-2024-49986: platform/x86: x86-android-tablets: Fix use after free on platform_device_register()
    errors (bsc#1232093).
    - CVE-2024-49987: bpftool: Fix undefined behavior in qsort(NULL, 0, ...) (bsc#1232258).
    - CVE-2024-49989: drm/amd/display: fix double free issue during amdgpu module unload (bsc#1232483).
    - CVE-2024-49991: drm/amdkfd: amdkfd_free_gtt_mem clear the correct pointer (bsc#1232282).
    - CVE-2024-49993: iommu/vt-d: Fix potential lockup if qi_submit_sync called with 0 count (bsc#1232316).
    - CVE-2024-49995: tipc: guard against string buffer overrun (bsc#1232432).
    - CVE-2024-49996: cifs: Fix buffer overflow when parsing NFS reparse points (bsc#1232089).
    - CVE-2024-50000: net/mlx5e: Fix NULL deref in mlx5e_tir_builder_alloc() (bsc#1232085).
    - CVE-2024-50001: net/mlx5: Fix error path in multi-packet WQE transmit (bsc#1232084).
    - CVE-2024-50002: static_call: Handle module init failure correctly in static_call_del_module()
    (bsc#1232083).
    - CVE-2024-50003: drm/amd/display: Fix system hang while resume with TBT monitor (bsc#1232385).
    - CVE-2024-50004: drm/amd/display: update DML2 policy EnhancedPrefetchScheduleAccelerationFinal DCN35
    (bsc#1232396).
    - CVE-2024-50006: ext4: fix i_data_sem unlock order in ext4_ind_migrate() (bsc#1232442).
    - CVE-2024-50009: cpufreq: amd-pstate: add check for cpufreq_cpu_get's return value (bsc#1232318).
    - CVE-2024-50012: cpufreq: Avoid a bad reference count on CPU node (bsc#1232386).
    - CVE-2024-50014: ext4: fix access to uninitialised lock in fc replay path (bsc#1232446).
    - CVE-2024-50015: ext4: dax: fix overflowing extents beyond inode size when partially writing
    (bsc#1232079).
    - CVE-2024-50020: ice: Fix improper handling of refcount in ice_sriov_set_msix_vec_count() (bsc#1231989).
    - CVE-2024-50021: ice: Fix improper handling of refcount in ice_dpll_init_rclk_pins() (bsc#1231957).
    - CVE-2024-50022: device-dax: correct pgoff align in dax_set_mapping() (bsc#1231956).
    - CVE-2024-50024: net: Fix an unsafe loop on the list (bsc#1231954).
    - CVE-2024-50027: thermal: core: Free tzp copy along with the thermal zone (bsc#1231951).
    - CVE-2024-50028: thermal: core: Reference count the zone in thermal_zone_get_by_id() (bsc#1231950).
    - CVE-2024-50033: slip: make slhc_remember() more robust against malicious packets (bsc#1231914).
    - CVE-2024-50035: ppp: fix ppp_async_encode() illegal access (bsc#1232392).
    - CVE-2024-50040: igb: Do not bring the device up after non-fatal error (bsc#1231908).
    - CVE-2024-50041: i40e: Fix macvlan leak by synchronizing access to mac_filter_hash (bsc#1231907).
    - CVE-2024-50042: ice: Fix increasing MSI-X on VF (bsc#1231906).
    - CVE-2024-50045: netfilter: br_netfilter: fix panic with metadata_dst skb (bsc#1231903).
    - CVE-2024-50046: NFSv4: Prevent NULL-pointer dereference in nfs42_complete_copies() (bsc#1231902).
    - CVE-2024-50047: smb: client: fix UAF in async decryption (bsc#1232418).
    - CVE-2024-50059: ntb: ntb_hw_switchtec: Fix use after free vulnerability in switchtec_ntb_remove due to
    race condition (bsc#1232345).
    - CVE-2024-50060: io_uring: check if we need to reschedule during overflow flush (bsc#1232417).
    - CVE-2024-50063: bpf: Prevent tail call between progs attached to different hooks (bsc#1232435).
    - CVE-2024-50064: zram: free secondary algorithms names (bsc#1231901).
    - CVE-2024-50080: ublk: do not allow user copy for unprivileged device (bsc#1232502).
    - CVE-2024-50081: blk-mq: setup queue ->tag_set before initializing hctx (bsc#1232501).
    - CVE-2024-50082: blk-rq-qos: fix crash on rq_qos_wait vs. rq_qos_wake_function race (bsc#1232500).
    - CVE-2024-50084: net: microchip: vcap api: Fix memory leaks in vcap_api_encode_rule_test() (bsc#1232494).
    - CVE-2024-50087: btrfs: fix uninitialized pointer free on read_alloc_one_name() error (bsc#1232499).
    - CVE-2024-50088: btrfs: fix uninitialized pointer free in add_inode_ref() (bsc#1232498).
    - CVE-2024-50098: scsi: ufs: core: Set SDEV_OFFLINE when UFS is shut down (bsc#1232881).
    - CVE-2024-50110: xfrm: fix one more kernel-infoleak in algo dumping (bsc#1232885).
    - CVE-2024-50115: KVM: nSVM: Ignore nCR3[4:0] when loading PDPTEs from memory (bsc#1232919).
    - CVE-2024-50124: Bluetooth: ISO: Fix UAF on iso_sock_timeout (bsc#1232926).
    - CVE-2024-50125: Bluetooth: SCO: Fix UAF on sco_sock_timeout (bsc#1232928).
    - CVE-2024-50127: net: sched: fix use-after-free in taprio_change() (bsc#1232907).
    - CVE-2024-50128: net: wwan: fix global oob in wwan_rtnl_policy (bsc#1232905).
    - CVE-2024-50130: netfilter: bpf: must hold reference on net namespace (bsc#1232894).
    - CVE-2024-50138: bpf: Use raw_spinlock_t in ringbuf (bsc#1232935).
    - CVE-2024-50139: KVM: arm64: Fix shift-out-of-bounds bug (bsc#1233062).
    - CVE-2024-50145: octeon_ep: add SKB allocation failures handling in __octep_oq_process_rx()
    (bsc#1233044).
    - CVE-2024-50153: scsi: target: core: Fix null-ptr-deref in target_alloc_device() (bsc#1233061).
    - CVE-2024-50154: tcp/dccp: Do not use timer_pending() in reqsk_queue_unlink() (bsc#1233070).
    - CVE-2024-50166: fsl/fman: Fix refcount handling of fman-related devices (bsc#1233050).
    - CVE-2024-50167: be2net: fix potential memory leak in be_xmit() (bsc#1233049).
    - CVE-2024-50169: vsock: Update rx_bytes on read_skb() (bsc#1233320).
    - CVE-2024-50171: net: systemport: fix potential memory leak in bcm_sysport_xmit() (bsc#1233057).
    - CVE-2024-50177: drm/amd/display: fix a UBSAN warning in DML2.1 (bsc#1233115).
    - CVE-2024-50182: secretmem: disable memfd_secret() if arch cannot set direct map (bsc#1233129).
    - CVE-2024-50184: virtio_pmem: Check device status before requesting flush (bsc#1233135).
    - CVE-2024-50186: net: explicitly clear the sk pointer, when pf->create fails (bsc#1233110).
    - CVE-2024-50192: irqchip/gic-v4: Do not allow a VMOVP on a dying VPE (bsc#1233106).
    - CVE-2024-50195: posix-clock: Fix missing timespec64 check in pc_clock_settime() (bsc#1233103).
    - CVE-2024-50225: btrfs: fix error propagation of split bios (bsc#1233193).
    - CVE-2024-50230: nilfs2: fix kernel bug due to missing clearing of checked flag (bsc#1233206).
    - CVE-2024-50245: fs/ntfs3: Fix possible deadlock in mi_read (bsc#1233203).
    - CVE-2024-50246: fs/ntfs3: Add rough attr alloc_size check (bsc#1233207).
    - CVE-2024-50250: fsdax: dax_unshare_iter needs to copy entire blocks (bsc#1233226).
    - CVE-2024-50252: mlxsw: spectrum_ipip: Fix memory leak when changing remote IPv6 address (bsc#1233201).
    - CVE-2024-50257: netfilter: Fix use-after-free in get_info() (bsc#1233244).
    - CVE-2024-50261: macsec: Fix use-after-free while sending the offloading packet (bsc#1233253).
    - CVE-2024-50264: vsock/virtio: Initialization of the dangling pointer occurring in vsk->trans
    (bsc#1233453).
    - CVE-2024-50271: signal: restore the override_rlimit logic (bsc#1233460).
    - CVE-2024-50273: btrfs: reinitialize delayed ref list after deleting it from the list (bsc#1233462).
    - CVE-2024-50274: idpf: avoid vport access in idpf_get_link_ksettings (bsc#1233463).
    - CVE-2024-50275: arm64/sve: Discard stale CPU state when handling SVE traps (bsc#1233464).
    - CVE-2024-50276: net: vertexcom: mse102x: Fix possible double free of TX skb (bsc#1233465).
    - CVE-2024-50279: dm cache: fix out-of-bounds access to the dirty bitset when resizing (bsc#1233468).
    - CVE-2024-50289: media: av7110: fix a spectre vulnerability (bsc#1233478).
    - CVE-2024-50295: net: arc: fix the device for dma_map_single/dma_unmap_single (bsc#1233484).
    - CVE-2024-50296: net: hns3: fix kernel crash when uninstalling driver (bsc#1233485).
    - CVE-2024-50298: net: enetc: allocate vf_state during PF probes (bsc#1233487).
    - CVE-2024-53042: ipv4: ip_tunnel: Fix suspicious RCU usage warning in ip_tunnel_init_flow()
    (bsc#1233540).
    - CVE-2024-53043: mctp i2c: handle NULL header address (bsc#1233523).
    - CVE-2024-53048: ice: fix crash on probe for DPLL enabled E810 LOM (bsc#1233721).
    - CVE-2024-53051: drm/i915/hdcp: Add encoder check in intel_hdcp_get_capability (bsc#1233547).
    - CVE-2024-53055: wifi: iwlwifi: mvm: fix 6 GHz scan construction (bsc#1233550).
    - CVE-2024-53056: drm/mediatek: Fix potential NULL dereference in mtk_crtc_destroy() (bsc#1233568).
    - CVE-2024-53058: net: stmmac: TSO: Fix unbalanced DMA map/unmap for non-paged SKB data (bsc#1233552).
    - CVE-2024-53079: mm/thp: fix deferred split unqueue naming and locking (bsc#1233570).
    - CVE-2024-53082: virtio_net: Add hash_key_length check (bsc#1233573).
    - CVE-2024-53110: vp_vdpa: fix id_table array not null terminated error (bsc#1234085).
    - CVE-2024-53121: net/mlx5: fs, lock FTE when checking if active (bsc#1234078).
    - CVE-2024-53138: net/mlx5e: kTLS, Fix incorrect page refcounting (bsc#1234223).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1012628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1082555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228119");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231083");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231102");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231474");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232043");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232083");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232124");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232129");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232151");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232156");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232232");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232250");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232315");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232340");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232394");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233091");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233097");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233119");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233129");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233130");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233460");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233464");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234043");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234083");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234121");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234223");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-December/019999.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7ba3991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52778");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26596");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26741");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26758");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26761");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26767");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26782");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27026");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27043");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27407");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35888");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35980");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36031");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36484");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36968");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38576");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38577");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38589");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41023");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41031");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41047");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42102");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46721");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46765");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46770");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46797");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46802");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46806");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46825");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46830");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46831");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46836");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-46871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47658");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47665");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47666");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47682");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47684");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47699");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47705");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47706");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47709");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47710");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47712");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47714");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47718");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47719");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47727");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47728");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47731");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47738");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47741");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47745");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47749");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47750");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47757");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49888");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49892");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49898");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49961");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49963");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49968");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49983");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49985");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49986");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49987");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49993");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-49996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50003");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50022");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50023");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50026");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50027");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50031");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50033");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50035");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50040");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50044");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50046");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50047");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50060");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50064");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50067");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50069");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50075");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50080");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50081");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50084");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50087");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50088");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50093");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50096");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50100");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50101");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50102");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50103");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50108");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50110");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50115");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50116");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50117");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50121");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50127");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50128");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50130");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50136");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50139");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50146");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50147");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50150");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50153");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50159");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50167");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50169");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50171");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50172");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50175");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50176");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50177");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50181");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50200");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50205");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50208");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50209");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50210");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50215");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50216");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50218");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50221");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50224");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50225");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50230");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50231");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50232");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50234");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50235");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50236");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50237");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50240");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50245");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50246");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50248");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50249");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50250");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50252");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50255");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50257");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50261");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50264");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50265");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50267");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50268");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50269");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50271");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50273");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50274");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50275");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50276");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50279");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50282");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50287");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50295");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50296");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50298");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50302");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53043");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53052");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53060");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53066");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53072");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53081");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53088");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53093");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53094");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53096");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53100");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53101");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53106");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53108");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53110");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53112");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53121");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53138");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-6_4_0-150600_23_30-default");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-64kb-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-64kb-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.30.1.150600.12.12.6', 'sp':'6', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.30.1.150600.12.12.6', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.30.1.150600.12.12.6', 'sp':'6', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.30.1.150600.12.12.6', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'reiserfs-kmp-default-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'kernel-64kb-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-64kb-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.30.1.150600.12.12.6', 'sp':'6', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.30.1.150600.12.12.6', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.30.1.150600.12.12.6', 'sp':'6', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.30.1.150600.12.12.6', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-basesystem-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'reiserfs-kmp-default-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-legacy-release-15.6', 'sles-release-15.6']},
    {'reference':'cluster-md-kmp-64kb-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'cluster-md-kmp-default-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dlm-kmp-64kb-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dlm-kmp-default-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-allwinner-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-altera-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-amazon-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-amd-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-amlogic-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-apm-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-apple-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-arm-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-broadcom-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-cavium-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-exynos-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-freescale-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-hisilicon-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-lg-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-marvell-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-mediatek-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-nvidia-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-qcom-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-renesas-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-rockchip-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-socionext-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-sprd-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'dtb-xilinx-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'gfs2-kmp-64kb-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'gfs2-kmp-default-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-64kb-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-64kb-devel-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-64kb-extra-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-64kb-optional-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-debug-6.4.0-150600.23.30.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-debug-devel-6.4.0-150600.23.30.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-debug-vdso-6.4.0-150600.23.30.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.30.1.150600.12.12.6', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-base-6.4.0-150600.23.30.1.150600.12.12.6', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-base-rebuild-6.4.0-150600.23.30.1.150600.12.12.6', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-base-rebuild-6.4.0-150600.23.30.1.150600.12.12.6', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-devel-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-livepatch-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-livepatch-devel-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-optional-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-default-vdso-6.4.0-150600.23.30.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-devel-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-6.4.0-150600.23.30.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-devel-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-devel-6.4.0-150600.23.30.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-kvmsmall-vdso-6.4.0-150600.23.30.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-macros-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-obs-build-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-obs-qa-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-source-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-source-vanilla-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-syms-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kernel-zfcpdump-6.4.0-150600.23.30.1', 'cpu':'s390x', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kselftests-kmp-64kb-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'kselftests-kmp-default-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ocfs2-kmp-64kb-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ocfs2-kmp-default-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'reiserfs-kmp-64kb-6.4.0-150600.23.30.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'reiserfs-kmp-default-6.4.0-150600.23.30.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'cluster-md-kmp-default-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.6']},
    {'reference':'dlm-kmp-default-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.6']},
    {'reference':'gfs2-kmp-default-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.6']},
    {'reference':'ocfs2-kmp-default-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.6']},
    {'reference':'kernel-default-livepatch-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.6']},
    {'reference':'kernel-default-livepatch-devel-6.4.0-150600.23.30.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.6']},
    {'reference':'kernel-livepatch-6_4_0-150600_23_30-default-1-150600.13.3.5', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'kernel-default-extra-6.4.0-150600.23.30.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.6', 'sled-release-15.6', 'sles-release-15.6']}
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
