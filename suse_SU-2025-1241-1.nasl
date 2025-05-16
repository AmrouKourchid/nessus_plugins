#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1241-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(234407);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2017-5753",
    "CVE-2021-4453",
    "CVE-2021-4454",
    "CVE-2021-47517",
    "CVE-2021-47631",
    "CVE-2021-47632",
    "CVE-2021-47633",
    "CVE-2021-47635",
    "CVE-2021-47636",
    "CVE-2021-47637",
    "CVE-2021-47638",
    "CVE-2021-47639",
    "CVE-2021-47641",
    "CVE-2021-47642",
    "CVE-2021-47643",
    "CVE-2021-47644",
    "CVE-2021-47645",
    "CVE-2021-47646",
    "CVE-2021-47647",
    "CVE-2021-47648",
    "CVE-2021-47649",
    "CVE-2021-47650",
    "CVE-2021-47651",
    "CVE-2021-47652",
    "CVE-2021-47653",
    "CVE-2021-47654",
    "CVE-2021-47656",
    "CVE-2021-47657",
    "CVE-2021-47659",
    "CVE-2022-0168",
    "CVE-2022-0995",
    "CVE-2022-1016",
    "CVE-2022-1048",
    "CVE-2022-1184",
    "CVE-2022-2977",
    "CVE-2022-3303",
    "CVE-2022-3435",
    "CVE-2022-29900",
    "CVE-2022-29901",
    "CVE-2022-49044",
    "CVE-2022-49050",
    "CVE-2022-49051",
    "CVE-2022-49053",
    "CVE-2022-49054",
    "CVE-2022-49055",
    "CVE-2022-49056",
    "CVE-2022-49057",
    "CVE-2022-49058",
    "CVE-2022-49059",
    "CVE-2022-49060",
    "CVE-2022-49061",
    "CVE-2022-49062",
    "CVE-2022-49063",
    "CVE-2022-49064",
    "CVE-2022-49065",
    "CVE-2022-49066",
    "CVE-2022-49070",
    "CVE-2022-49071",
    "CVE-2022-49073",
    "CVE-2022-49074",
    "CVE-2022-49075",
    "CVE-2022-49076",
    "CVE-2022-49078",
    "CVE-2022-49082",
    "CVE-2022-49083",
    "CVE-2022-49084",
    "CVE-2022-49085",
    "CVE-2022-49086",
    "CVE-2022-49088",
    "CVE-2022-49089",
    "CVE-2022-49090",
    "CVE-2022-49091",
    "CVE-2022-49092",
    "CVE-2022-49093",
    "CVE-2022-49095",
    "CVE-2022-49096",
    "CVE-2022-49097",
    "CVE-2022-49098",
    "CVE-2022-49099",
    "CVE-2022-49100",
    "CVE-2022-49102",
    "CVE-2022-49103",
    "CVE-2022-49104",
    "CVE-2022-49105",
    "CVE-2022-49106",
    "CVE-2022-49107",
    "CVE-2022-49109",
    "CVE-2022-49111",
    "CVE-2022-49112",
    "CVE-2022-49113",
    "CVE-2022-49114",
    "CVE-2022-49115",
    "CVE-2022-49116",
    "CVE-2022-49118",
    "CVE-2022-49119",
    "CVE-2022-49120",
    "CVE-2022-49121",
    "CVE-2022-49122",
    "CVE-2022-49123",
    "CVE-2022-49125",
    "CVE-2022-49126",
    "CVE-2022-49128",
    "CVE-2022-49129",
    "CVE-2022-49130",
    "CVE-2022-49131",
    "CVE-2022-49132",
    "CVE-2022-49133",
    "CVE-2022-49134",
    "CVE-2022-49135",
    "CVE-2022-49136",
    "CVE-2022-49137",
    "CVE-2022-49138",
    "CVE-2022-49139",
    "CVE-2022-49144",
    "CVE-2022-49145",
    "CVE-2022-49147",
    "CVE-2022-49148",
    "CVE-2022-49151",
    "CVE-2022-49153",
    "CVE-2022-49154",
    "CVE-2022-49155",
    "CVE-2022-49156",
    "CVE-2022-49157",
    "CVE-2022-49158",
    "CVE-2022-49159",
    "CVE-2022-49160",
    "CVE-2022-49162",
    "CVE-2022-49163",
    "CVE-2022-49164",
    "CVE-2022-49165",
    "CVE-2022-49174",
    "CVE-2022-49175",
    "CVE-2022-49176",
    "CVE-2022-49177",
    "CVE-2022-49178",
    "CVE-2022-49179",
    "CVE-2022-49180",
    "CVE-2022-49182",
    "CVE-2022-49183",
    "CVE-2022-49185",
    "CVE-2022-49187",
    "CVE-2022-49188",
    "CVE-2022-49189",
    "CVE-2022-49192",
    "CVE-2022-49193",
    "CVE-2022-49194",
    "CVE-2022-49196",
    "CVE-2022-49199",
    "CVE-2022-49200",
    "CVE-2022-49201",
    "CVE-2022-49202",
    "CVE-2022-49203",
    "CVE-2022-49204",
    "CVE-2022-49205",
    "CVE-2022-49206",
    "CVE-2022-49207",
    "CVE-2022-49208",
    "CVE-2022-49209",
    "CVE-2022-49212",
    "CVE-2022-49213",
    "CVE-2022-49214",
    "CVE-2022-49215",
    "CVE-2022-49216",
    "CVE-2022-49217",
    "CVE-2022-49218",
    "CVE-2022-49219",
    "CVE-2022-49221",
    "CVE-2022-49222",
    "CVE-2022-49224",
    "CVE-2022-49225",
    "CVE-2022-49226",
    "CVE-2022-49227",
    "CVE-2022-49228",
    "CVE-2022-49230",
    "CVE-2022-49232",
    "CVE-2022-49233",
    "CVE-2022-49235",
    "CVE-2022-49236",
    "CVE-2022-49237",
    "CVE-2022-49238",
    "CVE-2022-49239",
    "CVE-2022-49241",
    "CVE-2022-49242",
    "CVE-2022-49243",
    "CVE-2022-49244",
    "CVE-2022-49246",
    "CVE-2022-49247",
    "CVE-2022-49248",
    "CVE-2022-49249",
    "CVE-2022-49250",
    "CVE-2022-49251",
    "CVE-2022-49252",
    "CVE-2022-49253",
    "CVE-2022-49254",
    "CVE-2022-49256",
    "CVE-2022-49257",
    "CVE-2022-49258",
    "CVE-2022-49259",
    "CVE-2022-49260",
    "CVE-2022-49261",
    "CVE-2022-49262",
    "CVE-2022-49263",
    "CVE-2022-49264",
    "CVE-2022-49265",
    "CVE-2022-49266",
    "CVE-2022-49268",
    "CVE-2022-49269",
    "CVE-2022-49270",
    "CVE-2022-49271",
    "CVE-2022-49272",
    "CVE-2022-49273",
    "CVE-2022-49274",
    "CVE-2022-49275",
    "CVE-2022-49276",
    "CVE-2022-49277",
    "CVE-2022-49278",
    "CVE-2022-49279",
    "CVE-2022-49280",
    "CVE-2022-49281",
    "CVE-2022-49283",
    "CVE-2022-49285",
    "CVE-2022-49286",
    "CVE-2022-49287",
    "CVE-2022-49288",
    "CVE-2022-49290",
    "CVE-2022-49291",
    "CVE-2022-49292",
    "CVE-2022-49293",
    "CVE-2022-49294",
    "CVE-2022-49295",
    "CVE-2022-49296",
    "CVE-2022-49297",
    "CVE-2022-49298",
    "CVE-2022-49299",
    "CVE-2022-49300",
    "CVE-2022-49301",
    "CVE-2022-49302",
    "CVE-2022-49304",
    "CVE-2022-49305",
    "CVE-2022-49306",
    "CVE-2022-49307",
    "CVE-2022-49308",
    "CVE-2022-49309",
    "CVE-2022-49310",
    "CVE-2022-49311",
    "CVE-2022-49312",
    "CVE-2022-49313",
    "CVE-2022-49314",
    "CVE-2022-49315",
    "CVE-2022-49316",
    "CVE-2022-49319",
    "CVE-2022-49320",
    "CVE-2022-49321",
    "CVE-2022-49322",
    "CVE-2022-49323",
    "CVE-2022-49325",
    "CVE-2022-49326",
    "CVE-2022-49327",
    "CVE-2022-49328",
    "CVE-2022-49329",
    "CVE-2022-49330",
    "CVE-2022-49331",
    "CVE-2022-49332",
    "CVE-2022-49333",
    "CVE-2022-49335",
    "CVE-2022-49336",
    "CVE-2022-49337",
    "CVE-2022-49338",
    "CVE-2022-49339",
    "CVE-2022-49341",
    "CVE-2022-49342",
    "CVE-2022-49343",
    "CVE-2022-49345",
    "CVE-2022-49346",
    "CVE-2022-49347",
    "CVE-2022-49348",
    "CVE-2022-49349",
    "CVE-2022-49350",
    "CVE-2022-49351",
    "CVE-2022-49352",
    "CVE-2022-49353",
    "CVE-2022-49354",
    "CVE-2022-49356",
    "CVE-2022-49357",
    "CVE-2022-49359",
    "CVE-2022-49362",
    "CVE-2022-49365",
    "CVE-2022-49367",
    "CVE-2022-49368",
    "CVE-2022-49370",
    "CVE-2022-49371",
    "CVE-2022-49373",
    "CVE-2022-49375",
    "CVE-2022-49376",
    "CVE-2022-49377",
    "CVE-2022-49378",
    "CVE-2022-49379",
    "CVE-2022-49381",
    "CVE-2022-49382",
    "CVE-2022-49384",
    "CVE-2022-49385",
    "CVE-2022-49386",
    "CVE-2022-49389",
    "CVE-2022-49390",
    "CVE-2022-49392",
    "CVE-2022-49394",
    "CVE-2022-49396",
    "CVE-2022-49397",
    "CVE-2022-49398",
    "CVE-2022-49399",
    "CVE-2022-49400",
    "CVE-2022-49402",
    "CVE-2022-49404",
    "CVE-2022-49406",
    "CVE-2022-49407",
    "CVE-2022-49409",
    "CVE-2022-49410",
    "CVE-2022-49411",
    "CVE-2022-49412",
    "CVE-2022-49413",
    "CVE-2022-49414",
    "CVE-2022-49416",
    "CVE-2022-49418",
    "CVE-2022-49419",
    "CVE-2022-49421",
    "CVE-2022-49422",
    "CVE-2022-49424",
    "CVE-2022-49426",
    "CVE-2022-49427",
    "CVE-2022-49429",
    "CVE-2022-49430",
    "CVE-2022-49431",
    "CVE-2022-49432",
    "CVE-2022-49433",
    "CVE-2022-49434",
    "CVE-2022-49435",
    "CVE-2022-49436",
    "CVE-2022-49437",
    "CVE-2022-49438",
    "CVE-2022-49440",
    "CVE-2022-49441",
    "CVE-2022-49442",
    "CVE-2022-49443",
    "CVE-2022-49444",
    "CVE-2022-49445",
    "CVE-2022-49446",
    "CVE-2022-49447",
    "CVE-2022-49448",
    "CVE-2022-49449",
    "CVE-2022-49451",
    "CVE-2022-49453",
    "CVE-2022-49455",
    "CVE-2022-49458",
    "CVE-2022-49459",
    "CVE-2022-49460",
    "CVE-2022-49462",
    "CVE-2022-49463",
    "CVE-2022-49465",
    "CVE-2022-49466",
    "CVE-2022-49467",
    "CVE-2022-49468",
    "CVE-2022-49470",
    "CVE-2022-49472",
    "CVE-2022-49473",
    "CVE-2022-49474",
    "CVE-2022-49475",
    "CVE-2022-49476",
    "CVE-2022-49477",
    "CVE-2022-49478",
    "CVE-2022-49479",
    "CVE-2022-49480",
    "CVE-2022-49481",
    "CVE-2022-49482",
    "CVE-2022-49483",
    "CVE-2022-49484",
    "CVE-2022-49485",
    "CVE-2022-49486",
    "CVE-2022-49487",
    "CVE-2022-49488",
    "CVE-2022-49489",
    "CVE-2022-49490",
    "CVE-2022-49491",
    "CVE-2022-49492",
    "CVE-2022-49493",
    "CVE-2022-49494",
    "CVE-2022-49495",
    "CVE-2022-49497",
    "CVE-2022-49498",
    "CVE-2022-49499",
    "CVE-2022-49501",
    "CVE-2022-49502",
    "CVE-2022-49503",
    "CVE-2022-49504",
    "CVE-2022-49505",
    "CVE-2022-49506",
    "CVE-2022-49507",
    "CVE-2022-49508",
    "CVE-2022-49509",
    "CVE-2022-49510",
    "CVE-2022-49511",
    "CVE-2022-49512",
    "CVE-2022-49514",
    "CVE-2022-49515",
    "CVE-2022-49516",
    "CVE-2022-49517",
    "CVE-2022-49518",
    "CVE-2022-49519",
    "CVE-2022-49520",
    "CVE-2022-49521",
    "CVE-2022-49522",
    "CVE-2022-49523",
    "CVE-2022-49524",
    "CVE-2022-49525",
    "CVE-2022-49526",
    "CVE-2022-49527",
    "CVE-2022-49529",
    "CVE-2022-49530",
    "CVE-2022-49532",
    "CVE-2022-49533",
    "CVE-2022-49534",
    "CVE-2022-49535",
    "CVE-2022-49536",
    "CVE-2022-49537",
    "CVE-2022-49538",
    "CVE-2022-49541",
    "CVE-2022-49542",
    "CVE-2022-49543",
    "CVE-2022-49544",
    "CVE-2022-49545",
    "CVE-2022-49546",
    "CVE-2022-49548",
    "CVE-2022-49549",
    "CVE-2022-49551",
    "CVE-2022-49552",
    "CVE-2022-49555",
    "CVE-2022-49556",
    "CVE-2022-49559",
    "CVE-2022-49560",
    "CVE-2022-49562",
    "CVE-2022-49563",
    "CVE-2022-49564",
    "CVE-2022-49565",
    "CVE-2022-49566",
    "CVE-2022-49568",
    "CVE-2022-49569",
    "CVE-2022-49570",
    "CVE-2022-49579",
    "CVE-2022-49581",
    "CVE-2022-49583",
    "CVE-2022-49584",
    "CVE-2022-49591",
    "CVE-2022-49592",
    "CVE-2022-49603",
    "CVE-2022-49605",
    "CVE-2022-49606",
    "CVE-2022-49607",
    "CVE-2022-49609",
    "CVE-2022-49610",
    "CVE-2022-49611",
    "CVE-2022-49613",
    "CVE-2022-49615",
    "CVE-2022-49616",
    "CVE-2022-49617",
    "CVE-2022-49618",
    "CVE-2022-49621",
    "CVE-2022-49623",
    "CVE-2022-49624",
    "CVE-2022-49625",
    "CVE-2022-49626",
    "CVE-2022-49627",
    "CVE-2022-49628",
    "CVE-2022-49631",
    "CVE-2022-49634",
    "CVE-2022-49635",
    "CVE-2022-49638",
    "CVE-2022-49640",
    "CVE-2022-49641",
    "CVE-2022-49642",
    "CVE-2022-49643",
    "CVE-2022-49644",
    "CVE-2022-49645",
    "CVE-2022-49646",
    "CVE-2022-49647",
    "CVE-2022-49648",
    "CVE-2022-49649",
    "CVE-2022-49650",
    "CVE-2022-49652",
    "CVE-2022-49653",
    "CVE-2022-49655",
    "CVE-2022-49656",
    "CVE-2022-49657",
    "CVE-2022-49658",
    "CVE-2022-49661",
    "CVE-2022-49663",
    "CVE-2022-49665",
    "CVE-2022-49667",
    "CVE-2022-49668",
    "CVE-2022-49670",
    "CVE-2022-49671",
    "CVE-2022-49672",
    "CVE-2022-49673",
    "CVE-2022-49674",
    "CVE-2022-49675",
    "CVE-2022-49676",
    "CVE-2022-49677",
    "CVE-2022-49678",
    "CVE-2022-49679",
    "CVE-2022-49680",
    "CVE-2022-49683",
    "CVE-2022-49685",
    "CVE-2022-49686",
    "CVE-2022-49687",
    "CVE-2022-49688",
    "CVE-2022-49693",
    "CVE-2022-49694",
    "CVE-2022-49695",
    "CVE-2022-49697",
    "CVE-2022-49699",
    "CVE-2022-49700",
    "CVE-2022-49701",
    "CVE-2022-49703",
    "CVE-2022-49704",
    "CVE-2022-49705",
    "CVE-2022-49707",
    "CVE-2022-49708",
    "CVE-2022-49710",
    "CVE-2022-49711",
    "CVE-2022-49712",
    "CVE-2022-49713",
    "CVE-2022-49714",
    "CVE-2022-49715",
    "CVE-2022-49716",
    "CVE-2022-49719",
    "CVE-2022-49720",
    "CVE-2022-49721",
    "CVE-2022-49722",
    "CVE-2022-49723",
    "CVE-2022-49724",
    "CVE-2022-49725",
    "CVE-2022-49726",
    "CVE-2022-49729",
    "CVE-2022-49730",
    "CVE-2022-49731",
    "CVE-2022-49732",
    "CVE-2022-49733",
    "CVE-2022-49739",
    "CVE-2022-49746",
    "CVE-2022-49748",
    "CVE-2022-49751",
    "CVE-2022-49753",
    "CVE-2022-49755",
    "CVE-2022-49759",
    "CVE-2023-0179",
    "CVE-2023-1652",
    "CVE-2023-2162",
    "CVE-2023-3567",
    "CVE-2023-28410",
    "CVE-2023-52930",
    "CVE-2023-52933",
    "CVE-2023-52935",
    "CVE-2023-52939",
    "CVE-2023-52941",
    "CVE-2023-52973",
    "CVE-2023-52974",
    "CVE-2023-52975",
    "CVE-2023-52976",
    "CVE-2023-52979",
    "CVE-2023-52983",
    "CVE-2023-52984",
    "CVE-2023-52988",
    "CVE-2023-52989",
    "CVE-2023-52992",
    "CVE-2023-52993",
    "CVE-2023-53000",
    "CVE-2023-53005",
    "CVE-2023-53006",
    "CVE-2023-53007",
    "CVE-2023-53008",
    "CVE-2023-53010",
    "CVE-2023-53015",
    "CVE-2023-53016",
    "CVE-2023-53019",
    "CVE-2023-53023",
    "CVE-2023-53024",
    "CVE-2023-53025",
    "CVE-2023-53026",
    "CVE-2023-53028",
    "CVE-2023-53029",
    "CVE-2023-53030",
    "CVE-2023-53033",
    "CVE-2024-26634",
    "CVE-2024-47678",
    "CVE-2024-50290",
    "CVE-2024-53063",
    "CVE-2024-53124",
    "CVE-2024-53176",
    "CVE-2024-53178",
    "CVE-2024-56651",
    "CVE-2024-57996",
    "CVE-2024-58013",
    "CVE-2024-58014",
    "CVE-2025-21693",
    "CVE-2025-21718",
    "CVE-2025-21772",
    "CVE-2025-21780"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1241-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2025:1241-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2025:1241-1 advisory.

    The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2022-49053: scsi: target: tcmu: Fix possible page UAF (bsc#1237918).
    - CVE-2022-49465: blk-throttle: Set BIO_THROTTLED when bio has been throttled (bsc#1238919).
    - CVE-2022-49739: gfs2: Always check inode size of inline inodes (bsc#1240207).
    - CVE-2023-52935: mm/khugepaged: fix ->anon_vma race (bsc#1240276).
    - CVE-2024-53124: net: fix data-races around sk->sk_forward_alloc (bsc#1234074).
    - CVE-2024-53176: smb: During unmount, ensure all cached dir instances drop their dentry (bsc#1234894).
    - CVE-2024-53178: smb: Do not leak cfid when reconnect races with open_cached_dir (bsc#1234895).
    - CVE-2024-56651: can: hi311x: hi3110_can_ist(): fix potential use-after-free (bsc#1235528).
    - CVE-2024-57996: net_sched: sch_sfq: do not allow 1 packet limit (bsc#1239076).
    - CVE-2024-58013: Bluetooth: MGMT: Fix slab-use-after-free Read in mgmt_remove_adv_monitor_sync
    (bsc#1239095).
    - CVE-2024-58014: wifi: brcmsmac: add gain range check to wlc_phy_iqcal_gainparams_nphy() (bsc#1239109).
    - CVE-2025-21693: mm: zswap: properly synchronize freeing resources during CPU hotunplug (bsc#1237029).
    - CVE-2025-21718: net: rose: fix timer races against user threads (bsc#1239073).
    - CVE-2025-21772: partitions: mac: fix handling of bogus partition table (bsc#1238911).
    - CVE-2025-21780: drm/amdgpu: avoid buffer overflow attach in smu_sys_set_pp_table() (bsc#1239115).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209980");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1232743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234074");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237818");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237980");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238083");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238091");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238110");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238122");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238144");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238156");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238184");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238228");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238234");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238257");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238261");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238298");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238311");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238394");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238397");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238551");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238818");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238943");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240250");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240322");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-April/020694.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?953a5135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-5753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4453");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4454");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47517");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47637");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47638");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47647");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47648");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47649");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47654");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0168");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3303");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49044");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49050");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49053");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49054");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49057");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49060");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49064");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49065");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49066");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49070");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49071");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49075");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49083");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49084");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49086");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49088");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49089");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49091");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49092");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49093");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49096");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49100");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49102");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49103");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49105");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49106");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49107");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49109");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49111");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49112");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49113");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49115");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49116");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49118");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49119");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49120");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49121");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49122");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49123");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49126");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49128");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49129");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49130");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49131");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49132");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49133");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49136");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49137");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49139");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49144");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49147");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49151");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49153");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49154");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49159");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49163");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49164");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49165");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49174");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49175");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49176");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49177");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49178");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49182");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49183");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49185");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49187");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49188");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49189");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49193");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49194");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49196");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49199");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49200");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49203");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49204");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49205");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49206");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49207");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49208");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49209");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49212");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49213");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49214");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49215");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49216");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49217");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49218");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49219");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49221");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49222");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49224");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49225");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49226");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49227");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49228");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49230");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49232");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49235");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49236");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49237");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49238");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49239");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49241");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49242");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49243");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49246");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49247");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49248");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49249");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49250");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49251");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49252");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49253");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49254");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49256");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49257");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49258");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49259");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49260");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49261");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49262");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49263");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49264");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49265");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49266");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49268");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49269");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49271");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49272");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49273");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49274");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49275");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49276");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49277");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49278");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49279");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49283");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49286");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49287");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49291");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49293");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49294");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49295");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49296");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49297");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49298");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49299");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49300");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49302");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49304");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49305");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49306");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49307");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49308");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49309");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49310");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49311");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49313");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49314");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49315");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49316");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49319");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49320");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49321");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49322");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49323");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49325");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49326");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49327");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49328");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49329");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49330");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49331");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49332");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49333");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49335");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49336");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49337");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49338");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49339");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49341");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49342");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49343");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49345");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49346");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49347");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49348");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49349");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49350");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49351");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49352");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49353");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49354");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49356");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49357");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49359");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49362");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49365");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49367");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49368");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49370");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49371");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49373");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49375");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49376");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49377");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49378");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49379");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49381");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49382");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49384");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49385");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49386");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49389");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49390");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49392");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49394");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49396");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49397");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49398");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49399");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49400");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49404");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49406");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49407");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49409");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49410");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49411");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49412");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49413");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49414");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49416");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49418");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49419");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49421");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49422");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49424");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49426");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49427");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49429");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49430");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49431");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49432");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49433");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49437");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49438");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49440");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49441");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49442");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49443");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49444");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49445");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49446");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49447");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49448");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49449");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49451");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49453");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49455");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49458");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49459");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49460");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49462");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49463");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49465");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49466");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49467");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49468");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49470");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49473");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49474");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49475");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49478");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49479");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49480");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49481");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49482");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49483");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49484");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49485");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49486");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49487");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49488");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49489");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49491");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49492");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49493");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49494");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49495");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49497");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49498");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49499");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49501");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49503");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49504");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49506");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49508");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49510");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49511");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49512");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49514");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49515");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49516");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49517");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49518");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49519");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49520");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49522");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49523");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49525");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49526");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49527");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49529");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49530");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49533");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49534");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49537");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49538");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49542");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49543");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49544");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49549");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49551");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49552");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49555");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49556");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49559");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49560");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49562");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49563");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49564");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49568");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49570");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49579");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49584");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49606");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49613");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49617");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49618");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49621");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49624");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49625");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49626");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49627");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49634");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49638");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49647");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49648");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49649");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49658");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49665");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49677");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49683");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49694");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49699");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49700");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49705");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49710");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49711");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49712");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49714");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49716");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49719");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49721");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49722");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49724");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49725");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49726");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49729");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49731");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49755");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28410");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52983");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52993");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53023");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53026");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53029");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53030");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53033");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26634");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53176");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53178");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21718");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21780");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0995");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-56651");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/15");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150500_55_100-default");
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

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.100.1.150500.6.47.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'reiserfs-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.100.1.150500.6.47.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.100.1.150500.6.47.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-devel-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-macros-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-source-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-syms-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'kernel-syms-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.100.1.150500.6.47.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.100.1.150500.6.47.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'kernel-default-livepatch-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']},
    {'reference':'kernel-default-livepatch-devel-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']},
    {'reference':'kernel-livepatch-5_14_21-150500_55_100-default-1-150500.11.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.100.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'reiserfs-kmp-default-5.14.21-150500.55.100.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']}
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
      severity   : SECURITY_HOLE,
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
