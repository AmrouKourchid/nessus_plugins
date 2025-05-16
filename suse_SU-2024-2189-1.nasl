#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2189-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(201035);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2020-36788",
    "CVE-2021-4148",
    "CVE-2021-39698",
    "CVE-2021-43056",
    "CVE-2021-43527",
    "CVE-2021-47358",
    "CVE-2021-47359",
    "CVE-2021-47360",
    "CVE-2021-47361",
    "CVE-2021-47362",
    "CVE-2021-47363",
    "CVE-2021-47364",
    "CVE-2021-47365",
    "CVE-2021-47366",
    "CVE-2021-47367",
    "CVE-2021-47368",
    "CVE-2021-47369",
    "CVE-2021-47370",
    "CVE-2021-47371",
    "CVE-2021-47372",
    "CVE-2021-47373",
    "CVE-2021-47374",
    "CVE-2021-47375",
    "CVE-2021-47376",
    "CVE-2021-47378",
    "CVE-2021-47379",
    "CVE-2021-47380",
    "CVE-2021-47381",
    "CVE-2021-47382",
    "CVE-2021-47383",
    "CVE-2021-47384",
    "CVE-2021-47385",
    "CVE-2021-47386",
    "CVE-2021-47387",
    "CVE-2021-47388",
    "CVE-2021-47389",
    "CVE-2021-47390",
    "CVE-2021-47391",
    "CVE-2021-47392",
    "CVE-2021-47393",
    "CVE-2021-47394",
    "CVE-2021-47395",
    "CVE-2021-47396",
    "CVE-2021-47397",
    "CVE-2021-47398",
    "CVE-2021-47399",
    "CVE-2021-47400",
    "CVE-2021-47401",
    "CVE-2021-47402",
    "CVE-2021-47403",
    "CVE-2021-47404",
    "CVE-2021-47405",
    "CVE-2021-47406",
    "CVE-2021-47407",
    "CVE-2021-47408",
    "CVE-2021-47409",
    "CVE-2021-47410",
    "CVE-2021-47412",
    "CVE-2021-47413",
    "CVE-2021-47414",
    "CVE-2021-47415",
    "CVE-2021-47416",
    "CVE-2021-47417",
    "CVE-2021-47418",
    "CVE-2021-47419",
    "CVE-2021-47420",
    "CVE-2021-47421",
    "CVE-2021-47422",
    "CVE-2021-47423",
    "CVE-2021-47424",
    "CVE-2021-47425",
    "CVE-2021-47426",
    "CVE-2021-47427",
    "CVE-2021-47428",
    "CVE-2021-47429",
    "CVE-2021-47430",
    "CVE-2021-47431",
    "CVE-2021-47433",
    "CVE-2021-47434",
    "CVE-2021-47435",
    "CVE-2021-47436",
    "CVE-2021-47437",
    "CVE-2021-47438",
    "CVE-2021-47439",
    "CVE-2021-47440",
    "CVE-2021-47441",
    "CVE-2021-47442",
    "CVE-2021-47443",
    "CVE-2021-47444",
    "CVE-2021-47445",
    "CVE-2021-47446",
    "CVE-2021-47447",
    "CVE-2021-47448",
    "CVE-2021-47449",
    "CVE-2021-47450",
    "CVE-2021-47451",
    "CVE-2021-47452",
    "CVE-2021-47453",
    "CVE-2021-47454",
    "CVE-2021-47455",
    "CVE-2021-47456",
    "CVE-2021-47457",
    "CVE-2021-47458",
    "CVE-2021-47459",
    "CVE-2021-47460",
    "CVE-2021-47461",
    "CVE-2021-47462",
    "CVE-2021-47463",
    "CVE-2021-47464",
    "CVE-2021-47465",
    "CVE-2021-47466",
    "CVE-2021-47467",
    "CVE-2021-47468",
    "CVE-2021-47469",
    "CVE-2021-47470",
    "CVE-2021-47471",
    "CVE-2021-47472",
    "CVE-2021-47473",
    "CVE-2021-47474",
    "CVE-2021-47475",
    "CVE-2021-47476",
    "CVE-2021-47477",
    "CVE-2021-47478",
    "CVE-2021-47479",
    "CVE-2021-47480",
    "CVE-2021-47481",
    "CVE-2021-47482",
    "CVE-2021-47483",
    "CVE-2021-47484",
    "CVE-2021-47485",
    "CVE-2021-47486",
    "CVE-2021-47488",
    "CVE-2021-47489",
    "CVE-2021-47490",
    "CVE-2021-47491",
    "CVE-2021-47492",
    "CVE-2021-47493",
    "CVE-2021-47494",
    "CVE-2021-47495",
    "CVE-2021-47496",
    "CVE-2021-47497",
    "CVE-2021-47498",
    "CVE-2021-47499",
    "CVE-2021-47500",
    "CVE-2021-47501",
    "CVE-2021-47502",
    "CVE-2021-47503",
    "CVE-2021-47505",
    "CVE-2021-47506",
    "CVE-2021-47507",
    "CVE-2021-47509",
    "CVE-2021-47510",
    "CVE-2021-47511",
    "CVE-2021-47513",
    "CVE-2021-47514",
    "CVE-2021-47516",
    "CVE-2021-47518",
    "CVE-2021-47520",
    "CVE-2021-47521",
    "CVE-2021-47522",
    "CVE-2021-47523",
    "CVE-2021-47524",
    "CVE-2021-47525",
    "CVE-2021-47526",
    "CVE-2021-47528",
    "CVE-2021-47529",
    "CVE-2021-47533",
    "CVE-2021-47534",
    "CVE-2021-47535",
    "CVE-2021-47536",
    "CVE-2021-47537",
    "CVE-2021-47540",
    "CVE-2021-47541",
    "CVE-2021-47542",
    "CVE-2021-47544",
    "CVE-2021-47549",
    "CVE-2021-47550",
    "CVE-2021-47551",
    "CVE-2021-47553",
    "CVE-2021-47554",
    "CVE-2021-47556",
    "CVE-2021-47558",
    "CVE-2021-47559",
    "CVE-2021-47560",
    "CVE-2021-47562",
    "CVE-2021-47563",
    "CVE-2021-47564",
    "CVE-2021-47565",
    "CVE-2022-48632",
    "CVE-2022-48634",
    "CVE-2022-48636",
    "CVE-2022-48652",
    "CVE-2022-48662",
    "CVE-2022-48671",
    "CVE-2022-48672",
    "CVE-2022-48673",
    "CVE-2022-48675",
    "CVE-2022-48686",
    "CVE-2022-48687",
    "CVE-2022-48688",
    "CVE-2022-48692",
    "CVE-2022-48693",
    "CVE-2022-48694",
    "CVE-2022-48695",
    "CVE-2022-48697",
    "CVE-2022-48699",
    "CVE-2022-48700",
    "CVE-2022-48701",
    "CVE-2022-48702",
    "CVE-2022-48703",
    "CVE-2022-48704",
    "CVE-2022-48708",
    "CVE-2022-48709",
    "CVE-2022-48710",
    "CVE-2023-0160",
    "CVE-2023-1829",
    "CVE-2023-2860",
    "CVE-2023-6531",
    "CVE-2023-47233",
    "CVE-2023-52591",
    "CVE-2023-52654",
    "CVE-2023-52655",
    "CVE-2023-52676",
    "CVE-2023-52686",
    "CVE-2023-52690",
    "CVE-2023-52702",
    "CVE-2023-52703",
    "CVE-2023-52707",
    "CVE-2023-52708",
    "CVE-2023-52730",
    "CVE-2023-52733",
    "CVE-2023-52736",
    "CVE-2023-52738",
    "CVE-2023-52739",
    "CVE-2023-52740",
    "CVE-2023-52741",
    "CVE-2023-52742",
    "CVE-2023-52743",
    "CVE-2023-52744",
    "CVE-2023-52745",
    "CVE-2023-52747",
    "CVE-2023-52753",
    "CVE-2023-52754",
    "CVE-2023-52756",
    "CVE-2023-52759",
    "CVE-2023-52763",
    "CVE-2023-52764",
    "CVE-2023-52766",
    "CVE-2023-52774",
    "CVE-2023-52781",
    "CVE-2023-52788",
    "CVE-2023-52789",
    "CVE-2023-52791",
    "CVE-2023-52798",
    "CVE-2023-52799",
    "CVE-2023-52800",
    "CVE-2023-52804",
    "CVE-2023-52805",
    "CVE-2023-52806",
    "CVE-2023-52810",
    "CVE-2023-52811",
    "CVE-2023-52814",
    "CVE-2023-52816",
    "CVE-2023-52817",
    "CVE-2023-52818",
    "CVE-2023-52819",
    "CVE-2023-52821",
    "CVE-2023-52825",
    "CVE-2023-52826",
    "CVE-2023-52832",
    "CVE-2023-52833",
    "CVE-2023-52834",
    "CVE-2023-52838",
    "CVE-2023-52840",
    "CVE-2023-52841",
    "CVE-2023-52844",
    "CVE-2023-52847",
    "CVE-2023-52853",
    "CVE-2023-52854",
    "CVE-2023-52855",
    "CVE-2023-52856",
    "CVE-2023-52858",
    "CVE-2023-52864",
    "CVE-2023-52865",
    "CVE-2023-52867",
    "CVE-2023-52868",
    "CVE-2023-52870",
    "CVE-2023-52871",
    "CVE-2023-52872",
    "CVE-2023-52873",
    "CVE-2023-52875",
    "CVE-2023-52876",
    "CVE-2023-52877",
    "CVE-2023-52878",
    "CVE-2023-52880",
    "CVE-2024-0639",
    "CVE-2024-26739",
    "CVE-2024-26764",
    "CVE-2024-26828",
    "CVE-2024-26840",
    "CVE-2024-26852",
    "CVE-2024-26862",
    "CVE-2024-26921",
    "CVE-2024-26925",
    "CVE-2024-26928",
    "CVE-2024-26929",
    "CVE-2024-26930",
    "CVE-2024-27398",
    "CVE-2024-27413",
    "CVE-2024-35811",
    "CVE-2024-35815",
    "CVE-2024-35817",
    "CVE-2024-35863",
    "CVE-2024-35867",
    "CVE-2024-35868",
    "CVE-2024-35895",
    "CVE-2024-35904",
    "CVE-2024-35905",
    "CVE-2024-35914",
    "CVE-2024-36926"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2189-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2024:2189-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:2189-1 advisory.

    The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2024-35905: Fixed int overflow for stack access size (bsc#1224488).
    - CVE-2024-26828: Fix underflow in parse_server_interfaces() (bsc#1223084).
    - CVE-2024-35863: Fix potential UAF in is_valid_oplock_break() (bsc#1224763).
    - CVE-2024-35867: Fix potential UAF in cifs_stats_proc_show() (bsc#1224664).
    - CVE-2024-35868: Fix potential UAF in cifs_stats_proc_write() (bsc#1224678).
    - CVE-2024-26928: Fix potential UAF in cifs_debug_files_proc_show() (bsc#1223532).
    - CVE-2024-36926: Fixed LPAR panics during boot up with a frozen PE (bsc#1222011).
    - CVE-2024-26925: Release mutex after nft_gc_seq_end from abort path (bsc#1223390).
    - CVE-2024-27413: Fix incorrect allocation size (bsc#1224438).
    - CVE-2024-35817: Set gtt bound flag in amdgpu_ttm_gart_bind (bsc#1224736).
    - CVE-2024-35904: Avoid dereference of garbage after mount failure (bsc#1224494).
    - CVE-2024-26929: Fixed double free of fcport (bsc#1223715).
    - CVE-2024-27398: Fixed use-after-free bugs caused by sco_sock_timeout (bsc#1224174).
    - CVE-2024-26930: Fixed double free of the ha->vp_map pointer (bsc#1223626).
    - CVE-2024-26840: Fixed a memory leak in cachefiles_add_cache() (bsc#1222976).
    - CVE-2024-26862: Fixed packet annotate data-races around ignore_outgoing (bsc#1223111).
    - CVE-2024-0639: Fixed a denial-of-service vulnerability due to a deadlock found in sctp_auto_asconf_init
    in net/sctp/socket.c (bsc#1218917).
    - CVE-2024-26921: Preserve kabi for sk_buff (bsc#1223138).
    - CVE-2024-26852: Fixed use-after-free in ip6_route_mpath_notify() (bsc#1223057).
    - CVE-2023-1829: Fixed a use-after-free vulnerability in the control index filter (tcindex) (bsc#1210335).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224910");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224913");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225121");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225122");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225127");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225129");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225151");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225156");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225184");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225225");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225228");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225232");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225250");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225257");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225261");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225321");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225329");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225370");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225464");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225599");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035721.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43527");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47358");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47359");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47360");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47361");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47362");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47363");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47364");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47365");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47366");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47367");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47368");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47369");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47370");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47371");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47372");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47373");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47374");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47375");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47376");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47378");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47379");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47380");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47381");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47382");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47383");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47384");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47385");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47386");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47387");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47388");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47389");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47390");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47391");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47392");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47393");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47394");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47395");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47396");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47397");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47398");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47399");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47400");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47401");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47403");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47404");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47405");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47406");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47407");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47408");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47409");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47410");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47412");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47413");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47414");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47415");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47416");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47417");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47418");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47419");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47420");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47421");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47422");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47423");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47424");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47425");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47426");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47427");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47428");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47429");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47430");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47431");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47433");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47437");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47438");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47439");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47440");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47441");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47442");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47443");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47444");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47445");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47446");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47447");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47448");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47449");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47450");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47451");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47452");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47453");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47454");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47455");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47456");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47457");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47458");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47459");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47460");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47461");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47462");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47463");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47464");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47465");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47466");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47467");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47468");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47469");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47470");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47471");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47473");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47474");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47475");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47478");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47479");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47480");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47481");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47482");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47483");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47484");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47485");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47486");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47488");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47489");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47491");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47492");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47493");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47494");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47495");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47496");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47497");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47498");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47499");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47500");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47501");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47503");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47506");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47510");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47511");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47513");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47514");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47516");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47518");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47520");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47522");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47523");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47525");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47526");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47528");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47529");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47533");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47534");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47537");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47540");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47542");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47544");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47549");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47550");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47551");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47553");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47554");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47556");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47558");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47559");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47560");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47562");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47563");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47564");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48634");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48694");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48699");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48700");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48709");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48710");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52654");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52736");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52738");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52741");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52745");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52781");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52799");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52806");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52818");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52825");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52832");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52833");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52844");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52876");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27398");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27413");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36926");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43527");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/26");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150400_24_122-default");
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
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.122.2.150400.24.58.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-devel-5.14.21-150400.24.122.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-macros-5.14.21-150400.24.122.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-source-5.14.21-150400.24.122.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.122.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-64kb-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-64kb-devel-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'kernel-default-base-5.14.21-150400.24.122.2.150400.24.58.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.122.2.150400.24.58.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'kernel-devel-5.14.21-150400.24.122.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-macros-5.14.21-150400.24.122.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-source-5.14.21-150400.24.122.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-syms-5.14.21-150400.24.122.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-syms-5.14.21-150400.24.122.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-64kb-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-64kb-devel-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.122.2.150400.24.58.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.122.2.150400.24.58.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-devel-5.14.21-150400.24.122.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-macros-5.14.21-150400.24.122.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-source-5.14.21-150400.24.122.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.122.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.122.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.122.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.122.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-syms-5.14.21-150400.24.122.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-zfcpdump-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'cluster-md-kmp-default-5.14.21-150400.24.122.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'dlm-kmp-default-5.14.21-150400.24.122.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'gfs2-kmp-default-5.14.21-150400.24.122.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'ocfs2-kmp-default-5.14.21-150400.24.122.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'kernel-default-livepatch-5.14.21-150400.24.122.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-default-livepatch-devel-5.14.21-150400.24.122.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-livepatch-5_14_21-150400_24_122-default-1-150400.9.3.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.122.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.122.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.122.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.122.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-zfcpdump-5.14.21-150400.24.122.2', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.122.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']}
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
