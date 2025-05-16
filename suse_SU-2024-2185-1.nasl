#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2185-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(200930);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id(
    "CVE-2020-36788",
    "CVE-2021-3743",
    "CVE-2021-39698",
    "CVE-2021-43056",
    "CVE-2021-43527",
    "CVE-2021-47104",
    "CVE-2021-47192",
    "CVE-2021-47200",
    "CVE-2021-47220",
    "CVE-2021-47227",
    "CVE-2021-47228",
    "CVE-2021-47229",
    "CVE-2021-47230",
    "CVE-2021-47231",
    "CVE-2021-47235",
    "CVE-2021-47236",
    "CVE-2021-47237",
    "CVE-2021-47239",
    "CVE-2021-47240",
    "CVE-2021-47241",
    "CVE-2021-47246",
    "CVE-2021-47252",
    "CVE-2021-47253",
    "CVE-2021-47254",
    "CVE-2021-47255",
    "CVE-2021-47258",
    "CVE-2021-47259",
    "CVE-2021-47260",
    "CVE-2021-47261",
    "CVE-2021-47263",
    "CVE-2021-47265",
    "CVE-2021-47267",
    "CVE-2021-47269",
    "CVE-2021-47270",
    "CVE-2021-47274",
    "CVE-2021-47275",
    "CVE-2021-47276",
    "CVE-2021-47280",
    "CVE-2021-47281",
    "CVE-2021-47284",
    "CVE-2021-47285",
    "CVE-2021-47288",
    "CVE-2021-47289",
    "CVE-2021-47296",
    "CVE-2021-47301",
    "CVE-2021-47302",
    "CVE-2021-47305",
    "CVE-2021-47307",
    "CVE-2021-47308",
    "CVE-2021-47314",
    "CVE-2021-47315",
    "CVE-2021-47320",
    "CVE-2021-47321",
    "CVE-2021-47323",
    "CVE-2021-47324",
    "CVE-2021-47329",
    "CVE-2021-47330",
    "CVE-2021-47332",
    "CVE-2021-47333",
    "CVE-2021-47334",
    "CVE-2021-47337",
    "CVE-2021-47338",
    "CVE-2021-47340",
    "CVE-2021-47341",
    "CVE-2021-47343",
    "CVE-2021-47344",
    "CVE-2021-47347",
    "CVE-2021-47348",
    "CVE-2021-47350",
    "CVE-2021-47353",
    "CVE-2021-47354",
    "CVE-2021-47356",
    "CVE-2021-47369",
    "CVE-2021-47375",
    "CVE-2021-47378",
    "CVE-2021-47381",
    "CVE-2021-47382",
    "CVE-2021-47383",
    "CVE-2021-47387",
    "CVE-2021-47388",
    "CVE-2021-47391",
    "CVE-2021-47392",
    "CVE-2021-47393",
    "CVE-2021-47395",
    "CVE-2021-47396",
    "CVE-2021-47399",
    "CVE-2021-47402",
    "CVE-2021-47404",
    "CVE-2021-47405",
    "CVE-2021-47409",
    "CVE-2021-47413",
    "CVE-2021-47416",
    "CVE-2021-47422",
    "CVE-2021-47423",
    "CVE-2021-47424",
    "CVE-2021-47425",
    "CVE-2021-47426",
    "CVE-2021-47428",
    "CVE-2021-47431",
    "CVE-2021-47434",
    "CVE-2021-47435",
    "CVE-2021-47436",
    "CVE-2021-47441",
    "CVE-2021-47442",
    "CVE-2021-47443",
    "CVE-2021-47444",
    "CVE-2021-47445",
    "CVE-2021-47451",
    "CVE-2021-47456",
    "CVE-2021-47458",
    "CVE-2021-47460",
    "CVE-2021-47464",
    "CVE-2021-47465",
    "CVE-2021-47468",
    "CVE-2021-47473",
    "CVE-2021-47478",
    "CVE-2021-47480",
    "CVE-2021-47482",
    "CVE-2021-47483",
    "CVE-2021-47485",
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
    "CVE-2021-47511",
    "CVE-2021-47512",
    "CVE-2021-47516",
    "CVE-2021-47518",
    "CVE-2021-47521",
    "CVE-2021-47522",
    "CVE-2021-47523",
    "CVE-2021-47535",
    "CVE-2021-47536",
    "CVE-2021-47538",
    "CVE-2021-47540",
    "CVE-2021-47541",
    "CVE-2021-47542",
    "CVE-2021-47549",
    "CVE-2021-47557",
    "CVE-2021-47562",
    "CVE-2021-47563",
    "CVE-2021-47565",
    "CVE-2022-1195",
    "CVE-2022-20132",
    "CVE-2022-48636",
    "CVE-2022-48673",
    "CVE-2022-48704",
    "CVE-2022-48710",
    "CVE-2023-0160",
    "CVE-2023-1829",
    "CVE-2023-2176",
    "CVE-2023-4244",
    "CVE-2023-6531",
    "CVE-2023-47233",
    "CVE-2023-52433",
    "CVE-2023-52581",
    "CVE-2023-52591",
    "CVE-2023-52654",
    "CVE-2023-52655",
    "CVE-2023-52686",
    "CVE-2023-52840",
    "CVE-2023-52871",
    "CVE-2023-52880",
    "CVE-2024-26581",
    "CVE-2024-26643",
    "CVE-2024-26828",
    "CVE-2024-26921",
    "CVE-2024-26925",
    "CVE-2024-26929",
    "CVE-2024-26930",
    "CVE-2024-27398",
    "CVE-2024-27413",
    "CVE-2024-35811",
    "CVE-2024-35895",
    "CVE-2024-35914"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2185-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2024:2185-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:2185-1 advisory.

    The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2021-47378: Destroy cm id before destroy qp to avoid use after free (bsc#1225201).
    - CVE-2021-47496: Fix flipped sign in tls_err_abort() calls (bsc#1225354)
    - CVE-2021-47402: Protect fl_walk() with rcu (bsc#1225301)
    - CVE-2022-48673: kABI workarounds for struct smc_link (bsc#1223934).
    - CVE-2023-52871: Handle a second device without data corruption (bsc#1225534)
    - CVE-2024-26828: Fix underflow in parse_server_interfaces() (bsc#1223084).
    - CVE-2021-47497: Fixed shift-out-of-bound (UBSAN) with byte size cells (bsc#1225355).
    - CVE-2021-47500: Fixed trigger reference couting (bsc#1225360).
    - CVE-2024-27413: Fix incorrect allocation size (bsc#1224438).
    - CVE-2021-47383: Fiedx out-of-bound vmalloc access in imageblit (bsc#1225208).
    - CVE-2021-47511: Fixed negative period/buffer sizes (bsc#1225411).
    - CVE-2023-52840: Fix use after free in rmi_unregister_function() (bsc#1224928).
    - CVE-2021-47261: Fix initializing CQ fragments buffer (bsc#1224954)
    - CVE-2021-47254: Fix use-after-free in gfs2_glock_shrink_scan (bsc#1224888).
    - CVE-2024-27398: Fixed use-after-free bugs caused by sco_sock_timeout (bsc#1224174).
    - CVE-2024-26921: Preserve kabi for sk_buff (bsc#1223138).
    - CVE-2023-52655: Check packet for fixup for true limit (bsc#1217169).
    - CVE-2023-4244: Fixed a use-after-free in the nf_tables component, which could be exploited to achieve
    local privilege escalation (bsc#1215420).
    - CVE-2023-4244: Fixed a use-after-free in the nf_tables component, which could be exploited to achieve
    local privilege escalation (bsc#1215420).
    - CVE-2023-1829: Fixed a use-after-free vulnerability in the control index filter (tcindex) (bsc#1210335).
    - CVE-2023-52686: Fix a null pointer in opal_event_init() (bsc#1065729).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1151927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220144");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224907");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225083");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225091");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225128");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225232");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225261");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225316");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225321");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225330");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225367");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225370");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225534");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035718.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43527");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47200");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47220");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47227");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47228");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47229");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47230");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47231");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47235");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47236");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47237");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47239");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47240");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47241");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47246");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47252");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47253");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47254");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47255");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47258");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47259");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47260");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47261");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47263");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47265");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47267");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47269");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47274");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47275");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47276");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47284");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47296");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47302");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47305");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47307");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47308");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47314");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47315");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47320");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47321");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47323");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47324");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47329");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47330");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47332");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47333");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47334");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47337");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47338");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47340");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47341");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47343");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47344");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47347");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47348");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47350");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47353");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47354");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47356");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47369");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47375");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47378");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47381");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47382");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47383");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47387");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47388");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47391");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47392");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47393");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47395");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47396");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47399");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47404");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47405");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47409");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47413");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47416");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47422");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47423");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47424");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47425");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47426");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47428");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47431");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47441");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47442");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47443");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47444");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47445");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47451");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47456");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47458");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47460");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47464");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47465");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47468");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47473");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47478");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47480");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47482");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47483");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47485");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47511");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47512");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47516");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47518");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47522");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47523");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47538");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47540");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47542");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47549");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47557");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47562");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47563");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1195");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20132");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48710");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2176");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52433");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52654");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27398");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27413");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35914");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43527");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/25");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_164-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-devel");
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
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.164.1.150300.18.96.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-devel-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-macros-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-source-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-64kb-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-64kb-devel-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.164.1.150300.18.96.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.164.1.150300.18.96.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-devel-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-macros-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-source-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'cluster-md-kmp-default-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'dlm-kmp-default-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'gfs2-kmp-default-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'ocfs2-kmp-default-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'kernel-default-livepatch-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-default-livepatch-devel-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-livepatch-5_3_18-150300_59_164-default-1-150300.7.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.164.1.150300.18.96.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-zfcpdump-5.3.18-150300.59.164.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.164.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
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
