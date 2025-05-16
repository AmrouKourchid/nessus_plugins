#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2190-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(201009);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id(
    "CVE-2020-36788",
    "CVE-2021-4148",
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
    "CVE-2021-47504",
    "CVE-2021-47505",
    "CVE-2021-47506",
    "CVE-2021-47507",
    "CVE-2021-47508",
    "CVE-2021-47509",
    "CVE-2021-47510",
    "CVE-2021-47511",
    "CVE-2021-47512",
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
    "CVE-2021-47530",
    "CVE-2021-47531",
    "CVE-2021-47532",
    "CVE-2021-47533",
    "CVE-2021-47534",
    "CVE-2021-47535",
    "CVE-2021-47536",
    "CVE-2021-47537",
    "CVE-2021-47540",
    "CVE-2021-47541",
    "CVE-2021-47542",
    "CVE-2021-47544",
    "CVE-2021-47548",
    "CVE-2021-47549",
    "CVE-2021-47550",
    "CVE-2021-47551",
    "CVE-2021-47552",
    "CVE-2021-47553",
    "CVE-2021-47554",
    "CVE-2021-47555",
    "CVE-2021-47556",
    "CVE-2021-47557",
    "CVE-2021-47558",
    "CVE-2021-47559",
    "CVE-2021-47560",
    "CVE-2021-47562",
    "CVE-2021-47563",
    "CVE-2021-47564",
    "CVE-2021-47565",
    "CVE-2021-47569",
    "CVE-2022-48633",
    "CVE-2022-48662",
    "CVE-2022-48669",
    "CVE-2022-48689",
    "CVE-2022-48691",
    "CVE-2022-48699",
    "CVE-2022-48705",
    "CVE-2022-48708",
    "CVE-2022-48709",
    "CVE-2022-48710",
    "CVE-2023-0160",
    "CVE-2023-1829",
    "CVE-2023-6531",
    "CVE-2023-42755",
    "CVE-2023-47233",
    "CVE-2023-52586",
    "CVE-2023-52591",
    "CVE-2023-52618",
    "CVE-2023-52642",
    "CVE-2023-52643",
    "CVE-2023-52644",
    "CVE-2023-52646",
    "CVE-2023-52650",
    "CVE-2023-52653",
    "CVE-2023-52654",
    "CVE-2023-52655",
    "CVE-2023-52656",
    "CVE-2023-52657",
    "CVE-2023-52659",
    "CVE-2023-52660",
    "CVE-2023-52661",
    "CVE-2023-52662",
    "CVE-2023-52664",
    "CVE-2023-52669",
    "CVE-2023-52671",
    "CVE-2023-52674",
    "CVE-2023-52676",
    "CVE-2023-52678",
    "CVE-2023-52679",
    "CVE-2023-52680",
    "CVE-2023-52683",
    "CVE-2023-52685",
    "CVE-2023-52686",
    "CVE-2023-52690",
    "CVE-2023-52691",
    "CVE-2023-52692",
    "CVE-2023-52693",
    "CVE-2023-52694",
    "CVE-2023-52696",
    "CVE-2023-52698",
    "CVE-2023-52699",
    "CVE-2023-52702",
    "CVE-2023-52703",
    "CVE-2023-52705",
    "CVE-2023-52707",
    "CVE-2023-52708",
    "CVE-2023-52730",
    "CVE-2023-52731",
    "CVE-2023-52732",
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
    "CVE-2023-52746",
    "CVE-2023-52747",
    "CVE-2023-52753",
    "CVE-2023-52754",
    "CVE-2023-52756",
    "CVE-2023-52757",
    "CVE-2023-52759",
    "CVE-2023-52763",
    "CVE-2023-52764",
    "CVE-2023-52766",
    "CVE-2023-52773",
    "CVE-2023-52774",
    "CVE-2023-52777",
    "CVE-2023-52781",
    "CVE-2023-52788",
    "CVE-2023-52789",
    "CVE-2023-52791",
    "CVE-2023-52795",
    "CVE-2023-52796",
    "CVE-2023-52798",
    "CVE-2023-52799",
    "CVE-2023-52800",
    "CVE-2023-52803",
    "CVE-2023-52804",
    "CVE-2023-52805",
    "CVE-2023-52806",
    "CVE-2023-52807",
    "CVE-2023-52808",
    "CVE-2023-52809",
    "CVE-2023-52810",
    "CVE-2023-52811",
    "CVE-2023-52814",
    "CVE-2023-52815",
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
    "CVE-2023-52851",
    "CVE-2023-52853",
    "CVE-2023-52854",
    "CVE-2023-52855",
    "CVE-2023-52856",
    "CVE-2023-52858",
    "CVE-2023-52860",
    "CVE-2023-52861",
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
    "CVE-2024-2201",
    "CVE-2024-26597",
    "CVE-2024-26643",
    "CVE-2024-26679",
    "CVE-2024-26692",
    "CVE-2024-26698",
    "CVE-2024-26700",
    "CVE-2024-26715",
    "CVE-2024-26739",
    "CVE-2024-26742",
    "CVE-2024-26748",
    "CVE-2024-26758",
    "CVE-2024-26764",
    "CVE-2024-26775",
    "CVE-2024-26777",
    "CVE-2024-26778",
    "CVE-2024-26788",
    "CVE-2024-26791",
    "CVE-2024-26801",
    "CVE-2024-26822",
    "CVE-2024-26828",
    "CVE-2024-26829",
    "CVE-2024-26838",
    "CVE-2024-26839",
    "CVE-2024-26840",
    "CVE-2024-26846",
    "CVE-2024-26859",
    "CVE-2024-26870",
    "CVE-2024-26874",
    "CVE-2024-26876",
    "CVE-2024-26877",
    "CVE-2024-26880",
    "CVE-2024-26889",
    "CVE-2024-26894",
    "CVE-2024-26900",
    "CVE-2024-26907",
    "CVE-2024-26915",
    "CVE-2024-26916",
    "CVE-2024-26919",
    "CVE-2024-26920",
    "CVE-2024-26921",
    "CVE-2024-26922",
    "CVE-2024-26925",
    "CVE-2024-26928",
    "CVE-2024-26929",
    "CVE-2024-26930",
    "CVE-2024-26931",
    "CVE-2024-26933",
    "CVE-2024-26934",
    "CVE-2024-26935",
    "CVE-2024-26937",
    "CVE-2024-26938",
    "CVE-2024-26939",
    "CVE-2024-26940",
    "CVE-2024-26943",
    "CVE-2024-26957",
    "CVE-2024-26958",
    "CVE-2024-26964",
    "CVE-2024-26974",
    "CVE-2024-26977",
    "CVE-2024-26979",
    "CVE-2024-26984",
    "CVE-2024-26988",
    "CVE-2024-26989",
    "CVE-2024-26994",
    "CVE-2024-26996",
    "CVE-2024-26997",
    "CVE-2024-26999",
    "CVE-2024-27000",
    "CVE-2024-27001",
    "CVE-2024-27004",
    "CVE-2024-27008",
    "CVE-2024-27028",
    "CVE-2024-27037",
    "CVE-2024-27042",
    "CVE-2024-27045",
    "CVE-2024-27047",
    "CVE-2024-27051",
    "CVE-2024-27052",
    "CVE-2024-27053",
    "CVE-2024-27054",
    "CVE-2024-27059",
    "CVE-2024-27072",
    "CVE-2024-27073",
    "CVE-2024-27074",
    "CVE-2024-27075",
    "CVE-2024-27076",
    "CVE-2024-27077",
    "CVE-2024-27078",
    "CVE-2024-27388",
    "CVE-2024-27393",
    "CVE-2024-27395",
    "CVE-2024-27396",
    "CVE-2024-27398",
    "CVE-2024-27399",
    "CVE-2024-27400",
    "CVE-2024-27401",
    "CVE-2024-27405",
    "CVE-2024-27410",
    "CVE-2024-27412",
    "CVE-2024-27413",
    "CVE-2024-27416",
    "CVE-2024-27417",
    "CVE-2024-27419",
    "CVE-2024-27431",
    "CVE-2024-27435",
    "CVE-2024-27436",
    "CVE-2024-35789",
    "CVE-2024-35791",
    "CVE-2024-35796",
    "CVE-2024-35799",
    "CVE-2024-35801",
    "CVE-2024-35804",
    "CVE-2024-35806",
    "CVE-2024-35809",
    "CVE-2024-35811",
    "CVE-2024-35812",
    "CVE-2024-35813",
    "CVE-2024-35815",
    "CVE-2024-35817",
    "CVE-2024-35821",
    "CVE-2024-35822",
    "CVE-2024-35823",
    "CVE-2024-35825",
    "CVE-2024-35828",
    "CVE-2024-35829",
    "CVE-2024-35830",
    "CVE-2024-35833",
    "CVE-2024-35845",
    "CVE-2024-35847",
    "CVE-2024-35849",
    "CVE-2024-35851",
    "CVE-2024-35852",
    "CVE-2024-35854",
    "CVE-2024-35860",
    "CVE-2024-35861",
    "CVE-2024-35862",
    "CVE-2024-35863",
    "CVE-2024-35864",
    "CVE-2024-35865",
    "CVE-2024-35866",
    "CVE-2024-35867",
    "CVE-2024-35868",
    "CVE-2024-35869",
    "CVE-2024-35870",
    "CVE-2024-35872",
    "CVE-2024-35875",
    "CVE-2024-35877",
    "CVE-2024-35878",
    "CVE-2024-35879",
    "CVE-2024-35885",
    "CVE-2024-35887",
    "CVE-2024-35895",
    "CVE-2024-35901",
    "CVE-2024-35904",
    "CVE-2024-35905",
    "CVE-2024-35907",
    "CVE-2024-35912",
    "CVE-2024-35914",
    "CVE-2024-35915",
    "CVE-2024-35922",
    "CVE-2024-35924",
    "CVE-2024-35930",
    "CVE-2024-35932",
    "CVE-2024-35933",
    "CVE-2024-35935",
    "CVE-2024-35936",
    "CVE-2024-35938",
    "CVE-2024-35939",
    "CVE-2024-35940",
    "CVE-2024-35943",
    "CVE-2024-35944",
    "CVE-2024-35947",
    "CVE-2024-35950",
    "CVE-2024-35951",
    "CVE-2024-35952",
    "CVE-2024-35955",
    "CVE-2024-35959",
    "CVE-2024-35963",
    "CVE-2024-35964",
    "CVE-2024-35965",
    "CVE-2024-35966",
    "CVE-2024-35967",
    "CVE-2024-35969",
    "CVE-2024-35973",
    "CVE-2024-35976",
    "CVE-2024-35978",
    "CVE-2024-35982",
    "CVE-2024-35984",
    "CVE-2024-35989",
    "CVE-2024-35990",
    "CVE-2024-35998",
    "CVE-2024-35999",
    "CVE-2024-36006",
    "CVE-2024-36007",
    "CVE-2024-36012",
    "CVE-2024-36014",
    "CVE-2024-36015",
    "CVE-2024-36016",
    "CVE-2024-36026",
    "CVE-2024-36029",
    "CVE-2024-36032",
    "CVE-2024-36880",
    "CVE-2024-36893",
    "CVE-2024-36896",
    "CVE-2024-36897",
    "CVE-2024-36906",
    "CVE-2024-36918",
    "CVE-2024-36924",
    "CVE-2024-36926",
    "CVE-2024-36928",
    "CVE-2024-36931",
    "CVE-2024-36938",
    "CVE-2024-36940",
    "CVE-2024-36941",
    "CVE-2024-36942",
    "CVE-2024-36944",
    "CVE-2024-36947",
    "CVE-2024-36950",
    "CVE-2024-36952",
    "CVE-2024-36955",
    "CVE-2024-36959"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2190-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2024:2190-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:2190-1 advisory.

    The SUSE Linux Enterprise 15 SP5 kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2021-47548: Fixed a possible array out-of=bounds (bsc#1225506)
    - CVE-2022-48689: Fixed data-race in lru_add_fn (bsc#1223959)
    - CVE-2022-48691: Fixed memory leak in netfilter (bsc#1223961)
    - CVE-2023-1829: Fixed a use-after-free vulnerability in the control index filter (tcindex) (bsc#1210335).
    - CVE-2023-42755: Check user supplied offsets (bsc#1215702).
    - CVE-2023-52586: Fixed  mutex lock in control vblank irq (bsc#1221081).
    - CVE-2023-52618: Fixed string overflow in block/rnbd-srv (bsc#1221615).
    - CVE-2023-52655: Check packet for fixup for true limit (bsc#1217169).
    - CVE-2023-52656: Dropped any code related to SCM_RIGHTS (bsc#1224187).
    - CVE-2023-52660: Fiedx IRQ handling due to shared interrupts  (bsc#1224443).
    - CVE-2023-52664: Eliminate double free in error handling logic  (bsc#1224747).
    - CVE-2023-52671: Fixed hang/underflow when transitioning to ODM4:1 (bsc#1224729).
    - CVE-2023-52674: Add clamp() in scarlett2_mixer_ctl_put()  (bsc#1224727).
    - CVE-2023-52680: Fixed missing error checks to *_ctl_get()  (bsc#1224608).
    - CVE-2023-52692: Fixed missing error check to  scarlett2_usb_set_config() (bsc#1224628).
    - CVE-2023-52698: Fixed memory leak in netlbl_calipso_add_pass()  (bsc#1224621)
    - CVE-2023-52746: Prevent potential spectre v1 gadget in xfrm_xlate32_attr()  (bsc#1225114)
    - CVE-2023-52757: Fixed potential deadlock when releasing mids  (bsc#1225548).
    - CVE-2023-52795: Fixed use after free in vhost_vdpa_probe()  (bsc#1225085).
    - CVE-2023-52796: Add ipvlan_route_v6_outbound() helper (bsc#1224930).
    - CVE-2023-52807: Fixed out-of-bounds access may occur when coalesce  info is read via debugfs
    (bsc#1225097).
    - CVE-2023-52860: Fixed null pointer dereference in hisi_hns3 (bsc#1224936).
    - CVE-2023-6531: Fixed a use-after-free flaw due to a race problem in the unix garbage collector's
    deletion of SKB races with unix_stream_read_generic()on the socket that the SKB is queued on
    (bsc#1218447).
    - CVE-2024-2201: Fixed information leak in x86/BHI (bsc#1217339).
    - CVE-2024-26643: Fixed mark set as dead when unbinding anonymous  set with timeout (bsc#1221829).
    - CVE-2024-26679: Fixed read sk->sk_family once in inet_recv_error() (bsc#1222385).
    - CVE-2024-26692: Fixed regression in writes when non-standard maximum write  size negotiated
    (bsc#1222464).
    - CVE-2024-26700: Fixed drm/amd/display: Fix MST Null Ptr for RV (bsc#1222870)
    - CVE-2024-26715: Fixed NULL pointer dereference in  dwc3_gadget_suspend (bsc#1222561).
    - CVE-2024-26742: Fixed disable_managed_interrupts (git-fixes  bsc#1222608).
    - CVE-2024-26775: Fixed potential deadlock at set_capacity (bsc#1222627).
    - CVE-2024-26777: Error out if pixclock equals zero in fbdev/sis (bsc#1222765)
    - CVE-2024-26778: Error out if pixclock equals zero in fbdev/savage (bsc#1222770)
    - CVE-2024-26791: Fixed properly validate device names in btrfs (bsc#1222793)
    - CVE-2024-26822: Set correct id, uid and cruid for multiuser  automounts (bsc#1223011).
    - CVE-2024-26828: Fixed underflow in parse_server_interfaces() (bsc#1223084).
    - CVE-2024-26839: Fixed a memleak in init_credit_return() (bsc#1222975)
    - CVE-2024-26876: Fixed crash on irq during probe (bsc#1223119).
    - CVE-2024-26900: Fixed kmemleak of rdev->serial (bsc#1223046).
    - CVE-2024-26907: Fixed a fortify source warning while accessing Eth segment in mlx5 (bsc#1223203).
    - CVE-2024-26915: Reset IH OVERFLOW_CLEAR bit (bsc#1223207)
    - CVE-2024-26919: Fixed debugfs directory leak (bsc#1223847).
    - CVE-2024-26921: Preserve kabi for sk_buff (bsc#1223138).
    - CVE-2024-26925: Release mutex after nft_gc_seq_end from abort path (bsc#1223390).
    - CVE-2024-26928: Fixed potential UAF in cifs_debug_files_proc_show() (bsc#1223532).
    - CVE-2024-26939: Fixed UAF on destroy against retire race (bsc#1223679).
    - CVE-2024-26958: Fixed UAF in direct writes (bsc#1223653).
    - CVE-2024-27042: Fixed potential out-of-bounds access in 'amdgpu_discovery_reg_base_init()'
    (bsc#1223823).
    - CVE-2024-27395: Fixed Use-After-Free in ovs_ct_exit (bsc#1224098).
    - CVE-2024-27396: Fixed Use-After-Free in gtp_dellink (bsc#1224096).
    - CVE-2024-27398: Fixed use-after-free bugs caused by sco_sock_timeout (bsc#1224174).
    - CVE-2024-27401: Fixed user_length taken into account when  fetching packet contents (bsc#1224181).
    - CVE-2024-27413: Fixed incorrect allocation size (bsc#1224438).
    - CVE-2024-27417: Fixed potential 'struct net' leak in inet6_rtm_getaddr()  (bsc#1224721)
    - CVE-2024-27419: Fixed data-races around sysctl_net_busy_read  (bsc#1224759)
    - CVE-2024-27431: Zero-initialise xdp_rxq_info struct before running  XDP program (bsc#1224718).
    - CVE-2024-35791: Flush pages under kvm->lock to fix UAF in  svm_register_enc_region() (bsc#1224725).
    - CVE-2024-35799: Prevent crash when disable stream (bsc#1224740).
    - CVE-2024-35804: Mark target gfn of emulated atomic instruction as  dirty (bsc#1224638).
    - CVE-2024-35817: Set gtt bound flag in amdgpu_ttm_gart_bind (bsc#1224736).
    - CVE-2024-35852: Fixed memory leak when canceling rehash  work (bsc#1224502).
    - CVE-2024-35854: Fixed possible use-after-free during  rehash (bsc#1224636).
    - CVE-2024-35860: Struct bpf_link and bpf_link_ops kABI workaround  (bsc#1224531).
    - CVE-2024-35861: Fixed potential UAF in  cifs_signal_cifsd_for_reconnect() (bsc#1224766).
    - CVE-2024-35862: Fixed potential UAF in smb2_is_network_name_deleted()  (bsc#1224764).
    - CVE-2024-35863: Fixed potential UAF in is_valid_oplock_break() (bsc#1224763).
    - CVE-2024-35864: Fixed potential UAF in smb2_is_valid_lease_break()  (bsc#1224765,).
    - CVE-2024-35865: Fixed potential UAF in smb2_is_valid_oplock_break()  (bsc#1224668).
    - CVE-2024-35866: Fixed potential UAF in cifs_dump_full_key()  (bsc#1224667).
    - CVE-2024-35867: Fixed potential UAF in cifs_stats_proc_show() (bsc#1224664).
    - CVE-2024-35868: Fixed potential UAF in cifs_stats_proc_write() (bsc#1224678).
    - CVE-2024-35869: Guarantee refcounted children from parent session  (bsc#1224679).
    - CVE-2024-35870: Fixed UAF in smb2_reconnect_server() (bsc#1224020,  bsc#1224672).
    - CVE-2024-35872: Fixed GUP-fast succeeding on secretmem folios  (bsc#1224530).
    - CVE-2024-35875: Require seeding RNG with RDRAND on CoCo systems (bsc#1224665).
    - CVE-2024-35877: Fixed VM_PAT handling in COW mappings (bsc#1224525).
    - CVE-2024-35878: Prevent NULL pointer dereference in vsnprintf()  (bsc#1224671).
    - CVE-2024-35879: kABI workaround for drivers/of/dynamic.c (bsc#1224524).
    - CVE-2024-35885: Stop interface during shutdown (bsc#1224519).
    - CVE-2024-35904: Fixed dereference of garbage after mount failure (bsc#1224494).
    - CVE-2024-35905: Fixed int overflow for stack access size  (bsc#1224488).
    - CVE-2024-35907: Call request_irq() after NAPI initialized  (bsc#1224492).
    - CVE-2024-35924: Limit read size on v1.2 (bsc#1224657).
    - CVE-2024-35939: Fixed leak pages on dma_set_decrypted() failure (bsc#1224535).
    - CVE-2024-35943: Fixed a null pointer dereference in omap_prm_domain_init (bsc#1224649).
    - CVE-2024-35944: Fixed memcpy() run-time warning in dg_dispatch_as_host()  (bsc#1224648).
    - CVE-2024-35951: Fixed the error path in panfrost_mmu_map_fault_addr() (bsc#1224701).
    - CVE-2024-35959: Fixed mlx5e_priv_init() cleanup flow (bsc#1224666).
    - CVE-2024-35964: Fixed not validating setsockopt user input  (bsc#1224581).
    - CVE-2024-35969: Fixed race condition between ipv6_get_ifaddr and ipv6_del_addr  (bsc#1224580).
    - CVE-2024-35973: Fixed header validation in geneve[6]_xmit_skb  (bsc#1224586).
    - CVE-2024-35976: Validate user input for XDP_{UMEM|COMPLETION}_FILL_RING  (bsc#1224575).
    - CVE-2024-35998: Fixed lock ordering potential deadlock in  cifs_sync_mid_result (bsc#1224549).
    - CVE-2024-35999: Fixed missing lock when picking channel (bsc#1224550).
    - CVE-2024-36006: Fixed incorrect list API usage  (bsc#1224541).
    - CVE-2024-36007: Fixed warning during rehash  (bsc#1224543).
    - CVE-2024-36938: Fixed NULL pointer dereference in  sk_psock_skb_ingress_enqueue (bsc#1225761).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.suse.com/support/update/announcement/2024/suse-su-20242190-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d90a2d1");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035732.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43527");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43527");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/26");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150500_55_68-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"generated_plugin", value:"former");
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
    {'reference':'kernel-64kb-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.68.1.150500.6.31.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.68.1.150500.6.31.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.68.1.150500.6.31.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.68.1.150500.6.31.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-extra-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-default-extra-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'s390x', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'reiserfs-kmp-default-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.68.1.150500.6.31.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.68.1.150500.6.31.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.68.1.150500.6.31.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.68.1.150500.6.31.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'reiserfs-kmp-default-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-legacy-release-15.5', 'sles-release-15.5']},
    {'reference':'cluster-md-kmp-64kb-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-64kb-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-allwinner-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-altera-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-amazon-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-amd-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-amlogic-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-apm-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-apple-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-arm-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-broadcom-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-cavium-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-exynos-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-freescale-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-hisilicon-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-lg-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-marvell-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-mediatek-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-nvidia-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-qcom-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-renesas-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-rockchip-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-socionext-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-sprd-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dtb-xilinx-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-64kb-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-64kb-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-64kb-devel-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-64kb-extra-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-64kb-livepatch-devel-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-64kb-optional-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-debug-5.14.21-150500.55.68.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-debug-devel-5.14.21-150500.55.68.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-debug-livepatch-devel-5.14.21-150500.55.68.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-debug-vdso-5.14.21-150500.55.68.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.68.1.150500.6.31.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-base-5.14.21-150500.55.68.1.150500.6.31.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-base-rebuild-5.14.21-150500.55.68.1.150500.6.31.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-base-rebuild-5.14.21-150500.55.68.1.150500.6.31.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-devel-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-extra-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-livepatch-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-livepatch-devel-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-optional-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-default-vdso-5.14.21-150500.55.68.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-devel-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-kvmsmall-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-kvmsmall-5.14.21-150500.55.68.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-kvmsmall-devel-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-kvmsmall-devel-5.14.21-150500.55.68.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-kvmsmall-livepatch-devel-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-kvmsmall-livepatch-devel-5.14.21-150500.55.68.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-kvmsmall-vdso-5.14.21-150500.55.68.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-macros-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-obs-build-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-obs-qa-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-source-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-source-vanilla-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-zfcpdump-5.14.21-150500.55.68.1', 'cpu':'s390x', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-64kb-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-default-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-64kb-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-64kb-5.14.21-150500.55.68.1', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-default-5.14.21-150500.55.68.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'cluster-md-kmp-default-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.5']},
    {'reference':'dlm-kmp-default-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.5']},
    {'reference':'gfs2-kmp-default-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.5']},
    {'reference':'ocfs2-kmp-default-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.5']},
    {'reference':'kernel-default-livepatch-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']},
    {'reference':'kernel-default-livepatch-devel-5.14.21-150500.55.68.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']},
    {'reference':'kernel-livepatch-5_14_21-150500_55_68-default-1-150500.11.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']},
    {'reference':'kernel-default-extra-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'kernel-default-extra-5.14.21-150500.55.68.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-15.5', 'sled-release-15.5', 'sles-release-15.5']}
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
