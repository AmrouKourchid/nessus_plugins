#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2008-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(200462);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2020-36788",
    "CVE-2021-4148",
    "CVE-2021-39698",
    "CVE-2021-42327",
    "CVE-2021-43056",
    "CVE-2021-43527",
    "CVE-2021-47200",
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
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2008-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2024:2008-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:2008-1 advisory.

    The SUSE Linux Enterprise 15 SP5 RT kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2021-47548: Fixed a possible array out-of=bounds (bsc#1225506)
    - CVE-2022-48689: Fixed data-race in lru_add_fn (bsc#1223959)
    - CVE-2022-48691: Fixed memory leak in netfilter (bsc#1223961)
    - CVE-2023-1829: Fixed a use-after-free vulnerability in the control index filter (tcindex) (bsc#1210335).
    - CVE-2023-42755: Check user supplied offsets (bsc#1215702).
    - CVE-2023-52586: Fixed  mutex lock in control vblank irq (bsc#1221081).
    - CVE-2023-52618: Fixed string overflow in block/rnbd-srv (bsc#1221615).
    - CVE-2023-52656: Dropped any code related to SCM_RIGHTS (bsc#1224187).
    - CVE-2023-52660: Fiedx IRQ handling due to shared interrupts  (bsc#1224443).
    - CVE-2023-52664: Eliminate double free in error handling logic  (bsc#1224747).
    - CVE-2023-52671: Fixed hang/underflow when transitioning to ODM4:1 (bsc#1224729).
    - CVE-2023-52674: Add clamp() in scarlett2_mixer_ctl_put()  (bsc#1224727).
    - CVE-2023-52680: Fixed missing error checks to *_ctl_get()  (bsc#1224608).
    - CVE-2023-52692: Fixed missing error check to  scarlett2_usb_set_config() (bsc#1224628).
    - CVE-2023-52698: Fixed memory leak in netlbl_calipso_add_pass()  (CVE-2023-52698 bsc#1224621)
    - CVE-2023-52746: Prevent potential spectre v1 gadget in xfrm_xlate32_attr()  (bsc#1225114)
    - CVE-2023-52757: Fixed potential deadlock when releasing mids  (bsc#1225548).
    - CVE-2023-52795: Fixed use after free in vhost_vdpa_probe()  (bsc#1225085).
    - CVE-2023-52796: Add ipvlan_route_v6_outbound() helper (bsc#1224930).
    - CVE-2023-52807: Fixed out-of-bounds access may occur when coalesce  info is read via debugfs
    (bsc#1225097).
    - CVE-2023-52860: Fixed null pointer dereference in hisi_hns3 (bsc#1224936).
    - CVE-2024-2201: Fixed information leak in x86/BHI (bsc#1217339).
    - CVE-2024-26643: Fixed mark set as dead when unbinding anonymous  set with timeout (bsc#1221829).
    - CVE-2024-26679: Fixed read sk->sk_family once in inet_recv_error() (bsc#1222385).
    - CVE-2024-26692: Fixed regression in writes when non-standard maximum write  size negotiated
    (bsc#1222464).
    - CVE-2024-26715: Fixed NULL pointer dereference in  dwc3_gadget_suspend (bsc#1222561).
    - CVE-2024-26742: Fixed disable_managed_interrupts (git-fixes  bsc#1222608).
    - CVE-2024-26775: Fixed potential deadlock at set_capacity (bsc#1222627).
    - CVE-2024-26791: Fixed properly validate device names in btrfs (bsc#1222793)
    - CVE-2024-26822: Set correct id, uid and cruid for multiuser  automounts (bsc#1223011).
    - CVE-2024-26828: Fixed underflow in parse_server_interfaces() (bsc#1223084).
    - CVE-2024-26876: Fixed crash on irq during probe (bsc#1223119).
    - CVE-2024-26900: Fixed kmemleak of rdev->serial (bsc#1223046).
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
    - CVE-2024-27417: Fixed potential 'struct net' leak in inet6_rtm_getaddr()  (bsc#1224721)
    - CVE-2024-27419: Fixed data-races around sysctl_net_busy_read  (bsc#1224759)
    - CVE-2024-27431: Fixed Zero-initialise xdp_rxq_info struct before running  XDP program (bsc#1224718).
    - CVE-2024-35791: Flush pages under kvm->lock to fix UAF in  svm_register_enc_region() (bsc#1224725).
    - CVE-2024-35799: Prevent crash when disable stream (bsc#1224740).
    - CVE-2024-35804: Mark target gfn of emulated atomic instruction as  dirty (bsc#1224638).
    - CVE-2024-35852: Fixed memory leak when canceling rehash  work (bsc#1224502).
    - CVE-2024-35854: Fixed possible use-after-free during  rehash (bsc#1224636).
    - CVE-2024-35860: struct bpf_link and bpf_link_ops kABI workaround  (bsc#1224531).
    - CVE-2024-35861: Fixed potential UAF in  cifs_signal_cifsd_for_reconnect() (bsc#1224766).
    - CVE-2024-35862: Fixed potential UAF in smb2_is_network_name_deleted()  (bsc#1224764).
    - CVE-2024-35863: Fixed potential UAF in is_valid_oplock_break() (bsc#1224763).
    - CVE-2024-35864: Fixed potential UAF in smb2_is_valid_lease_break()  (bsc#1224765).
    - CVE-2024-35865: Fixed potential UAF in smb2_is_valid_oplock_break()  (bsc#1224668).
    - CVE-2024-35866: Fixed potential UAF in cifs_dump_full_key()  (bsc#1224667).
    - CVE-2024-35867: Fixed potential UAF in cifs_stats_proc_show() (bsc#1224664).
    - CVE-2024-35868: Fixed potential UAF in cifs_stats_proc_write() (bsc#1224678).
    - CVE-2024-35869: Guarantee refcounted children from parent session  (bsc#1224679).
    - CVE-2024-35870: Fixed UAF in smb2_reconnect_server() (bsc#1224672).
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209980");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210335");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222464");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223043");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223119");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224676");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224733");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224803");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225114");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225139");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225222");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225382");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225444");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225480");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225842");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035569.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42327");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43527");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47200");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47504");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47506");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47508");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47510");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47511");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47512");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47530");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47533");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47534");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47537");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47540");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47542");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47544");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47549");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47550");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47551");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47552");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47553");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47554");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47555");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47556");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47557");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47558");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47559");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47560");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47562");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47563");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47564");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48689");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48699");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48705");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48709");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48710");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6531");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-42755");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47233");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52618");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52654");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52683");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52694");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52699");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52705");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52731");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52732");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52757");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52781");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52795");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52799");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52806");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52808");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52815");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52861");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-2201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26700");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26758");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26778");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26801");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26822");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26839");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26876");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26994");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27037");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27047");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27052");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27053");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27054");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27072");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27075");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27388");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27393");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27395");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27396");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27398");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27399");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27400");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27401");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27405");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27410");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27412");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27413");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27416");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27417");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27419");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27431");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35799");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35801");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35806");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35822");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35825");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35830");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35833");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35869");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35963");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36026");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36029");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36032");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36959");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43527");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150500_13_58-rt");
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
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'dlm-kmp-rt-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'gfs2-kmp-rt-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-devel-rt-5.14.21-150500.13.58.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-devel-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-extra-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-livepatch-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-livepatch-devel-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-optional-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt-vdso-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-devel-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-livepatch-devel-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-rt_debug-vdso-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-source-rt-5.14.21-150500.13.58.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-syms-rt-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kselftests-kmp-rt-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'ocfs2-kmp-rt-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'reiserfs-kmp-rt-5.14.21-150500.13.58.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'kernel-livepatch-5_14_21-150500_13_58-rt-1-150500.11.3.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.5']}
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
