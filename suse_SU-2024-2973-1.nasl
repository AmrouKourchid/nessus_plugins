#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2973-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(206008);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/09");

  script_cve_id(
    "CVE-2021-47432",
    "CVE-2022-48772",
    "CVE-2023-0160",
    "CVE-2023-6238",
    "CVE-2023-7042",
    "CVE-2023-38417",
    "CVE-2023-47210",
    "CVE-2023-51780",
    "CVE-2023-52435",
    "CVE-2023-52458",
    "CVE-2023-52472",
    "CVE-2023-52503",
    "CVE-2023-52616",
    "CVE-2023-52618",
    "CVE-2023-52622",
    "CVE-2023-52631",
    "CVE-2023-52635",
    "CVE-2023-52640",
    "CVE-2023-52641",
    "CVE-2023-52645",
    "CVE-2023-52652",
    "CVE-2023-52653",
    "CVE-2023-52656",
    "CVE-2023-52657",
    "CVE-2023-52658",
    "CVE-2023-52659",
    "CVE-2023-52660",
    "CVE-2023-52661",
    "CVE-2023-52662",
    "CVE-2023-52663",
    "CVE-2023-52664",
    "CVE-2023-52667",
    "CVE-2023-52669",
    "CVE-2023-52670",
    "CVE-2023-52671",
    "CVE-2023-52672",
    "CVE-2023-52673",
    "CVE-2023-52674",
    "CVE-2023-52675",
    "CVE-2023-52676",
    "CVE-2023-52678",
    "CVE-2023-52679",
    "CVE-2023-52680",
    "CVE-2023-52681",
    "CVE-2023-52683",
    "CVE-2023-52685",
    "CVE-2023-52686",
    "CVE-2023-52687",
    "CVE-2023-52690",
    "CVE-2023-52691",
    "CVE-2023-52692",
    "CVE-2023-52693",
    "CVE-2023-52694",
    "CVE-2023-52695",
    "CVE-2023-52696",
    "CVE-2023-52697",
    "CVE-2023-52698",
    "CVE-2023-52699",
    "CVE-2023-52735",
    "CVE-2023-52749",
    "CVE-2023-52750",
    "CVE-2023-52751",
    "CVE-2023-52753",
    "CVE-2023-52754",
    "CVE-2023-52757",
    "CVE-2023-52759",
    "CVE-2023-52762",
    "CVE-2023-52763",
    "CVE-2023-52764",
    "CVE-2023-52765",
    "CVE-2023-52766",
    "CVE-2023-52767",
    "CVE-2023-52768",
    "CVE-2023-52769",
    "CVE-2023-52771",
    "CVE-2023-52772",
    "CVE-2023-52773",
    "CVE-2023-52774",
    "CVE-2023-52775",
    "CVE-2023-52776",
    "CVE-2023-52777",
    "CVE-2023-52780",
    "CVE-2023-52781",
    "CVE-2023-52782",
    "CVE-2023-52783",
    "CVE-2023-52784",
    "CVE-2023-52786",
    "CVE-2023-52787",
    "CVE-2023-52788",
    "CVE-2023-52789",
    "CVE-2023-52791",
    "CVE-2023-52792",
    "CVE-2023-52794",
    "CVE-2023-52795",
    "CVE-2023-52796",
    "CVE-2023-52798",
    "CVE-2023-52799",
    "CVE-2023-52800",
    "CVE-2023-52801",
    "CVE-2023-52803",
    "CVE-2023-52804",
    "CVE-2023-52805",
    "CVE-2023-52806",
    "CVE-2023-52807",
    "CVE-2023-52808",
    "CVE-2023-52809",
    "CVE-2023-52810",
    "CVE-2023-52811",
    "CVE-2023-52812",
    "CVE-2023-52813",
    "CVE-2023-52814",
    "CVE-2023-52815",
    "CVE-2023-52816",
    "CVE-2023-52817",
    "CVE-2023-52818",
    "CVE-2023-52819",
    "CVE-2023-52821",
    "CVE-2023-52825",
    "CVE-2023-52826",
    "CVE-2023-52827",
    "CVE-2023-52829",
    "CVE-2023-52832",
    "CVE-2023-52833",
    "CVE-2023-52834",
    "CVE-2023-52835",
    "CVE-2023-52836",
    "CVE-2023-52837",
    "CVE-2023-52838",
    "CVE-2023-52840",
    "CVE-2023-52841",
    "CVE-2023-52842",
    "CVE-2023-52843",
    "CVE-2023-52844",
    "CVE-2023-52845",
    "CVE-2023-52847",
    "CVE-2023-52849",
    "CVE-2023-52850",
    "CVE-2023-52851",
    "CVE-2023-52853",
    "CVE-2023-52854",
    "CVE-2023-52855",
    "CVE-2023-52856",
    "CVE-2023-52857",
    "CVE-2023-52858",
    "CVE-2023-52860",
    "CVE-2023-52861",
    "CVE-2023-52862",
    "CVE-2023-52863",
    "CVE-2023-52864",
    "CVE-2023-52865",
    "CVE-2023-52866",
    "CVE-2023-52867",
    "CVE-2023-52868",
    "CVE-2023-52869",
    "CVE-2023-52870",
    "CVE-2023-52871",
    "CVE-2023-52872",
    "CVE-2023-52873",
    "CVE-2023-52874",
    "CVE-2023-52875",
    "CVE-2023-52876",
    "CVE-2023-52877",
    "CVE-2023-52878",
    "CVE-2023-52879",
    "CVE-2023-52880",
    "CVE-2023-52881",
    "CVE-2023-52882",
    "CVE-2023-52883",
    "CVE-2023-52884",
    "CVE-2024-0639",
    "CVE-2024-21823",
    "CVE-2024-22099",
    "CVE-2024-23848",
    "CVE-2024-24861",
    "CVE-2024-25739",
    "CVE-2024-25741",
    "CVE-2024-26601",
    "CVE-2024-26611",
    "CVE-2024-26614",
    "CVE-2024-26615",
    "CVE-2024-26623",
    "CVE-2024-26625",
    "CVE-2024-26632",
    "CVE-2024-26633",
    "CVE-2024-26635",
    "CVE-2024-26636",
    "CVE-2024-26638",
    "CVE-2024-26641",
    "CVE-2024-26642",
    "CVE-2024-26643",
    "CVE-2024-26650",
    "CVE-2024-26652",
    "CVE-2024-26654",
    "CVE-2024-26656",
    "CVE-2024-26657",
    "CVE-2024-26663",
    "CVE-2024-26665",
    "CVE-2024-26671",
    "CVE-2024-26673",
    "CVE-2024-26674",
    "CVE-2024-26676",
    "CVE-2024-26679",
    "CVE-2024-26684",
    "CVE-2024-26685",
    "CVE-2024-26691",
    "CVE-2024-26704",
    "CVE-2024-26714",
    "CVE-2024-26726",
    "CVE-2024-26731",
    "CVE-2024-26733",
    "CVE-2024-26734",
    "CVE-2024-26737",
    "CVE-2024-26739",
    "CVE-2024-26740",
    "CVE-2024-26742",
    "CVE-2024-26750",
    "CVE-2024-26756",
    "CVE-2024-26758",
    "CVE-2024-26760",
    "CVE-2024-26761",
    "CVE-2024-26764",
    "CVE-2024-26767",
    "CVE-2024-26769",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26774",
    "CVE-2024-26775",
    "CVE-2024-26780",
    "CVE-2024-26783",
    "CVE-2024-26785",
    "CVE-2024-26786",
    "CVE-2024-26791",
    "CVE-2024-26793",
    "CVE-2024-26794",
    "CVE-2024-26802",
    "CVE-2024-26805",
    "CVE-2024-26807",
    "CVE-2024-26813",
    "CVE-2024-26814",
    "CVE-2024-26815",
    "CVE-2024-26816",
    "CVE-2024-26822",
    "CVE-2024-26826",
    "CVE-2024-26832",
    "CVE-2024-26836",
    "CVE-2024-26842",
    "CVE-2024-26844",
    "CVE-2024-26845",
    "CVE-2024-26846",
    "CVE-2024-26853",
    "CVE-2024-26854",
    "CVE-2024-26855",
    "CVE-2024-26856",
    "CVE-2024-26857",
    "CVE-2024-26858",
    "CVE-2024-26860",
    "CVE-2024-26861",
    "CVE-2024-26862",
    "CVE-2024-26863",
    "CVE-2024-26866",
    "CVE-2024-26868",
    "CVE-2024-26870",
    "CVE-2024-26878",
    "CVE-2024-26881",
    "CVE-2024-26882",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26885",
    "CVE-2024-26889",
    "CVE-2024-26899",
    "CVE-2024-26900",
    "CVE-2024-26901",
    "CVE-2024-26903",
    "CVE-2024-26906",
    "CVE-2024-26909",
    "CVE-2024-26920",
    "CVE-2024-26921",
    "CVE-2024-26922",
    "CVE-2024-26923",
    "CVE-2024-26925",
    "CVE-2024-26928",
    "CVE-2024-26932",
    "CVE-2024-26933",
    "CVE-2024-26934",
    "CVE-2024-26935",
    "CVE-2024-26937",
    "CVE-2024-26938",
    "CVE-2024-26940",
    "CVE-2024-26943",
    "CVE-2024-26944",
    "CVE-2024-26945",
    "CVE-2024-26946",
    "CVE-2024-26948",
    "CVE-2024-26949",
    "CVE-2024-26950",
    "CVE-2024-26951",
    "CVE-2024-26957",
    "CVE-2024-26958",
    "CVE-2024-26960",
    "CVE-2024-26961",
    "CVE-2024-26962",
    "CVE-2024-26963",
    "CVE-2024-26964",
    "CVE-2024-26972",
    "CVE-2024-26973",
    "CVE-2024-26978",
    "CVE-2024-26981",
    "CVE-2024-26982",
    "CVE-2024-26983",
    "CVE-2024-26984",
    "CVE-2024-26986",
    "CVE-2024-26988",
    "CVE-2024-26989",
    "CVE-2024-26990",
    "CVE-2024-26991",
    "CVE-2024-26992",
    "CVE-2024-26993",
    "CVE-2024-26994",
    "CVE-2024-26995",
    "CVE-2024-26996",
    "CVE-2024-26997",
    "CVE-2024-26999",
    "CVE-2024-27000",
    "CVE-2024-27001",
    "CVE-2024-27002",
    "CVE-2024-27003",
    "CVE-2024-27004",
    "CVE-2024-27008",
    "CVE-2024-27012",
    "CVE-2024-27013",
    "CVE-2024-27014",
    "CVE-2024-27015",
    "CVE-2024-27016",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27022",
    "CVE-2024-27025",
    "CVE-2024-27027",
    "CVE-2024-27028",
    "CVE-2024-27030",
    "CVE-2024-27031",
    "CVE-2024-27046",
    "CVE-2024-27056",
    "CVE-2024-27057",
    "CVE-2024-27062",
    "CVE-2024-27064",
    "CVE-2024-27065",
    "CVE-2024-27067",
    "CVE-2024-27080",
    "CVE-2024-27388",
    "CVE-2024-27389",
    "CVE-2024-27393",
    "CVE-2024-27395",
    "CVE-2024-27396",
    "CVE-2024-27399",
    "CVE-2024-27400",
    "CVE-2024-27401",
    "CVE-2024-27402",
    "CVE-2024-27404",
    "CVE-2024-27405",
    "CVE-2024-27408",
    "CVE-2024-27410",
    "CVE-2024-27411",
    "CVE-2024-27412",
    "CVE-2024-27413",
    "CVE-2024-27414",
    "CVE-2024-27416",
    "CVE-2024-27417",
    "CVE-2024-27418",
    "CVE-2024-27419",
    "CVE-2024-27431",
    "CVE-2024-27432",
    "CVE-2024-27434",
    "CVE-2024-27435",
    "CVE-2024-27436",
    "CVE-2024-33619",
    "CVE-2024-34777",
    "CVE-2024-35247",
    "CVE-2024-35784",
    "CVE-2024-35786",
    "CVE-2024-35788",
    "CVE-2024-35789",
    "CVE-2024-35790",
    "CVE-2024-35791",
    "CVE-2024-35794",
    "CVE-2024-35795",
    "CVE-2024-35796",
    "CVE-2024-35799",
    "CVE-2024-35800",
    "CVE-2024-35801",
    "CVE-2024-35803",
    "CVE-2024-35804",
    "CVE-2024-35805",
    "CVE-2024-35806",
    "CVE-2024-35807",
    "CVE-2024-35808",
    "CVE-2024-35809",
    "CVE-2024-35810",
    "CVE-2024-35811",
    "CVE-2024-35812",
    "CVE-2024-35813",
    "CVE-2024-35814",
    "CVE-2024-35815",
    "CVE-2024-35817",
    "CVE-2024-35819",
    "CVE-2024-35821",
    "CVE-2024-35822",
    "CVE-2024-35823",
    "CVE-2024-35824",
    "CVE-2024-35825",
    "CVE-2024-35827",
    "CVE-2024-35828",
    "CVE-2024-35829",
    "CVE-2024-35830",
    "CVE-2024-35831",
    "CVE-2024-35833",
    "CVE-2024-35834",
    "CVE-2024-35835",
    "CVE-2024-35836",
    "CVE-2024-35837",
    "CVE-2024-35838",
    "CVE-2024-35841",
    "CVE-2024-35842",
    "CVE-2024-35843",
    "CVE-2024-35845",
    "CVE-2024-35847",
    "CVE-2024-35848",
    "CVE-2024-35849",
    "CVE-2024-35850",
    "CVE-2024-35851",
    "CVE-2024-35852",
    "CVE-2024-35853",
    "CVE-2024-35854",
    "CVE-2024-35857",
    "CVE-2024-35860",
    "CVE-2024-35861",
    "CVE-2024-35862",
    "CVE-2024-35863",
    "CVE-2024-35864",
    "CVE-2024-35865",
    "CVE-2024-35866",
    "CVE-2024-35867",
    "CVE-2024-35868",
    "CVE-2024-35872",
    "CVE-2024-35875",
    "CVE-2024-35877",
    "CVE-2024-35878",
    "CVE-2024-35879",
    "CVE-2024-35880",
    "CVE-2024-35883",
    "CVE-2024-35884",
    "CVE-2024-35885",
    "CVE-2024-35886",
    "CVE-2024-35887",
    "CVE-2024-35889",
    "CVE-2024-35890",
    "CVE-2024-35891",
    "CVE-2024-35892",
    "CVE-2024-35893",
    "CVE-2024-35895",
    "CVE-2024-35896",
    "CVE-2024-35898",
    "CVE-2024-35899",
    "CVE-2024-35900",
    "CVE-2024-35901",
    "CVE-2024-35903",
    "CVE-2024-35904",
    "CVE-2024-35905",
    "CVE-2024-35907",
    "CVE-2024-35908",
    "CVE-2024-35909",
    "CVE-2024-35911",
    "CVE-2024-35912",
    "CVE-2024-35914",
    "CVE-2024-35915",
    "CVE-2024-35916",
    "CVE-2024-35917",
    "CVE-2024-35921",
    "CVE-2024-35922",
    "CVE-2024-35924",
    "CVE-2024-35925",
    "CVE-2024-35926",
    "CVE-2024-35927",
    "CVE-2024-35928",
    "CVE-2024-35930",
    "CVE-2024-35931",
    "CVE-2024-35932",
    "CVE-2024-35933",
    "CVE-2024-35934",
    "CVE-2024-35935",
    "CVE-2024-35936",
    "CVE-2024-35937",
    "CVE-2024-35938",
    "CVE-2024-35940",
    "CVE-2024-35942",
    "CVE-2024-35943",
    "CVE-2024-35944",
    "CVE-2024-35945",
    "CVE-2024-35946",
    "CVE-2024-35947",
    "CVE-2024-35950",
    "CVE-2024-35951",
    "CVE-2024-35952",
    "CVE-2024-35953",
    "CVE-2024-35954",
    "CVE-2024-35955",
    "CVE-2024-35956",
    "CVE-2024-35957",
    "CVE-2024-35958",
    "CVE-2024-35959",
    "CVE-2024-35960",
    "CVE-2024-35961",
    "CVE-2024-35962",
    "CVE-2024-35963",
    "CVE-2024-35964",
    "CVE-2024-35965",
    "CVE-2024-35966",
    "CVE-2024-35967",
    "CVE-2024-35969",
    "CVE-2024-35970",
    "CVE-2024-35971",
    "CVE-2024-35972",
    "CVE-2024-35973",
    "CVE-2024-35974",
    "CVE-2024-35975",
    "CVE-2024-35976",
    "CVE-2024-35977",
    "CVE-2024-35978",
    "CVE-2024-35979",
    "CVE-2024-35981",
    "CVE-2024-35982",
    "CVE-2024-35984",
    "CVE-2024-35986",
    "CVE-2024-35989",
    "CVE-2024-35990",
    "CVE-2024-35991",
    "CVE-2024-35992",
    "CVE-2024-35995",
    "CVE-2024-35997",
    "CVE-2024-35998",
    "CVE-2024-35999",
    "CVE-2024-36002",
    "CVE-2024-36003",
    "CVE-2024-36004",
    "CVE-2024-36005",
    "CVE-2024-36006",
    "CVE-2024-36007",
    "CVE-2024-36008",
    "CVE-2024-36009",
    "CVE-2024-36010",
    "CVE-2024-36011",
    "CVE-2024-36012",
    "CVE-2024-36013",
    "CVE-2024-36014",
    "CVE-2024-36015",
    "CVE-2024-36016",
    "CVE-2024-36017",
    "CVE-2024-36018",
    "CVE-2024-36019",
    "CVE-2024-36020",
    "CVE-2024-36021",
    "CVE-2024-36024",
    "CVE-2024-36025",
    "CVE-2024-36026",
    "CVE-2024-36029",
    "CVE-2024-36030",
    "CVE-2024-36032",
    "CVE-2024-36281",
    "CVE-2024-36477",
    "CVE-2024-36478",
    "CVE-2024-36479",
    "CVE-2024-36880",
    "CVE-2024-36882",
    "CVE-2024-36885",
    "CVE-2024-36887",
    "CVE-2024-36889",
    "CVE-2024-36890",
    "CVE-2024-36891",
    "CVE-2024-36893",
    "CVE-2024-36894",
    "CVE-2024-36895",
    "CVE-2024-36896",
    "CVE-2024-36897",
    "CVE-2024-36898",
    "CVE-2024-36899",
    "CVE-2024-36900",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36903",
    "CVE-2024-36904",
    "CVE-2024-36906",
    "CVE-2024-36909",
    "CVE-2024-36910",
    "CVE-2024-36911",
    "CVE-2024-36912",
    "CVE-2024-36913",
    "CVE-2024-36914",
    "CVE-2024-36915",
    "CVE-2024-36916",
    "CVE-2024-36917",
    "CVE-2024-36918",
    "CVE-2024-36919",
    "CVE-2024-36921",
    "CVE-2024-36922",
    "CVE-2024-36923",
    "CVE-2024-36924",
    "CVE-2024-36926",
    "CVE-2024-36928",
    "CVE-2024-36930",
    "CVE-2024-36931",
    "CVE-2024-36934",
    "CVE-2024-36935",
    "CVE-2024-36936",
    "CVE-2024-36937",
    "CVE-2024-36938",
    "CVE-2024-36940",
    "CVE-2024-36942",
    "CVE-2024-36944",
    "CVE-2024-36945",
    "CVE-2024-36946",
    "CVE-2024-36947",
    "CVE-2024-36949",
    "CVE-2024-36950",
    "CVE-2024-36951",
    "CVE-2024-36952",
    "CVE-2024-36955",
    "CVE-2024-36957",
    "CVE-2024-36959",
    "CVE-2024-36960",
    "CVE-2024-36962",
    "CVE-2024-36964",
    "CVE-2024-36965",
    "CVE-2024-36967",
    "CVE-2024-36969",
    "CVE-2024-36971",
    "CVE-2024-36972",
    "CVE-2024-36973",
    "CVE-2024-36975",
    "CVE-2024-36977",
    "CVE-2024-36978",
    "CVE-2024-37021",
    "CVE-2024-37078",
    "CVE-2024-37353",
    "CVE-2024-37354",
    "CVE-2024-38381",
    "CVE-2024-38384",
    "CVE-2024-38385",
    "CVE-2024-38388",
    "CVE-2024-38390",
    "CVE-2024-38391",
    "CVE-2024-38539",
    "CVE-2024-38540",
    "CVE-2024-38541",
    "CVE-2024-38543",
    "CVE-2024-38544",
    "CVE-2024-38546",
    "CVE-2024-38547",
    "CVE-2024-38548",
    "CVE-2024-38549",
    "CVE-2024-38550",
    "CVE-2024-38551",
    "CVE-2024-38552",
    "CVE-2024-38553",
    "CVE-2024-38554",
    "CVE-2024-38555",
    "CVE-2024-38556",
    "CVE-2024-38557",
    "CVE-2024-38558",
    "CVE-2024-38562",
    "CVE-2024-38564",
    "CVE-2024-38565",
    "CVE-2024-38566",
    "CVE-2024-38567",
    "CVE-2024-38568",
    "CVE-2024-38569",
    "CVE-2024-38570",
    "CVE-2024-38571",
    "CVE-2024-38572",
    "CVE-2024-38573",
    "CVE-2024-38575",
    "CVE-2024-38578",
    "CVE-2024-38579",
    "CVE-2024-38580",
    "CVE-2024-38581",
    "CVE-2024-38582",
    "CVE-2024-38583",
    "CVE-2024-38586",
    "CVE-2024-38587",
    "CVE-2024-38588",
    "CVE-2024-38590",
    "CVE-2024-38591",
    "CVE-2024-38592",
    "CVE-2024-38594",
    "CVE-2024-38595",
    "CVE-2024-38597",
    "CVE-2024-38598",
    "CVE-2024-38599",
    "CVE-2024-38600",
    "CVE-2024-38601",
    "CVE-2024-38602",
    "CVE-2024-38603",
    "CVE-2024-38604",
    "CVE-2024-38605",
    "CVE-2024-38608",
    "CVE-2024-38610",
    "CVE-2024-38611",
    "CVE-2024-38615",
    "CVE-2024-38616",
    "CVE-2024-38617",
    "CVE-2024-38618",
    "CVE-2024-38619",
    "CVE-2024-38621",
    "CVE-2024-38622",
    "CVE-2024-38627",
    "CVE-2024-38628",
    "CVE-2024-38629",
    "CVE-2024-38630",
    "CVE-2024-38633",
    "CVE-2024-38634",
    "CVE-2024-38635",
    "CVE-2024-38636",
    "CVE-2024-38659",
    "CVE-2024-38661",
    "CVE-2024-38663",
    "CVE-2024-38664",
    "CVE-2024-38780",
    "CVE-2024-39276",
    "CVE-2024-39277",
    "CVE-2024-39291",
    "CVE-2024-39296",
    "CVE-2024-39301",
    "CVE-2024-39362",
    "CVE-2024-39371",
    "CVE-2024-39463",
    "CVE-2024-39466",
    "CVE-2024-39468",
    "CVE-2024-39469",
    "CVE-2024-39471",
    "CVE-2024-39472",
    "CVE-2024-39473",
    "CVE-2024-39474",
    "CVE-2024-39475",
    "CVE-2024-39479",
    "CVE-2024-39481",
    "CVE-2024-39482",
    "CVE-2024-39487",
    "CVE-2024-39490",
    "CVE-2024-39494",
    "CVE-2024-39496",
    "CVE-2024-39498",
    "CVE-2024-39502",
    "CVE-2024-39504",
    "CVE-2024-39507",
    "CVE-2024-40901",
    "CVE-2024-40906",
    "CVE-2024-40908",
    "CVE-2024-40919",
    "CVE-2024-40923",
    "CVE-2024-40925",
    "CVE-2024-40928",
    "CVE-2024-40931",
    "CVE-2024-40935",
    "CVE-2024-40937",
    "CVE-2024-40940",
    "CVE-2024-40947",
    "CVE-2024-40948",
    "CVE-2024-40953",
    "CVE-2024-40960",
    "CVE-2024-40961",
    "CVE-2024-40966",
    "CVE-2024-40970",
    "CVE-2024-40972",
    "CVE-2024-40975",
    "CVE-2024-40979",
    "CVE-2024-40998",
    "CVE-2024-40999",
    "CVE-2024-41006",
    "CVE-2024-41011",
    "CVE-2024-41013",
    "CVE-2024-41014",
    "CVE-2024-41017",
    "CVE-2024-41090",
    "CVE-2024-41091"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2973-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2024:2973-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:2973-1 advisory.

    The SUSE Linux Enterprise 15 SP6 RT kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2023-0160: Fixed deadlock flaw in BPF that could allow a local user to potentially crash the system
    (bsc#1209657).
    - CVE-2023-38417: wifi: iwlwifi: bump FW API to 90 for BZ/SC devices (bsc#1225600).
    - CVE-2023-47210: wifi: iwlwifi: bump FW API to 90 for BZ/SC devices (bsc#1225601).
    - CVE-2023-52435: net: prevent mss overflow in skb_segment() (bsc#1220138).
    - CVE-2023-52458: Fixed check that partition length needs to be aligned  with block size (bsc#1220428).
    - CVE-2023-52503: Fixed tee/amdtee use-after-free vulnerability in amdtee_close_session (bsc#1220915).
    - CVE-2023-52618: Fixed string overflow in block/rnbd-srv (bsc#1221615).
    - CVE-2023-52622: ext4: avoid online resizing failures due to oversized flex bg (bsc#1222080).
    - CVE-2023-52631: Fixed an NULL dereference bug (bsc#1222264  CVE-2023-52631).
    - CVE-2023-52640: Fixed out-of-bounds in ntfs_listxattr (bsc#1222301).
    - CVE-2023-52641: Fixed NULL ptr dereference checking at the end of attr_allocate_frame() (bsc#1222303)
    - CVE-2023-52645: Fixed pmdomain/mediatek race conditions with genpd (bsc#1223033).
    - CVE-2023-52652: Fixed NTB for possible name leak in ntb_register_device() (bsc#1223686).
    - CVE-2023-52656: Dropped any code related to SCM_RIGHTS (bsc#1224187).
    - CVE-2023-52672: pipe: wakeup wr_wait after setting max_usage (bsc#1224614).
    - CVE-2023-52674: Add clamp() in scarlett2_mixer_ctl_put()  (bsc#1224727).
    - CVE-2023-52659: Fixed to pfn_to_kaddr() not treated as a 64-bit type (bsc#1224442)
    - CVE-2023-52680: Fixed missing error checks to *_ctl_get()  (bsc#1224608).
    - CVE-2023-52692: Fixed missing error check to  scarlett2_usb_set_config() (bsc#1224628).
    - CVE-2023-52698: Fixed memory leak in netlbl_calipso_add_pass()  (CVE-2023-52698 bsc#1224621)
    - CVE-2023-52699: sysv: don't call sb_bread() with pointers_lock held (bsc#1224659).
    - CVE-2023-52735: bpf, sockmap: Don't let sock_map_{close,destroy,unhash} call itself (bsc#1225475).
    - CVE-2023-52751: smb: client: fix use-after-free in smb2_query_info_compound() (bsc#1225489).
    - CVE-2023-52757: Fixed potential deadlock when releasing mids (bsc#1225548).
    - CVE-2023-52771: Fixed delete_endpoint() vs parent unregistration race  (bsc#1225007).
    - CVE-2023-52772: Fixed use-after-free in unix_stream_read_actor()  (bsc#1224989).
    - CVE-2023-52775: net/smc: avoid data corruption caused by decline (bsc#1225088).
    - CVE-2023-52786: ext4: fix racy may inline data check in dio write (bsc#1224939).
    - CVE-2023-52787: blk-mq: make sure active queue usage is held for bio_integrity_prep() (bsc#1225105).
    - CVE-2023-52837: nbd: fix uaf in nbd_open (bsc#1224935).
    - CVE-2023-52843: llc: verify mac len before reading mac header (bsc#1224951).
    - CVE-2023-52845: tipc: Change nla_policy for bearer-related names to NLA_NUL_STRING (bsc#1225585).
    - CVE-2023-52855: usb: dwc2: fix possible NULL pointer dereference caused by driver concurrency
    (bsc#1225583).
    - CVE-2023-52860: Fixed null pointer dereference in hisi_hns3 (bsc#1224936).
    - CVE-2023-52875: Add check for mtk_alloc_clk_data (bsc#1225096).
    - CVE-2023-52881: tcp: do not accept ACK of bytes we never sent (bsc#1225611).
    - CVE-2023-6238: Fixed kcalloc() arguments order (bsc#1217384).
    - CVE-2024-21823: Fixed safety flag to struct ends (bsc#1223625).
    - CVE-2024-23848: Fixed media/cec for possible use-after-free in cec_queue_msg_fh (bsc#1219104).
    - CVE-2024-25739: Fixed possible crash in create_empty_lvol() in drivers/mtd/ubi/vtbl.c (bsc#1219834).
    - CVE-2024-26601: Fixed ext4 buddy bitmap corruption via fast commit replay (bsc#1220342).
    - CVE-2024-26614: Fixed the initialization of accept_queue's spinlocks (bsc#1221293).
    - CVE-2024-26615: net/smc: fix illegal rmb_desc access in SMC-D connection dump (bsc#1220942).
    - CVE-2024-26623: pds_core: Prevent race issues involving the adminq (bsc#1221057).
    - CVE-2024-26625: Call sock_orphan() at release time (bsc#1221086)
    - CVE-2024-26632: Fixed iterating over an empty bio with  bio_for_each_folio_all (bsc#1221635).
    - CVE-2024-26633: ip6_tunnel: fix NEXTHDR_FRAGMENT handling in ip6_tnl_parse_tlv_enc_lim() (bsc#1221647).
    - CVE-2024-26635: llc: Drop support for ETH_P_TR_802_2 (bsc#1221656).
    - CVE-2024-26636: llc: make llc_ui_sendmsg() more robust against bonding changes (bsc#1221659).
    - CVE-2024-26638: Fixed uninitialize struct msghdr completely (bsc#1221649 CVE-2024-26638).
    - CVE-2024-26641: ip6_tunnel: make sure to pull inner header in __ip6_tnl_rcv() (bsc#1221654).
    - CVE-2024-26642: Fixed the set of anonymous timeout flag in netfilter nf_tables (bsc#1221830).
    - CVE-2024-26643: Fixed mark set as dead when unbinding anonymous  set with timeout (bsc#1221829).
    - CVE-2024-26663: tipc: Check the bearer type before calling tipc_udp_nl_bearer_add() (bsc#1222326).
    - CVE-2024-26665: tunnels: fix out of bounds access when building IPv6 PMTU error (bsc#1222328).
    - CVE-2024-26671: Fixed blk-mq IO hang from sbitmap wakeup race (bsc#1222357).
    - CVE-2024-26673: Fixed netfilter/nft_ct layer 3 and 4 protocol sanitization (bsc#1222368).
    - CVE-2024-26674: Revert to _ASM_EXTABLE_UA() for {get,put}_user() fixups (bsc#1222378).
    - CVE-2024-26679: Fixed read sk->sk_family once in inet_recv_error() (bsc#1222385).
    - CVE-2024-26684: Fixed net/stmmac/xgmac handling of DPP safety error for DMA channels (bsc#1222445).
    - CVE-2024-26691: KVM: arm64: Fix circular locking dependency (bsc#1222463).
    - CVE-2024-26704: Fixed a double-free of blocks due to wrong extents moved_len in ext4 (bsc#1222422).
    - CVE-2024-26726: Fixed invalid drop extent_map for free space inode on write error (bsc#1222532)
    - CVE-2024-26731: Fixed NULL pointer dereference in  sk_psock_verdict_data_ready() (bsc#1222371).
    - CVE-2024-26733: Fixed an overflow in arp_req_get() in arp (bsc#1222585).
    - CVE-2024-26734: devlink: fix possible use-after-free and memory leaks in devlink_init() (bsc#1222438).
    - CVE-2024-26737: Fixed selftests/bpf racing between bpf_timer_cancel_and_free and bpf_timer_cancel
    (bsc#1222557).
    - CVE-2024-26740: Fixed use the backlog for mirred ingress  (bsc#1222563).
    - CVE-2024-26760: scsi: target: pscsi: Fix bio_put() for error case (bsc#1222596).
    - CVE-2024-26772: Fixed ext4 to avoid allocating blocks from corrupted group in ext4_mb_find_by_goal()
    (bsc#1222613).
    - CVE-2024-26773: Fixed ext4 block allocation from corrupted group in ext4_mb_try_best_found()
    (bsc#1222618).
    - CVE-2024-26774: Fixed dividing by 0 in mb_update_avg_fragment_size()  when block bitmap corrupt
    (bsc#1222622).
    - CVE-2024-26775: Fixed potential deadlock at set_capacity (bsc#1222627).
    - CVE-2024-26783: Fixed mm/vmscan bug when calling wakeup_kswapd() with a wrong zone index (bsc#1222615).
    - CVE-2024-26785: iommufd: Fix protection fault in iommufd_test_syz_conv_iova (bsc#1222779).
    - CVE-2024-26791: Fixed properly validate device names in btrfs (bsc#1222793)
    - CVE-2024-26805: Fixed a kernel-infoleak-after-free in __skb_datagram_iter in netlink (bsc#1222630).
    - CVE-2024-26807: Fixed spi/cadence-qspi NULL pointer reference in runtime PM hooks (bsc#1222801).
    - CVE-2024-26813: vfio/platform: Create persistent IRQ handlers (bsc#1222809).
    - CVE-2024-26814: vfio/fsl-mc: Block calling interrupt handler without trigger (bsc#1222810).
    - CVE-2024-26815: Fixed improper TCA_TAPRIO_TC_ENTRY_INDEX check  (bsc#1222635).
    - CVE-2024-26816: Fixed relocations in .notes section when building with CONFIG_XEN_PV=y (bsc#1222624).
    - CVE-2024-26822: Set correct id, uid and cruid for multiuser  automounts (bsc#1223011).
    - CVE-2024-26826: mptcp: fix data re-injection from stale subflow (bsc#1223010).
    - CVE-2024-26832: Fixed missing folio cleanup in writeback race path  (bsc#1223007).
    - CVE-2024-26836: Fixed platform/x86/think-lmi password opcode ordering for workstations (bsc#1222968).
    - CVE-2024-26844: Fixed WARNING in _copy_from_iter (bsc#1223015).
    - CVE-2024-26845: scsi: target: core: Add TMF to tmr_list handling (bsc#1223018).
    - CVE-2024-26860: Fixed a memory leak when rechecking the data (bsc#1223077).
    - CVE-2024-26862: Fixed packet annotate data-races around ignore_outgoing (bsc#1223111).
    - CVE-2024-26863: hsr: Fix uninit-value access in hsr_get_node() (bsc#1223021).
    - CVE-2024-26878: Fixed quota for potential NULL pointer dereference (bsc#1223060).
    - CVE-2024-26882: Fixed net/ip_tunnel to make sure to pull inner header in ip_tunnel_rcv() (bsc#1223034).
    - CVE-2024-26883: Fixed bpf stackmap overflow check on 32-bit arches (bsc#1223035).
    - CVE-2024-26884: Fixed bpf hashtab overflow check on 32-bit arches (bsc#1223189).
    - CVE-2024-26885: Fixed bpf DEVMAP_HASH overflow check on 32-bit arches (bsc#1223190).
    - CVE-2024-26899: Fixed deadlock between bd_link_disk_holder and partition  scan (bsc#1223045).
    - CVE-2024-26901: Fixed do_sys_name_to_handle() to use kzalloc() to prevent kernel-infoleak (bsc#1223198).
    - CVE-2024-26906: Fixed invalid vsyscall page read for copy_from_kernel_nofault() (bsc#1223202).
    - CVE-2024-26909: Fixed drm bridge use-after-free  (bsc#1223143).
    - CVE-2024-26921: Preserve kabi for sk_buff (bsc#1223138).
    - CVE-2024-26923: Fixed false-positive lockdep splat for spin_lock() in __unix_gc() (bsc#1223384).
    - CVE-2024-26925: Release mutex after nft_gc_seq_end from abort path (bsc#1223390).
    - CVE-2024-26928: Fixed potential UAF in cifs_debug_files_proc_show() (bsc#1223532).
    - CVE-2024-26944: btrfs: zoned: fix lock ordering in btrfs_zone_activate() (bsc#1223731).
    - CVE-2024-26945: Fixed nr_cpus < nr_iaa case (bsc#1223732).
    - CVE-2024-26946: Fixed copy_from_kernel_nofault() to read from unsafe  address (bsc#1223669).
    - CVE-2024-26948: Fixed drm/amd/display by adding dc_state NULL check in dc_state_release (bsc#1223664).
    - CVE-2024-26958: Fixed UAF in direct writes (bsc#1223653).
    - CVE-2024-26960: Fixed mm/swap race between free_swap_and_cache() and swapoff() (bsc#1223655).
    - CVE-2024-26982: Fixed Squashfs inode number check not to be an invalid value of zero (bsc#1223634).
    - CVE-2024-26991: Fixed overflow lpage_info when checking  attributes (bsc#1223695).
    - CVE-2024-26993: Fixed fs/sysfs reference leak in sysfs_break_active_protection() (bsc#1223693).
    - CVE-2024-27012: netfilter: nf_tables: restore set elements when delete set fails (bsc#1223804).
    - CVE-2024-27013: Fixed tun limit printing rate when illegal packet received by tun device (bsc#1223745).
    - CVE-2024-27014: Fixed net/mlx5e to prevent deadlock while disabling aRFS (bsc#1223735).
    - CVE-2024-27015: netfilter: flowtable: incorrect pppoe tuple (bsc#1223806).
    - CVE-2024-27016: netfilter: flowtable: validate pppoe header (bsc#1223807).
    - CVE-2024-27019: netfilter: nf_tables: Fix potential data-race in __nft_obj_type_get() (bsc#1223813)
    - CVE-2024-27020: netfilter: nf_tables: Fix potential data-race in __nft_expr_type_get() (bsc#1223815)
    - CVE-2024-27022: Fixed linking file vma until vma is fully initialized  (bsc#1223774).
    - CVE-2024-27025: nbd: null check for nla_nest_start (bsc#1223778)
    - CVE-2024-27056: Fixed wifi/iwlwifi/mvm to ensure offloading TID queue exists (bsc#1223822).
    - CVE-2024-27064: netfilter: nf_tables: Fix a memory leak in nf_tables_updchain (bsc#1223740).
    - CVE-2024-27065: netfilter: nf_tables: do not compare internal table flags on updates (bsc#1223836).
    - CVE-2024-27395: Fixed Use-After-Free in ovs_ct_exit (bsc#1224098).
    - CVE-2024-27396: Fixed Use-After-Free in gtp_dellink (bsc#1224096).
    - CVE-2024-27401: Fixed user_length taken into account when fetching packet contents (bsc#1224181).
    - CVE-2024-27402: phonet/pep: fix racy skb_queue_empty() use (bsc#1224414).
    - CVE-2024-27404: mptcp: fix data races on remote_id (bsc#1224422)
    - CVE-2024-27408: Fixed race condition in dmaengine w-edma/eDMA (bsc#1224430).
    - CVE-2024-27414: rtnetlink: fix error logic of IFLA_BRIDGE_FLAGS writing back (bsc#1224439).
    - CVE-2024-27417: Fixed potential 'struct net' leak in inet6_rtm_getaddr()  (bsc#1224721)
    - CVE-2024-27418: Fixed memory leak in mctp_local_output (bsc#1224720)
    - CVE-2024-27419: Fixed data-races around sysctl_net_busy_read (bsc#1224759)
    - CVE-2024-27431: Fixed Zero-initialise xdp_rxq_info struct before running  XDP program (bsc#1224718).
    - CVE-2024-35247: fpga: region: add owner module and take its refcount (bsc#1226948).
    - CVE-2024-35805: dm snapshot: fix lockup in dm_exception_table_exit (bsc#1224743).
    - CVE-2024-35807: ext4: fix corruption during on-line resize (bsc#1224735).
    - CVE-2024-35827: io_uring/net: fix overflow check in io_recvmsg_mshot_prep() (bsc#1224606).
    - CVE-2024-35831: io_uring: Fix release of pinned pages when __io_uaddr_map fails (bsc#1224698).
    - CVE-2024-35843: iommu/vt-d: Use device rbtree in iopf reporting path (bsc#1224751).
    - CVE-2024-35848: eeprom: at24: fix memory corruption race condition (bsc#1224612).
    - CVE-2024-35852: Fixed memory leak when canceling rehash  work (bsc#1224502).
    - CVE-2024-35853: mlxsw: spectrum_acl_tcam: Fix memory leak during rehash (bsc#1224604).
    - CVE-2024-35854: Fixed possible use-after-free during rehash (bsc#1224636).
    - CVE-2024-35857: icmp: prevent possible NULL dereferences from icmp_build_probe() (bsc#1224619).
    - CVE-2024-35860: Struct bpf_link and bpf_link_ops kABI workaround  (bsc#1224531).
    - CVE-2024-35861: Fixed potential UAF in cifs_signal_cifsd_for_reconnect() (bsc#1224766).
    - CVE-2024-35862: Fixed potential UAF in smb2_is_network_name_deleted() (bsc#1224764).
    - CVE-2024-35863: Fixed potential UAF in is_valid_oplock_break() (bsc#1224763).
    - CVE-2024-35864: Fixed potential UAF in smb2_is_valid_lease_break() (bsc#1224765).
    - CVE-2024-35865: Fixed potential UAF in smb2_is_valid_oplock_break() (bsc#1224668).
    - CVE-2024-35866: Fixed potential UAF in cifs_dump_full_key()  (bsc#1224667).
    - CVE-2024-35867: Fixed potential UAF in cifs_stats_proc_show() (bsc#1224664).
    - CVE-2024-35868: Fixed potential UAF in cifs_stats_proc_write() (bsc#1224678).
    - CVE-2024-35872: Fixed GUP-fast succeeding on secretmem folios  (bsc#1224530).
    - CVE-2024-35877: Fixed VM_PAT handling in COW mappings (bsc#1224525).
    - CVE-2024-35880: io_uring/kbuf: hold io_buffer_list reference over mmap (bsc#1224523).
    - CVE-2024-35884: udp: do not accept non-tunnel GSO skbs landing in a tunnel (bsc#1224520).
    - CVE-2024-35886: ipv6: Fix infinite recursion in fib6_dump_done() (bsc#1224670).
    - CVE-2024-35890: gro: fix ownership transfer (bsc#1224516).
    - CVE-2024-35892: net/sched: fix lockdep splat in qdisc_tree_reduce_backlog() (bsc#1224515).
    - CVE-2024-35893: net/sched: act_skbmod: prevent kernel-infoleak (bsc#1224512)
    - CVE-2024-35895: Fixed lock inversion deadlock in map delete elem (bsc#1224511).
    - CVE-2024-35898: netfilter: nf_tables: Fix potential data-race in __nft_flowtable_type_get()
    (bsc#1224498).
    - CVE-2024-35899: netfilter: nf_tables: flush pending destroy work before exit_net release (bsc#1224499)
    - CVE-2024-35900: netfilter: nf_tables: reject new basechain after table flag update (bsc#1224497).
    - CVE-2024-35903: Fixed IP after emitting call depth accounting (bsc#1224493).
    - CVE-2024-35908: tls: get psock ref after taking rxlock to avoid leak (bsc#1224490)
    - CVE-2024-35917: Fixed Fix bpf_plt pointer arithmetic (bsc#1224481).
    - CVE-2024-35921: Fixed oops when HEVC init fails (bsc#1224477).
    - CVE-2024-35925: block: prevent division by zero in blk_rq_stat_sum() (bsc#1224661).
    - CVE-2024-35926: crypto: iaa - Fix async_disable descriptor leak (bsc#1224655).
    - CVE-2024-35931: Fixed PCI error slot reset during RAS recovery (bsc#1224652).
    - CVE-2024-35934: net/smc: reduce rtnl pressure in smc_pnet_create_pnetids_list() (bsc#1224641)
    - CVE-2024-35942: pmdomain: imx8mp-blk-ctrl: imx8mp_blk: Add fdcc clock to hdmimix domain (bsc#1224589).
    - CVE-2024-35943: Fixed a null pointer dereference in omap_prm_domain_init (bsc#1224649).
    - CVE-2024-35944: Fixed memcpy() run-time warning in dg_dispatch_as_host() (bsc#1224648).
    - CVE-2024-35964: Fixed not validating setsockopt user input  (bsc#1224581).
    - CVE-2024-35969: Fixed race condition between ipv6_get_ifaddr and ipv6_del_addr (bsc#1224580).
    - CVE-2024-35976: Validate user input for XDP_{UMEM|COMPLETION}_FILL_RING (bsc#1224575).
    - CVE-2024-35979: raid1: fix use-after-free for original bio in raid1_write_request() (bsc#1224572).
    - CVE-2024-35991: Fixed kABI workaround for struct idxd_evl (bsc#1224553).
    - CVE-2024-35998: Fixed lock ordering potential deadlock in cifs_sync_mid_result (bsc#1224549).
    - CVE-2024-35999: Fixed missing lock when picking channel (bsc#1224550).
    - CVE-2024-36003: ice: fix LAG and VF lock dependency in ice_reset_vf() (bsc#1224544).
    - CVE-2024-36004: i40e: Do not use WQ_MEM_RECLAIM flag for workqueue (bsc#1224545)
    - CVE-2024-36005: netfilter: nf_tables: honor table dormant flag from netdev release event path
    (bsc#1224539).
    - CVE-2024-36006: Fixed incorrect list API usage  (bsc#1224541).
    - CVE-2024-36007: Fixed warning during rehash  (bsc#1224543).
    - CVE-2024-36008: ipv4: check for NULL idev in ip_route_use_hint() (bsc#1224540).
    - CVE-2024-36017: rtnetlink: Correct nested IFLA_VF_VLAN_LIST attribute validation (bsc#1225681).
    - CVE-2024-36024: drm/amd/display: Disable idle reallow as part of command/gpint execution (bsc#1225702).
    - CVE-2024-36030: Fixed the double free in rvu_npc_freemem() (bsc#1225712)
    - CVE-2024-36281: net/mlx5: Use mlx5_ipsec_rx_status_destroy to correctly delete status rules
    (bsc#1226799).
    - CVE-2024-36478: null_blk: fix null-ptr-dereference while configuring 'power' and 'submit_queues'
    (bsc#1226841).
    - CVE-2024-36479: fpga: bridge: add owner module and take its refcount (bsc#1226949).
    - CVE-2024-36882: mm: use memalloc_nofs_save() in page_cache_ra_order() (bsc#1225723).
    - CVE-2024-36889: ata: libata-scsi: Fix offsets for the fixed format sense data (bsc#1225746).
    - CVE-2024-36899: gpiolib: cdev: Fix use after free in lineinfo_changed_notify (bsc#1225737).
    - CVE-2024-36900: net: hns3: fix kernel crash when devlink reload during initialization (bsc#1225726).
    - CVE-2024-36901: ipv6: prevent NULL dereference in ip6_output() (bsc#1225711)
    - CVE-2024-36902: ipv6: fib6_rules: avoid possible NULL dereference in fib6_rule_action() (bsc#1225719).
    - CVE-2024-36903: ipv6: Fix potential uninit-value access in __ip6_make_skb() (bsc#1225741).
    - CVE-2024-36904: tcp: Use refcount_inc_not_zero() in tcp_twsk_unique() (bsc#1225732).
    - CVE-2024-36909: Drivers: hv: vmbus: Do not free ring buffers that couldn't be re-encrypted
    (bsc#1225744).
    - CVE-2024-36910: uio_hv_generic: Do not free decrypted memory (bsc#1225717).
    - CVE-2024-36911: hv_netvsc: Do not free decrypted memory (bsc#1225745).
    - CVE-2024-36912: Drivers: hv: vmbus: Track decrypted status in vmbus_gpadl (bsc#1225752).
    - CVE-2024-36913: Drivers: hv: vmbus: Leak pages if set_memory_encrypted() fails (bsc#1225753).
    - CVE-2024-36914: drm/amd/display: Skip on writeback when it's not applicable (bsc#1225757).
    - CVE-2024-36915: nfc: llcp: fix nfc_llcp_setsockopt() unsafe copies (bsc#1225758).
    - CVE-2024-36916: blk-iocost: avoid out of bounds shift (bsc#1225759).
    - CVE-2024-36917: block: fix overflow in blk_ioctl_discard() (bsc#1225770).
    - CVE-2024-36919: scsi: bnx2fc: Remove spin_lock_bh while releasing resources after upload (bsc#1225767).
    - CVE-2024-36923: fs/9p: fix uninitialized values during inode evict (bsc#1225815).
    - CVE-2024-36934: bna: ensure the copied buf is NUL terminated (bsc#1225760).
    - CVE-2024-36935: ice: ensure the copied buf is NUL terminated (bsc#1225763).
    - CVE-2024-36937: xdp: use flags field to disambiguate broadcast redirect (bsc#1225834).
    - CVE-2024-36938: Fixed NULL pointer dereference in sk_psock_skb_ingress_enqueue (bsc#1225761).
    - CVE-2024-36945: net/smc: fix neighbour and rtable leak in smc_ib_find_route() (bsc#1225823).
    - CVE-2024-36946: phonet: fix rtm_phonet_notify() skb allocation (bsc#1225851).
    - CVE-2024-36957: octeontx2-af: avoid off-by-one read from userspace (bsc#1225762).
    - CVE-2024-36971: net: fix __dst_negative_advice() race (bsc#1226145).
    - CVE-2024-36978: net: sched: sch_multiq: fix possible OOB write in multiq_tune() (bsc#1226514).
    - CVE-2024-37021: fpga: manager: add owner module and take its refcount (bsc#1226950).
    - CVE-2024-37078: nilfs2: fix potential kernel bug due to lack of writeback flag waiting (bsc#1227066).
    - CVE-2024-37353: virtio: fixed a double free in vp_del_vqs() (bsc#1226875).
    - CVE-2024-37354: btrfs: fix crash on racing fsync and size-extending write into prealloc (bsc#1227101).
    - CVE-2024-38553: net: fec: remove .ndo_poll_controller to avoid deadlock (bsc#1226744).
    - CVE-2024-38555: net/mlx5: Discard command completions in internal error (bsc#1226607).
    - CVE-2024-38556: net/mlx5: Add a timeout to acquire the command queue semaphore (bsc#1226774).
    - CVE-2024-38557: net/mlx5: Reload only IB representors upon lag disable/enable (bsc#1226781).
    - CVE-2024-38558: net: openvswitch: fix overwriting ct original tuple for ICMPv6 (bsc#1226783).
    - CVE-2024-38564: bpf: Add BPF_PROG_TYPE_CGROUP_SKB attach type enforcement in BPF_LINK_CREATE
    (bsc#1226789).
    - CVE-2024-38566: bpf: Fix verifier assumptions about socket->sk (bsc#1226790).
    - CVE-2024-38568: drivers/perf: hisi: hns3: Fix out-of-bound access when valid event group (bsc#1226771).
    - CVE-2024-38569: drivers/perf: hisi_pcie: Fix out-of-bound access when valid event group (bsc#1226772).
    - CVE-2024-38570: gfs2: Fix potential glock use-after-free on unmount (bsc#1226775).
    - CVE-2024-38580: epoll: be better about file lifetimes (bsc#1226610).
    - CVE-2024-38586: r8169: Fix possible ring buffer corruption on fragmented Tx packets (bsc#1226750).
    - CVE-2024-38594: net: stmmac: move the EST lock to struct stmmac_priv (bsc#1226734).
    - CVE-2024-38597: eth: sungem: remove .ndo_poll_controller to avoid deadlocks (bsc#1226749).
    - CVE-2024-38598: md: fix resync softlockup when bitmap size is less than array size (bsc#1226757).
    - CVE-2024-38603: drivers/perf: hisi: hns3: Actually use devm_add_action_or_reset() (bsc#1226842).
    - CVE-2024-38604: block: refine the EOF check in blkdev_iomap_begin (bsc#1226866).
    - CVE-2024-38608: net/mlx5e: Fix netif state handling (bsc#1226746).
    - CVE-2024-38610: drivers/virt/acrn: fix PFNMAP PTE checks in acrn_vm_ram_map() (bsc#1226758).
    - CVE-2024-38627: stm class: Fix a double free in stm_register_device() (bsc#1226857).
    - CVE-2024-38636: f2fs: multidev: fix to recognize valid zero block address (bsc#1226879).
    - CVE-2024-38659: enic: Validate length of nl attributes in enic_set_vf_port (bsc#1226883).
    - CVE-2024-38661: s390/ap: Fix crash in AP internal function modify_bitmap() (bsc#1226996).
    - CVE-2024-39276: ext4: fix mb_cache_entry's e_refcnt leak in ext4_xattr_block_cache_find() (bsc#1226993).
    - CVE-2024-39301: net/9p: fix uninit-value in p9_client_rpc() (bsc#1226994).
    - CVE-2024-39371: io_uring: check for non-NULL file pointer in io_file_can_poll() (bsc#1226990).
    - CVE-2024-39468: smb: client: fix deadlock in smb2_find_smb_tcon() (bsc#1227103.
    - CVE-2024-39472: xfs: fix log recovery buffer allocation for the legacy h_size fixup (bsc#1227432).
    - CVE-2024-39474: mm/vmalloc: fix vmalloc which may return null if called with __GFP_NOFAIL (bsc#1227434).
    - CVE-2024-39482: bcache: fix variable length array abuse in btree_iter (bsc#1227447).
    - CVE-2024-39487: bonding: Fix out-of-bounds read in bond_option_arp_ip_targets_set() (bsc#1227573)
    - CVE-2024-39490: ipv6: sr: fix missing sk_buff release in seg6_input_core (bsc#1227626).
    - CVE-2024-39494: ima: Fix use-after-free on a dentry's dname.name (bsc#1227716).
    - CVE-2024-39496: btrfs: zoned: fix use-after-free due to race with dev replace (bsc#1227719).
    - CVE-2024-39498: drm/mst: Fix NULL pointer dereference at drm_dp_add_payload_part2 (bsc#1227723)
    - CVE-2024-39502: ionic: fix use after netif_napi_del() (bsc#1227755).
    - CVE-2024-39504: netfilter: nft_inner: validate mandatory meta and payload (bsc#1227757).
    - CVE-2024-39507: net: hns3: fix kernel crash problem in concurrent scenario (bsc#1227730).
    - CVE-2024-40901: scsi: mpt3sas: Avoid test/set_bit() operating in non-allocated memory (bsc#1227762).
    - CVE-2024-40906: net/mlx5: Always stop health timer during driver removal (bsc#1227763).
    - CVE-2024-40908: bpf: Set run context for rawtp test_run callback (bsc#1227783).
    - CVE-2024-40919: bnxt_en: Adjust logging of firmware messages in case of released token in __hwrm_send()
    (bsc#1227779).
    - CVE-2024-40923: vmxnet3: disable rx data ring on dma allocation failure (bsc#1227786).
    - CVE-2024-40925: block: fix request.queuelist usage in flush (bsc#1227789).
    - CVE-2024-40928: net: ethtool: fix the error condition in ethtool_get_phy_stats_ethtool() (bsc#1227788).
    - CVE-2024-40931: mptcp: ensure snd_una is properly initialized on connect (bsc#1227780).
    - CVE-2024-40935: cachefiles: flush all requests after setting CACHEFILES_DEAD (bsc#1227797).
    - CVE-2024-40937: gve: Clear napi->skb before dev_kfree_skb_any() (bsc#1227836).
    - CVE-2024-40940: net/mlx5: Fix tainted pointer delete is case of flow rules creation fail (bsc#1227800).
    - CVE-2024-40947: ima: Avoid blocking in RCU read-side critical section (bsc#1227803).
    - CVE-2024-40948: mm/page_table_check: fix crash on ZONE_DEVICE (bsc#1227801).
    - CVE-2024-40953: KVM: Fix a data race on last_boosted_vcpu in kvm_vcpu_on_spin() (bsc#1227806).
    - CVE-2024-40960: ipv6: prevent possible NULL dereference in rt6_probe() (bsc#1227813).
    - CVE-2024-40961: ipv6: prevent possible NULL deref in fib6_nh_init() (bsc#1227814).
    - CVE-2024-40966: kABI: tty: add the option to have a tty reject a new ldisc (bsc#1227886).
    - CVE-2024-40970: Avoid hw_desc array overrun in dw-axi-dmac (bsc#1227899).
    - CVE-2024-40972: ext4: fold quota accounting into ext4_xattr_inode_lookup_create() (bsc#1227910).
    - CVE-2024-40975: platform/x86: x86-android-tablets: Unregister devices in reverse order (bsc#1227926).
    - CVE-2024-40998: ext4: fix uninitialized ratelimit_state->lock access in __ext4_fill_super()
    (bsc#1227866).
    - CVE-2024-40999: net: ena: Add validation for completion descriptors consistency (bsc#1227913).
    - CVE-2024-41006: netrom: Fix a memory leak in nr_heartbeat_expiry() (bsc#1227862).
    - CVE-2024-41013: xfs: do not walk off the end of a directory data block (bsc#1228405).
    - CVE-2024-41014: xfs: add bounds checking to xlog_recover_process_data (bsc#1228408).
    - CVE-2024-41017: jfs: do not walk off the end of ealist (bsc#1228403).
    - CVE-2024-41090: tap: add missing verification for short frame (bsc#1228328).
    - CVE-2024-41091: tun: add missing verification for short frame (bsc#1228327).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1012628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1208593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222173");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222301");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223138");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224438");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224603");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224676");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224720");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225475");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225704");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226163");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226582");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226588");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226754");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226776");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226796");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227362");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227757");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227806");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227910");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227913");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228211");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228417");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-August/019280.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8ffd8a9");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47432");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38417");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47210");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-51780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52458");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52503");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52618");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52658");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52660");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52662");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52669");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52672");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52680");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52683");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52690");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52692");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52694");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52696");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52697");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52698");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52699");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52749");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52750");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52757");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52762");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52765");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52767");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52768");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52769");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52771");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52776");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52781");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52782");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52783");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52787");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52792");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52794");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52795");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52799");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52801");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52806");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52808");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52818");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52825");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52832");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52833");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52836");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52844");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52869");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52876");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6238");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-7042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-21823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-25739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-25741");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26625");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26632");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26638");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26654");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26656");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26665");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26676");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26684");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26714");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26726");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26731");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26734");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26750");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26758");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26761");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26764");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26767");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26769");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26783");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26785");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26793");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26794");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26802");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26822");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26832");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26836");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26844");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26846");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26881");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26961");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26963");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26983");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26986");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26993");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26994");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27003");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27022");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27027");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27030");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27031");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27046");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27057");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27064");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27065");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27067");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27080");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27388");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27389");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27393");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27395");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27396");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27399");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27400");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27401");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27404");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27405");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27408");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27410");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27411");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27412");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27413");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27414");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27416");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27417");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27418");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27419");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27431");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27432");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27434");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27435");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27436");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-33619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-34777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35247");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35790");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35794");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35795");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35799");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35801");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35806");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35808");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35822");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35824");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35825");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35830");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35831");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35833");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35836");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35865");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35867");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35879");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35892");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35961");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35963");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35970");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35971");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35982");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35984");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35986");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35991");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35992");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35995");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35997");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36003");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36005");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36007");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36010");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36018");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36019");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36025");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36026");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36029");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36030");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36032");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36478");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36479");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36887");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36895");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36897");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36913");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36944");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36945");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36951");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36952");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36955");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36962");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36965");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36967");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36969");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36971");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37021");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37353");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-37354");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38381");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38384");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38385");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38388");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38390");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38391");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38539");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38540");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38543");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38544");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38547");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38548");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38549");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38550");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38551");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38552");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38553");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38554");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38555");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38556");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38557");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38558");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38562");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38564");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38568");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38570");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38572");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38573");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38575");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38578");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38579");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38580");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38594");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38604");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38617");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38618");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38621");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38627");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38629");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38630");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38633");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38634");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39276");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39277");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39291");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39296");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39362");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39371");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39463");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39466");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39468");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39469");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39471");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39472");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39473");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39474");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39475");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39479");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39481");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39482");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39487");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39494");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39496");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39498");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39502");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39504");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40906");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40908");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40953");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40961");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40970");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40979");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41017");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41091");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-livepatch-6_4_0-150600_10_5-rt package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-41011");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-6_4_0-150600_10_5-rt");
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
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-livepatch-6_4_0-150600_10_5-rt-1-150600.1.5.1', 'sp':'6', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-livepatch-6_4_0-150600_10_5-rt');
}
