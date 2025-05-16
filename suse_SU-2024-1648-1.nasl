#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1648-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(197048);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/27");

  script_cve_id(
    "CVE-2019-25160",
    "CVE-2020-36312",
    "CVE-2021-23134",
    "CVE-2021-46904",
    "CVE-2021-46905",
    "CVE-2021-46907",
    "CVE-2021-46909",
    "CVE-2021-46938",
    "CVE-2021-46939",
    "CVE-2021-46941",
    "CVE-2021-46950",
    "CVE-2021-46958",
    "CVE-2021-46960",
    "CVE-2021-46963",
    "CVE-2021-46964",
    "CVE-2021-46966",
    "CVE-2021-46975",
    "CVE-2021-46981",
    "CVE-2021-46988",
    "CVE-2021-46990",
    "CVE-2021-46998",
    "CVE-2021-47006",
    "CVE-2021-47015",
    "CVE-2021-47024",
    "CVE-2021-47034",
    "CVE-2021-47045",
    "CVE-2021-47049",
    "CVE-2021-47055",
    "CVE-2021-47056",
    "CVE-2021-47060",
    "CVE-2021-47061",
    "CVE-2021-47063",
    "CVE-2021-47068",
    "CVE-2021-47070",
    "CVE-2021-47071",
    "CVE-2021-47073",
    "CVE-2021-47100",
    "CVE-2021-47101",
    "CVE-2021-47104",
    "CVE-2021-47110",
    "CVE-2021-47112",
    "CVE-2021-47114",
    "CVE-2021-47117",
    "CVE-2021-47118",
    "CVE-2021-47119",
    "CVE-2021-47138",
    "CVE-2021-47141",
    "CVE-2021-47142",
    "CVE-2021-47143",
    "CVE-2021-47146",
    "CVE-2021-47149",
    "CVE-2021-47150",
    "CVE-2021-47153",
    "CVE-2021-47159",
    "CVE-2021-47161",
    "CVE-2021-47162",
    "CVE-2021-47165",
    "CVE-2021-47166",
    "CVE-2021-47167",
    "CVE-2021-47168",
    "CVE-2021-47169",
    "CVE-2021-47171",
    "CVE-2021-47173",
    "CVE-2021-47177",
    "CVE-2021-47179",
    "CVE-2021-47180",
    "CVE-2021-47181",
    "CVE-2021-47182",
    "CVE-2021-47183",
    "CVE-2021-47184",
    "CVE-2021-47185",
    "CVE-2021-47188",
    "CVE-2021-47189",
    "CVE-2021-47198",
    "CVE-2021-47202",
    "CVE-2021-47203",
    "CVE-2021-47204",
    "CVE-2021-47205",
    "CVE-2021-47207",
    "CVE-2021-47211",
    "CVE-2021-47216",
    "CVE-2021-47217",
    "CVE-2022-0487",
    "CVE-2022-48619",
    "CVE-2022-48626",
    "CVE-2022-48636",
    "CVE-2022-48650",
    "CVE-2022-48651",
    "CVE-2022-48667",
    "CVE-2022-48668",
    "CVE-2022-48687",
    "CVE-2022-48688",
    "CVE-2022-48695",
    "CVE-2022-48701",
    "CVE-2023-0160",
    "CVE-2023-6270",
    "CVE-2023-6356",
    "CVE-2023-6535",
    "CVE-2023-6536",
    "CVE-2023-7042",
    "CVE-2023-7192",
    "CVE-2023-28746",
    "CVE-2023-35827",
    "CVE-2023-52454",
    "CVE-2023-52469",
    "CVE-2023-52470",
    "CVE-2023-52474",
    "CVE-2023-52476",
    "CVE-2023-52477",
    "CVE-2023-52486",
    "CVE-2023-52488",
    "CVE-2023-52509",
    "CVE-2023-52515",
    "CVE-2023-52524",
    "CVE-2023-52528",
    "CVE-2023-52575",
    "CVE-2023-52583",
    "CVE-2023-52587",
    "CVE-2023-52590",
    "CVE-2023-52591",
    "CVE-2023-52595",
    "CVE-2023-52598",
    "CVE-2023-52607",
    "CVE-2023-52614",
    "CVE-2023-52620",
    "CVE-2023-52628",
    "CVE-2023-52635",
    "CVE-2023-52639",
    "CVE-2023-52644",
    "CVE-2023-52646",
    "CVE-2023-52650",
    "CVE-2023-52652",
    "CVE-2023-52653",
    "CVE-2024-2201",
    "CVE-2024-22099",
    "CVE-2024-23307",
    "CVE-2024-23848",
    "CVE-2024-24855",
    "CVE-2024-24861",
    "CVE-2024-26614",
    "CVE-2024-26642",
    "CVE-2024-26651",
    "CVE-2024-26671",
    "CVE-2024-26675",
    "CVE-2024-26689",
    "CVE-2024-26704",
    "CVE-2024-26733",
    "CVE-2024-26739",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26747",
    "CVE-2024-26754",
    "CVE-2024-26763",
    "CVE-2024-26771",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26777",
    "CVE-2024-26778",
    "CVE-2024-26779",
    "CVE-2024-26793",
    "CVE-2024-26805",
    "CVE-2024-26816",
    "CVE-2024-26817",
    "CVE-2024-26839",
    "CVE-2024-26840",
    "CVE-2024-26852",
    "CVE-2024-26855",
    "CVE-2024-26857",
    "CVE-2024-26859",
    "CVE-2024-26878",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26898",
    "CVE-2024-26901",
    "CVE-2024-26903",
    "CVE-2024-26907",
    "CVE-2024-26922",
    "CVE-2024-26929",
    "CVE-2024-26930",
    "CVE-2024-26931",
    "CVE-2024-26948",
    "CVE-2024-26993",
    "CVE-2024-27013",
    "CVE-2024-27014",
    "CVE-2024-27043",
    "CVE-2024-27046",
    "CVE-2024-27054",
    "CVE-2024-27072",
    "CVE-2024-27073",
    "CVE-2024-27074",
    "CVE-2024-27075",
    "CVE-2024-27078",
    "CVE-2024-27388"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1648-1");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2024:1648-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12 host has packages installed that are affected by
multiple vulnerabilities as referenced in the SUSE-SU-2024:1648-1 advisory.

  - Use After Free vulnerability in nfc sockets in the Linux Kernel before 5.12.4 allows local attackers to
    elevate their privileges. In typical configurations, the issue can only be triggered by a privileged local
    user with the CAP_NET_RAW capability. (CVE-2021-23134)

  - In the Linux kernel, the following vulnerability has been resolved: scsi: qla2xxx: Fix double free of the
    ha->vp_map pointer Coverity scan reported potential risk of double free of the pointer ha->vp_map.
    ha->vp_map was freed in qla2x00_mem_alloc(), and again freed in function qla2x00_mem_free(ha). Assign NULL
    to vp_map and kfree take care of NULL. (CVE-2024-26930)

  - In the Linux kernel, the following vulnerability has been resolved: netlabel: fix out-of-bounds memory
    accesses There are two array out-of-bounds memory accesses, one in cipso_v4_map_lvl_valid(), the other in
    netlbl_bitmap_walk(). Both errors are embarassingly simple, and the fixes are straightforward. As a FYI
    for anyone backporting this patch to kernels prior to v4.8, you'll want to apply the netlbl_bitmap_walk()
    patch to cipso_v4_bitmap_walk() as netlbl_bitmap_walk() doesn't exist before Linux v4.8. (CVE-2019-25160)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1084332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220394");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220751");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221830");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223513");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223843");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223954");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035259.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-25160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36312");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-23134");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46939");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46950");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46963");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46966");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46981");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46988");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46990");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47034");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47049");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47056");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47060");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47061");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47070");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47071");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47100");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47101");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47104");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47110");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47112");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47117");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47118");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47119");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47138");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47141");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47143");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47146");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47149");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47150");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47153");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47159");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47165");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47166");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47167");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47168");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47169");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47171");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47173");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47177");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47179");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47181");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47182");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47183");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47185");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47188");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47189");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47203");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47204");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47205");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47207");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47211");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47216");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47217");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0487");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48626");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48636");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48667");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48668");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48688");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48695");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-35827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52454");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52469");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52470");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52474");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52476");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52477");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52486");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52488");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52509");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52515");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52528");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52575");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52628");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52635");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52639");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6270");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6356");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-7042");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-7192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-2201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22099");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23307");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23848");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26675");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26689");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26771");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26778");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26779");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26793");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26839");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26852");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26884");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26922");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26993");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27013");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27043");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27046");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27054");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27072");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27075");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-27388");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23134");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-27043");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-kgraft-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_12_14-122_212-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLED_SAP12|SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-4.12.14-122.212.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.212.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.212.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.212.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.212.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.212.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.212.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.212.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-obs-build-4.12.14-122.212.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.212.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.212.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'cluster-md-kmp-default-4.12.14-122.212.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'dlm-kmp-default-4.12.14-122.212.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'gfs2-kmp-default-4.12.14-122.212.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'ocfs2-kmp-default-4.12.14-122.212.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-12.5']},
    {'reference':'kernel-default-kgraft-4.12.14-122.212.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-default-kgraft-devel-4.12.14-122.212.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kgraft-patch-4_12_14-122_212-default-1-8.11.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-live-patching-release-12.5']},
    {'reference':'kernel-obs-build-4.12.14-122.212.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.212.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-extra-4.12.14-122.212.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'kernel-default-4.12.14-122.212.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-base-4.12.14-122.212.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-devel-4.12.14-122.212.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-default-man-4.12.14-122.212.1', 'sp':'5', 'cpu':'s390x', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-devel-4.12.14-122.212.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-macros-4.12.14-122.212.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-source-4.12.14-122.212.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'kernel-syms-4.12.14-122.212.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
