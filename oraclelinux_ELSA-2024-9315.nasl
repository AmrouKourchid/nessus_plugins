#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-9315.
##

include('compat.inc');

if (description)
{
  script_id(211575);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/19");

  script_cve_id(
    "CVE-2019-25162",
    "CVE-2020-10135",
    "CVE-2021-47098",
    "CVE-2021-47101",
    "CVE-2021-47185",
    "CVE-2021-47384",
    "CVE-2021-47386",
    "CVE-2021-47428",
    "CVE-2021-47429",
    "CVE-2021-47432",
    "CVE-2021-47454",
    "CVE-2021-47457",
    "CVE-2021-47495",
    "CVE-2021-47497",
    "CVE-2021-47505",
    "CVE-2022-48669",
    "CVE-2022-48672",
    "CVE-2022-48703",
    "CVE-2022-48804",
    "CVE-2022-48929",
    "CVE-2023-52445",
    "CVE-2023-52451",
    "CVE-2023-52455",
    "CVE-2023-52462",
    "CVE-2023-52464",
    "CVE-2023-52466",
    "CVE-2023-52467",
    "CVE-2023-52473",
    "CVE-2023-52475",
    "CVE-2023-52477",
    "CVE-2023-52482",
    "CVE-2023-52490",
    "CVE-2023-52492",
    "CVE-2023-52498",
    "CVE-2023-52501",
    "CVE-2023-52513",
    "CVE-2023-52520",
    "CVE-2023-52528",
    "CVE-2023-52560",
    "CVE-2023-52565",
    "CVE-2023-52585",
    "CVE-2023-52594",
    "CVE-2023-52595",
    "CVE-2023-52606",
    "CVE-2023-52614",
    "CVE-2023-52615",
    "CVE-2023-52619",
    "CVE-2023-52621",
    "CVE-2023-52622",
    "CVE-2023-52624",
    "CVE-2023-52625",
    "CVE-2023-52632",
    "CVE-2023-52634",
    "CVE-2023-52635",
    "CVE-2023-52637",
    "CVE-2023-52643",
    "CVE-2023-52648",
    "CVE-2023-52649",
    "CVE-2023-52650",
    "CVE-2023-52656",
    "CVE-2023-52659",
    "CVE-2023-52661",
    "CVE-2023-52662",
    "CVE-2023-52663",
    "CVE-2023-52664",
    "CVE-2023-52674",
    "CVE-2023-52676",
    "CVE-2023-52679",
    "CVE-2023-52680",
    "CVE-2023-52683",
    "CVE-2023-52686",
    "CVE-2023-52689",
    "CVE-2023-52690",
    "CVE-2023-52696",
    "CVE-2023-52697",
    "CVE-2023-52698",
    "CVE-2023-52703",
    "CVE-2023-52730",
    "CVE-2023-52731",
    "CVE-2023-52740",
    "CVE-2023-52749",
    "CVE-2023-52751",
    "CVE-2023-52756",
    "CVE-2023-52757",
    "CVE-2023-52758",
    "CVE-2023-52762",
    "CVE-2023-52775",
    "CVE-2023-52784",
    "CVE-2023-52788",
    "CVE-2023-52791",
    "CVE-2023-52811",
    "CVE-2023-52813",
    "CVE-2023-52814",
    "CVE-2023-52817",
    "CVE-2023-52819",
    "CVE-2023-52831",
    "CVE-2023-52833",
    "CVE-2023-52834",
    "CVE-2023-52837",
    "CVE-2023-52840",
    "CVE-2023-52859",
    "CVE-2023-52867",
    "CVE-2023-52869",
    "CVE-2023-52878",
    "CVE-2023-52902",
    "CVE-2024-0340",
    "CVE-2024-1151",
    "CVE-2024-22099",
    "CVE-2024-23307",
    "CVE-2024-23848",
    "CVE-2024-24857",
    "CVE-2024-24858",
    "CVE-2024-24859",
    "CVE-2024-25739",
    "CVE-2024-26589",
    "CVE-2024-26591",
    "CVE-2024-26601",
    "CVE-2024-26603",
    "CVE-2024-26605",
    "CVE-2024-26611",
    "CVE-2024-26612",
    "CVE-2024-26614",
    "CVE-2024-26618",
    "CVE-2024-26631",
    "CVE-2024-26638",
    "CVE-2024-26641",
    "CVE-2024-26645",
    "CVE-2024-26646",
    "CVE-2024-26650",
    "CVE-2024-26656",
    "CVE-2024-26660",
    "CVE-2024-26661",
    "CVE-2024-26662",
    "CVE-2024-26663",
    "CVE-2024-26664",
    "CVE-2024-26669",
    "CVE-2024-26670",
    "CVE-2024-26672",
    "CVE-2024-26674",
    "CVE-2024-26675",
    "CVE-2024-26678",
    "CVE-2024-26679",
    "CVE-2024-26680",
    "CVE-2024-26686",
    "CVE-2024-26691",
    "CVE-2024-26700",
    "CVE-2024-26704",
    "CVE-2024-26707",
    "CVE-2024-26708",
    "CVE-2024-26712",
    "CVE-2024-26717",
    "CVE-2024-26719",
    "CVE-2024-26725",
    "CVE-2024-26733",
    "CVE-2024-26740",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26746",
    "CVE-2024-26757",
    "CVE-2024-26758",
    "CVE-2024-26759",
    "CVE-2024-26761",
    "CVE-2024-26767",
    "CVE-2024-26772",
    "CVE-2024-26774",
    "CVE-2024-26782",
    "CVE-2024-26785",
    "CVE-2024-26786",
    "CVE-2024-26803",
    "CVE-2024-26812",
    "CVE-2024-26815",
    "CVE-2024-26835",
    "CVE-2024-26837",
    "CVE-2024-26838",
    "CVE-2024-26840",
    "CVE-2024-26843",
    "CVE-2024-26846",
    "CVE-2024-26857",
    "CVE-2024-26861",
    "CVE-2024-26862",
    "CVE-2024-26863",
    "CVE-2024-26870",
    "CVE-2024-26872",
    "CVE-2024-26878",
    "CVE-2024-26882",
    "CVE-2024-26889",
    "CVE-2024-26890",
    "CVE-2024-26892",
    "CVE-2024-26894",
    "CVE-2024-26899",
    "CVE-2024-26900",
    "CVE-2024-26901",
    "CVE-2024-26903",
    "CVE-2024-26906",
    "CVE-2024-26907",
    "CVE-2024-26915",
    "CVE-2024-26920",
    "CVE-2024-26921",
    "CVE-2024-26922",
    "CVE-2024-26924",
    "CVE-2024-26927",
    "CVE-2024-26928",
    "CVE-2024-26933",
    "CVE-2024-26934",
    "CVE-2024-26937",
    "CVE-2024-26938",
    "CVE-2024-26939",
    "CVE-2024-26940",
    "CVE-2024-26950",
    "CVE-2024-26951",
    "CVE-2024-26953",
    "CVE-2024-26958",
    "CVE-2024-26960",
    "CVE-2024-26962",
    "CVE-2024-26964",
    "CVE-2024-26973",
    "CVE-2024-26975",
    "CVE-2024-26976",
    "CVE-2024-26984",
    "CVE-2024-26987",
    "CVE-2024-26988",
    "CVE-2024-26989",
    "CVE-2024-26990",
    "CVE-2024-26992",
    "CVE-2024-27003",
    "CVE-2024-27004",
    "CVE-2024-27010",
    "CVE-2024-27011",
    "CVE-2024-27012",
    "CVE-2024-27013",
    "CVE-2024-27014",
    "CVE-2024-27015",
    "CVE-2024-27017",
    "CVE-2024-27023",
    "CVE-2024-27025",
    "CVE-2024-27038",
    "CVE-2024-27042",
    "CVE-2024-27048",
    "CVE-2024-27057",
    "CVE-2024-27062",
    "CVE-2024-27079",
    "CVE-2024-27389",
    "CVE-2024-27395",
    "CVE-2024-27404",
    "CVE-2024-27410",
    "CVE-2024-27414",
    "CVE-2024-27431",
    "CVE-2024-27436",
    "CVE-2024-27437",
    "CVE-2024-31076",
    "CVE-2024-35787",
    "CVE-2024-35794",
    "CVE-2024-35795",
    "CVE-2024-35801",
    "CVE-2024-35805",
    "CVE-2024-35807",
    "CVE-2024-35808",
    "CVE-2024-35809",
    "CVE-2024-35810",
    "CVE-2024-35812",
    "CVE-2024-35814",
    "CVE-2024-35817",
    "CVE-2024-35822",
    "CVE-2024-35824",
    "CVE-2024-35827",
    "CVE-2024-35831",
    "CVE-2024-35835",
    "CVE-2024-35838",
    "CVE-2024-35840",
    "CVE-2024-35843",
    "CVE-2024-35847",
    "CVE-2024-35853",
    "CVE-2024-35854",
    "CVE-2024-35855",
    "CVE-2024-35859",
    "CVE-2024-35861",
    "CVE-2024-35862",
    "CVE-2024-35863",
    "CVE-2024-35864",
    "CVE-2024-35865",
    "CVE-2024-35866",
    "CVE-2024-35867",
    "CVE-2024-35869",
    "CVE-2024-35872",
    "CVE-2024-35876",
    "CVE-2024-35877",
    "CVE-2024-35878",
    "CVE-2024-35880",
    "CVE-2024-35886",
    "CVE-2024-35888",
    "CVE-2024-35892",
    "CVE-2024-35894",
    "CVE-2024-35900",
    "CVE-2024-35904",
    "CVE-2024-35905",
    "CVE-2024-35908",
    "CVE-2024-35912",
    "CVE-2024-35913",
    "CVE-2024-35918",
    "CVE-2024-35923",
    "CVE-2024-35924",
    "CVE-2024-35925",
    "CVE-2024-35927",
    "CVE-2024-35928",
    "CVE-2024-35930",
    "CVE-2024-35931",
    "CVE-2024-35938",
    "CVE-2024-35939",
    "CVE-2024-35942",
    "CVE-2024-35944",
    "CVE-2024-35946",
    "CVE-2024-35947",
    "CVE-2024-35950",
    "CVE-2024-35952",
    "CVE-2024-35954",
    "CVE-2024-35957",
    "CVE-2024-35959",
    "CVE-2024-35973",
    "CVE-2024-35976",
    "CVE-2024-35979",
    "CVE-2024-35983",
    "CVE-2024-35991",
    "CVE-2024-35995",
    "CVE-2024-36006",
    "CVE-2024-36010",
    "CVE-2024-36015",
    "CVE-2024-36022",
    "CVE-2024-36028",
    "CVE-2024-36030",
    "CVE-2024-36031",
    "CVE-2024-36477",
    "CVE-2024-36881",
    "CVE-2024-36882",
    "CVE-2024-36884",
    "CVE-2024-36885",
    "CVE-2024-36891",
    "CVE-2024-36896",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36905",
    "CVE-2024-36917",
    "CVE-2024-36920",
    "CVE-2024-36926",
    "CVE-2024-36927",
    "CVE-2024-36930",
    "CVE-2024-36932",
    "CVE-2024-36933",
    "CVE-2024-36936",
    "CVE-2024-36939",
    "CVE-2024-36940",
    "CVE-2024-36944",
    "CVE-2024-36945",
    "CVE-2024-36955",
    "CVE-2024-36956",
    "CVE-2024-36960",
    "CVE-2024-36961",
    "CVE-2024-36967",
    "CVE-2024-36974",
    "CVE-2024-36977",
    "CVE-2024-38388",
    "CVE-2024-38555",
    "CVE-2024-38581",
    "CVE-2024-38596",
    "CVE-2024-38598",
    "CVE-2024-38600",
    "CVE-2024-38604",
    "CVE-2024-38605",
    "CVE-2024-38618",
    "CVE-2024-38627",
    "CVE-2024-38629",
    "CVE-2024-38632",
    "CVE-2024-38635",
    "CVE-2024-39276",
    "CVE-2024-39291",
    "CVE-2024-39298",
    "CVE-2024-39471",
    "CVE-2024-39473",
    "CVE-2024-39474",
    "CVE-2024-39479",
    "CVE-2024-39486",
    "CVE-2024-39488",
    "CVE-2024-39491",
    "CVE-2024-39497",
    "CVE-2024-39498",
    "CVE-2024-39499",
    "CVE-2024-39501",
    "CVE-2024-39503",
    "CVE-2024-39507",
    "CVE-2024-39508",
    "CVE-2024-40901",
    "CVE-2024-40903",
    "CVE-2024-40906",
    "CVE-2024-40907",
    "CVE-2024-40913",
    "CVE-2024-40919",
    "CVE-2024-40922",
    "CVE-2024-40923",
    "CVE-2024-40924",
    "CVE-2024-40925",
    "CVE-2024-40930",
    "CVE-2024-40940",
    "CVE-2024-40945",
    "CVE-2024-40948",
    "CVE-2024-40965",
    "CVE-2024-40966",
    "CVE-2024-40967",
    "CVE-2024-40988",
    "CVE-2024-40989",
    "CVE-2024-40997",
    "CVE-2024-41001",
    "CVE-2024-41007",
    "CVE-2024-41008",
    "CVE-2024-41012",
    "CVE-2024-41020",
    "CVE-2024-41032",
    "CVE-2024-41038",
    "CVE-2024-41039",
    "CVE-2024-41042",
    "CVE-2024-41049",
    "CVE-2024-41056",
    "CVE-2024-41057",
    "CVE-2024-41058",
    "CVE-2024-41060",
    "CVE-2024-41063",
    "CVE-2024-41065",
    "CVE-2024-41077",
    "CVE-2024-41079",
    "CVE-2024-41082",
    "CVE-2024-41084",
    "CVE-2024-41085",
    "CVE-2024-41089",
    "CVE-2024-41092",
    "CVE-2024-41093",
    "CVE-2024-41094",
    "CVE-2024-41095",
    "CVE-2024-42070",
    "CVE-2024-42078",
    "CVE-2024-42084",
    "CVE-2024-42090",
    "CVE-2024-42101",
    "CVE-2024-42114",
    "CVE-2024-42123",
    "CVE-2024-42124",
    "CVE-2024-42125",
    "CVE-2024-42132",
    "CVE-2024-42141",
    "CVE-2024-42154",
    "CVE-2024-42159",
    "CVE-2024-42226",
    "CVE-2024-42228",
    "CVE-2024-42237",
    "CVE-2024-42238",
    "CVE-2024-42240",
    "CVE-2024-42245",
    "CVE-2024-42258",
    "CVE-2024-42268",
    "CVE-2024-42271",
    "CVE-2024-42276",
    "CVE-2024-42301",
    "CVE-2024-43817",
    "CVE-2024-43826",
    "CVE-2024-43830",
    "CVE-2024-43842",
    "CVE-2024-43856",
    "CVE-2024-43865",
    "CVE-2024-43866",
    "CVE-2024-43869",
    "CVE-2024-43870",
    "CVE-2024-43879",
    "CVE-2024-43888",
    "CVE-2024-43892",
    "CVE-2024-43911",
    "CVE-2024-44947",
    "CVE-2024-44960",
    "CVE-2024-44965",
    "CVE-2024-44970",
    "CVE-2024-44984",
    "CVE-2024-45005"
  );
  script_xref(name:"IAVA", value:"2024-A-0487");

  script_name(english:"Oracle Linux 9 : kernel (ELSA-2024-9315)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-9315 advisory.

    - memcg: protect concurrent access to mem_cgroup_idr (Rafael Aquini) [RHEL-56254] {CVE-2024-43892}
    - bnxt_en: Fix double DMA unmapping for XDP_REDIRECT (Michal Schmidt) [RHEL-57259] {CVE-2024-44984}
    - dma: fix call order in dmam_free_coherent (Eder Zulian) [RHEL-54751] {CVE-2024-43856}
    - dmaengine: idxd: Avoid unnecessary destruction of file_ida (Jerry Snitselaar) [RHEL-44508]
    {CVE-2024-38629}
    - tipc: Return non-zero value from tipc_udp_addr2str() on error (Xin Long) [RHEL-55074] {CVE-2024-42284}
    - net/mlx5e: SHAMPO, Fix invalid WQ linked list unlink (Michal Schmidt) [RHEL-57119] {CVE-2024-44970}
    - net/mlx5e: Fix CT entry update leaks of modify header context (Michal Schmidt) [RHEL-55628]
    {CVE-2024-43864}
    - net/mlx5: Always drain health in shutdown callback (Michal Schmidt) [RHEL-55616] {CVE-2024-43866}
    - net/mlx5: Fix missing lock on sync reset reload (Michal Schmidt) [RHEL-55121] {CVE-2024-42268}
    - ionic: fix kernel panic in XDP_TX action (CKI Backport Bot) [RHEL-47730] {CVE-2024-40907}
    - r8169: Fix possible ring buffer corruption on fragmented Tx packets. (Izabela Bakollari) [RHEL-44037]
    {CVE-2024-38586}
    - KVM: s390: fix validity interception issue when gisa is switched off (CKI Backport Bot) [RHEL-57197]
    {CVE-2024-45005}
    - wifi: cfg80211: handle 2x996 RU allocation in cfg80211_calculate_bitrate_he() (Jose Ignacio Tornos
    Martinez) [RHEL-55579] {CVE-2024-43879}
    - wifi: mac80211: fix NULL dereference at band check in starting tx ba session (Jose Ignacio Tornos
    Martinez) [RHEL-56191] {CVE-2024-43911}
    - wifi: rtw89: Fix array index mistake in rtw89_sta_info_get_iter() (Jose Ignacio Tornos Martinez)
    [RHEL-54805] {CVE-2024-43842}
    - gfs2: Fix NULL pointer dereference in gfs2_log_flush (Andrew Price) [RHEL-51559] {CVE-2024-42079}
    - x86/mm: Fix pti_clone_pgtable() alignment assumption (Rafael Aquini) [RHEL-57170] {CVE-2024-44965}
    - bnxt_en: Adjust logging of firmware messages in case of released token in __hwrm_send() (CKI Backport
    Bot) [RHEL-47822] {CVE-2024-40919}
    - netfilter: tproxy: bail out if IP has been disabled on the device (Phil Sutter) [RHEL-44369]
    {CVE-2024-36270}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-9315.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10135");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-43888");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:5:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9:5:baseos_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uki-virt-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rtla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['5.14.0-503.11.1.el9_5'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2024-9315');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '5.14';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'bpftool-7.4.0-503.11.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-cross-headers-5.14.0-503.11.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-headers-5.14.0-503.11.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-tools-5.14.0-503.11.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-503.11.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-503.11.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'libperf-5.14.0-503.11.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-503.11.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-503.11.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-503.11.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-503.11.1.el9_5', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftool-7.4.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-5.14.0'},
    {'reference':'kernel-abi-stablelists-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-stablelists-5.14.0'},
    {'reference':'kernel-core-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-core-5.14.0'},
    {'reference':'kernel-cross-headers-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-cross-headers-5.14.0'},
    {'reference':'kernel-debug-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-5.14.0'},
    {'reference':'kernel-debug-core-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-core-5.14.0'},
    {'reference':'kernel-debug-devel-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-5.14.0'},
    {'reference':'kernel-debug-devel-matched-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-matched-5.14.0'},
    {'reference':'kernel-debug-modules-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-5.14.0'},
    {'reference':'kernel-debug-modules-core-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-core-5.14.0'},
    {'reference':'kernel-debug-modules-extra-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-modules-extra-5.14.0'},
    {'reference':'kernel-debug-uki-virt-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-uki-virt-5.14.0'},
    {'reference':'kernel-devel-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-5.14.0'},
    {'reference':'kernel-devel-matched-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-matched-5.14.0'},
    {'reference':'kernel-headers-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-5.14.0'},
    {'reference':'kernel-modules-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-5.14.0'},
    {'reference':'kernel-modules-core-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-core-5.14.0'},
    {'reference':'kernel-modules-extra-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-modules-extra-5.14.0'},
    {'reference':'kernel-tools-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-5.14.0'},
    {'reference':'kernel-tools-libs-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-5.14.0'},
    {'reference':'kernel-tools-libs-devel-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-5.14.0'},
    {'reference':'kernel-uki-virt-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uki-virt-5.14.0'},
    {'reference':'kernel-uki-virt-addons-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-uki-virt-addons-5.14.0'},
    {'reference':'libperf-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-perf-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rtla-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rv-5.14.0-503.11.1.el9_5', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / etc');
}
