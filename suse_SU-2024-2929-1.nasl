#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2929-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(205650);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2021-4439",
    "CVE-2021-47534",
    "CVE-2021-47576",
    "CVE-2021-47578",
    "CVE-2021-47580",
    "CVE-2021-47582",
    "CVE-2021-47583",
    "CVE-2021-47584",
    "CVE-2021-47585",
    "CVE-2021-47586",
    "CVE-2021-47587",
    "CVE-2021-47589",
    "CVE-2021-47592",
    "CVE-2021-47596",
    "CVE-2021-47597",
    "CVE-2021-47598",
    "CVE-2021-47600",
    "CVE-2021-47601",
    "CVE-2021-47602",
    "CVE-2021-47603",
    "CVE-2021-47607",
    "CVE-2021-47608",
    "CVE-2021-47609",
    "CVE-2021-47611",
    "CVE-2021-47612",
    "CVE-2021-47614",
    "CVE-2021-47615",
    "CVE-2021-47616",
    "CVE-2021-47617",
    "CVE-2021-47618",
    "CVE-2021-47619",
    "CVE-2021-47620",
    "CVE-2021-47622",
    "CVE-2021-47624",
    "CVE-2022-0854",
    "CVE-2022-2964",
    "CVE-2022-20368",
    "CVE-2022-28748",
    "CVE-2022-48711",
    "CVE-2022-48712",
    "CVE-2022-48713",
    "CVE-2022-48715",
    "CVE-2022-48717",
    "CVE-2022-48720",
    "CVE-2022-48721",
    "CVE-2022-48722",
    "CVE-2022-48723",
    "CVE-2022-48724",
    "CVE-2022-48725",
    "CVE-2022-48726",
    "CVE-2022-48727",
    "CVE-2022-48728",
    "CVE-2022-48729",
    "CVE-2022-48730",
    "CVE-2022-48732",
    "CVE-2022-48734",
    "CVE-2022-48735",
    "CVE-2022-48736",
    "CVE-2022-48737",
    "CVE-2022-48738",
    "CVE-2022-48739",
    "CVE-2022-48740",
    "CVE-2022-48743",
    "CVE-2022-48744",
    "CVE-2022-48745",
    "CVE-2022-48746",
    "CVE-2022-48747",
    "CVE-2022-48749",
    "CVE-2022-48751",
    "CVE-2022-48752",
    "CVE-2022-48754",
    "CVE-2022-48756",
    "CVE-2022-48758",
    "CVE-2022-48759",
    "CVE-2022-48760",
    "CVE-2022-48761",
    "CVE-2022-48763",
    "CVE-2022-48765",
    "CVE-2022-48767",
    "CVE-2022-48768",
    "CVE-2022-48769",
    "CVE-2022-48771",
    "CVE-2022-48773",
    "CVE-2022-48774",
    "CVE-2022-48775",
    "CVE-2022-48776",
    "CVE-2022-48777",
    "CVE-2022-48778",
    "CVE-2022-48780",
    "CVE-2022-48783",
    "CVE-2022-48784",
    "CVE-2022-48786",
    "CVE-2022-48787",
    "CVE-2022-48788",
    "CVE-2022-48789",
    "CVE-2022-48790",
    "CVE-2022-48791",
    "CVE-2022-48792",
    "CVE-2022-48793",
    "CVE-2022-48794",
    "CVE-2022-48796",
    "CVE-2022-48797",
    "CVE-2022-48798",
    "CVE-2022-48799",
    "CVE-2022-48800",
    "CVE-2022-48801",
    "CVE-2022-48802",
    "CVE-2022-48803",
    "CVE-2022-48804",
    "CVE-2022-48805",
    "CVE-2022-48806",
    "CVE-2022-48807",
    "CVE-2022-48811",
    "CVE-2022-48812",
    "CVE-2022-48813",
    "CVE-2022-48814",
    "CVE-2022-48815",
    "CVE-2022-48816",
    "CVE-2022-48817",
    "CVE-2022-48818",
    "CVE-2022-48820",
    "CVE-2022-48821",
    "CVE-2022-48822",
    "CVE-2022-48823",
    "CVE-2022-48824",
    "CVE-2022-48825",
    "CVE-2022-48826",
    "CVE-2022-48827",
    "CVE-2022-48828",
    "CVE-2022-48829",
    "CVE-2022-48830",
    "CVE-2022-48831",
    "CVE-2022-48834",
    "CVE-2022-48835",
    "CVE-2022-48836",
    "CVE-2022-48837",
    "CVE-2022-48838",
    "CVE-2022-48839",
    "CVE-2022-48840",
    "CVE-2022-48841",
    "CVE-2022-48842",
    "CVE-2022-48843",
    "CVE-2022-48847",
    "CVE-2022-48849",
    "CVE-2022-48851",
    "CVE-2022-48853",
    "CVE-2022-48856",
    "CVE-2022-48857",
    "CVE-2022-48858",
    "CVE-2022-48859",
    "CVE-2022-48860",
    "CVE-2022-48861",
    "CVE-2022-48862",
    "CVE-2022-48863",
    "CVE-2022-48866",
    "CVE-2023-1582",
    "CVE-2023-37453",
    "CVE-2023-52591",
    "CVE-2023-52762",
    "CVE-2023-52766",
    "CVE-2023-52800",
    "CVE-2023-52885",
    "CVE-2023-52886",
    "CVE-2024-26583",
    "CVE-2024-26584",
    "CVE-2024-26585",
    "CVE-2024-26800",
    "CVE-2024-26813",
    "CVE-2024-26814",
    "CVE-2024-26976",
    "CVE-2024-35878",
    "CVE-2024-35901",
    "CVE-2024-35905",
    "CVE-2024-36926",
    "CVE-2024-36974",
    "CVE-2024-38541",
    "CVE-2024-38555",
    "CVE-2024-38559",
    "CVE-2024-39463",
    "CVE-2024-39494",
    "CVE-2024-40902",
    "CVE-2024-40937",
    "CVE-2024-40954",
    "CVE-2024-40956",
    "CVE-2024-40989",
    "CVE-2024-40994",
    "CVE-2024-41011",
    "CVE-2024-41012",
    "CVE-2024-41059",
    "CVE-2024-41069",
    "CVE-2024-41090",
    "CVE-2024-42093",
    "CVE-2024-42145",
    "CVE-2024-42230"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2929-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2024:2929-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:2929-1 advisory.

    The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.


    The following security bugs were fixed:

    - CVE-2024-39494: ima: Fix use-after-free on a dentry's dname.name (bsc#1227716).
    - CVE-2024-41069: ASoC: topology: Fix route memory corruption (bsc#1228644).
    - CVE-2024-40954: net: do not leave a dangling sk pointer, when socket creation fails (bsc#1227808)
    - CVE-2024-42145: IB/core: Implement a limit on UMAD receive List (bsc#1228743)
    - CVE-2024-40994: ptp: fix integer overflow in max_vclocks_store (bsc#1227829).
    - CVE-2024-41012: filelock: Remove locks reliably when fcntl/close race is detected (bsc#1228247).
    - CVE-2024-42093: net/dpaa2: Avoid explicit cpumask var allocation on stack (bsc#1228680).
    - CVE-2024-40989: KVM: arm64: Disassociate vcpus from redistributor region on teardown (bsc#1227823).
    - CVE-2024-41059: hfsplus: fix uninit-value in copy_name (bsc#1228561).
    - CVE-2024-40956: dmaengine: idxd: Fix possible Use-After-Free in irq_process_work_list (bsc#1227810).
    - CVE-2024-41090: tap: add missing verification for short frame (bsc#1228328).
    - CVE-2024-41011: drm/amdkfd: do not allow mapping the MMIO HDP page with large pages (bsc#1228114).
    - CVE-2024-39463: 9p: add missing locking around taking dentry fid list (bsc#1227090).
    - CVE-2021-47598: sch_cake: do not call cake_destroy() from cake_init() (bsc#1226574).
    - CVE-2024-40937: gve: Clear napi->skb before dev_kfree_skb_any() (bsc#1227836).
    - CVE-2024-35901: net: mana: Fix Rx DMA datasize and skb_over_panic (bsc#1224495).
    - CVE-2024-42230: powerpc/pseries: Fix scv instruction crash with kexec (bsc#1194869).
    - CVE-2024-26585: Fixed race between tx work scheduling and socket close (bsc#1220187).
    - CVE-2024-36974: net/sched: taprio: always validate TCA_TAPRIO_ATTR_PRIOMAP (bsc#1226519).
    - CVE-2024-38555: net/mlx5: Discard command completions in internal error (bsc#1226607).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194324");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226603");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227487");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227808");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227917");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228009");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228025");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228064");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228743");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228801");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-August/036473.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4439");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47534");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47576");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47578");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47580");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47584");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47585");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47589");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47596");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47612");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47614");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47616");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47617");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47618");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47622");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47624");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20368");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48711");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48712");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48717");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48721");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48722");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48724");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48725");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48726");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48727");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48728");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48729");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48732");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48734");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48736");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48737");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48738");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48744");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48745");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48746");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48747");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48749");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48751");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48752");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48754");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48758");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48759");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48761");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48763");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48765");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48767");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48768");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48769");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48771");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48773");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48776");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48778");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48783");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48787");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48790");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48792");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48793");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48794");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48796");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48797");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48799");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48801");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48802");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48804");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48806");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48807");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48812");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48818");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48820");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48822");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48824");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48825");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48826");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48828");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48830");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48831");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48836");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48839");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48842");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48859");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48860");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-37453");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52762");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52766");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52885");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52886");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26584");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26585");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26814");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-36974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38555");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38559");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39463");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39494");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40902");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40954");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40994");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41012");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41069");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41090");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42093");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42230");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0854");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-42093");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/16");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150400_24_128-default");
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
    {'reference':'kernel-default-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.128.1.150400.24.62.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-devel-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-macros-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-source-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-64kb-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-64kb-devel-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'kernel-default-base-5.14.21-150400.24.128.1.150400.24.62.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.128.1.150400.24.62.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'kernel-devel-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-macros-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-source-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-syms-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-syms-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-64kb-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-64kb-devel-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.128.1.150400.24.62.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.128.1.150400.24.62.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-devel-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-macros-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-source-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-syms-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-zfcpdump-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'cluster-md-kmp-default-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'dlm-kmp-default-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'gfs2-kmp-default-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'ocfs2-kmp-default-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'kernel-default-livepatch-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-default-livepatch-devel-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-livepatch-5_14_21-150400_24_128-default-1-150400.9.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-zfcpdump-5.14.21-150400.24.128.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.128.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']}
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
      severity   : SECURITY_NOTE,
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
