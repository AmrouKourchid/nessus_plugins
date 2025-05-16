#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1263-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(234484);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/16");

  script_cve_id(
    "CVE-2017-5753",
    "CVE-2020-27835",
    "CVE-2021-47248",
    "CVE-2021-47631",
    "CVE-2021-47641",
    "CVE-2021-47642",
    "CVE-2021-47650",
    "CVE-2021-47651",
    "CVE-2021-47652",
    "CVE-2021-47653",
    "CVE-2021-47659",
    "CVE-2022-0168",
    "CVE-2022-1016",
    "CVE-2022-1048",
    "CVE-2022-1184",
    "CVE-2022-2977",
    "CVE-2022-3303",
    "CVE-2022-29900",
    "CVE-2022-29901",
    "CVE-2022-49044",
    "CVE-2022-49051",
    "CVE-2022-49053",
    "CVE-2022-49055",
    "CVE-2022-49058",
    "CVE-2022-49059",
    "CVE-2022-49063",
    "CVE-2022-49065",
    "CVE-2022-49073",
    "CVE-2022-49076",
    "CVE-2022-49078",
    "CVE-2022-49082",
    "CVE-2022-49083",
    "CVE-2022-49085",
    "CVE-2022-49091",
    "CVE-2022-49095",
    "CVE-2022-49098",
    "CVE-2022-49100",
    "CVE-2022-49111",
    "CVE-2022-49114",
    "CVE-2022-49122",
    "CVE-2022-49137",
    "CVE-2022-49145",
    "CVE-2022-49151",
    "CVE-2022-49153",
    "CVE-2022-49155",
    "CVE-2022-49156",
    "CVE-2022-49157",
    "CVE-2022-49158",
    "CVE-2022-49159",
    "CVE-2022-49160",
    "CVE-2022-49162",
    "CVE-2022-49164",
    "CVE-2022-49175",
    "CVE-2022-49185",
    "CVE-2022-49189",
    "CVE-2022-49196",
    "CVE-2022-49200",
    "CVE-2022-49201",
    "CVE-2022-49206",
    "CVE-2022-49212",
    "CVE-2022-49213",
    "CVE-2022-49216",
    "CVE-2022-49217",
    "CVE-2022-49224",
    "CVE-2022-49226",
    "CVE-2022-49232",
    "CVE-2022-49235",
    "CVE-2022-49239",
    "CVE-2022-49242",
    "CVE-2022-49243",
    "CVE-2022-49247",
    "CVE-2022-49248",
    "CVE-2022-49253",
    "CVE-2022-49259",
    "CVE-2022-49261",
    "CVE-2022-49263",
    "CVE-2022-49264",
    "CVE-2022-49271",
    "CVE-2022-49272",
    "CVE-2022-49275",
    "CVE-2022-49279",
    "CVE-2022-49280",
    "CVE-2022-49281",
    "CVE-2022-49285",
    "CVE-2022-49287",
    "CVE-2022-49288",
    "CVE-2022-49290",
    "CVE-2022-49291",
    "CVE-2022-49292",
    "CVE-2022-49293",
    "CVE-2022-49295",
    "CVE-2022-49297",
    "CVE-2022-49298",
    "CVE-2022-49299",
    "CVE-2022-49300",
    "CVE-2022-49301",
    "CVE-2022-49302",
    "CVE-2022-49304",
    "CVE-2022-49305",
    "CVE-2022-49307",
    "CVE-2022-49313",
    "CVE-2022-49314",
    "CVE-2022-49315",
    "CVE-2022-49316",
    "CVE-2022-49320",
    "CVE-2022-49321",
    "CVE-2022-49326",
    "CVE-2022-49327",
    "CVE-2022-49331",
    "CVE-2022-49332",
    "CVE-2022-49335",
    "CVE-2022-49343",
    "CVE-2022-49347",
    "CVE-2022-49349",
    "CVE-2022-49352",
    "CVE-2022-49357",
    "CVE-2022-49370",
    "CVE-2022-49371",
    "CVE-2022-49373",
    "CVE-2022-49375",
    "CVE-2022-49376",
    "CVE-2022-49382",
    "CVE-2022-49385",
    "CVE-2022-49389",
    "CVE-2022-49394",
    "CVE-2022-49396",
    "CVE-2022-49397",
    "CVE-2022-49398",
    "CVE-2022-49399",
    "CVE-2022-49402",
    "CVE-2022-49404",
    "CVE-2022-49409",
    "CVE-2022-49410",
    "CVE-2022-49411",
    "CVE-2022-49413",
    "CVE-2022-49414",
    "CVE-2022-49416",
    "CVE-2022-49421",
    "CVE-2022-49422",
    "CVE-2022-49437",
    "CVE-2022-49438",
    "CVE-2022-49441",
    "CVE-2022-49442",
    "CVE-2022-49446",
    "CVE-2022-49451",
    "CVE-2022-49455",
    "CVE-2022-49459",
    "CVE-2022-49460",
    "CVE-2022-49462",
    "CVE-2022-49465",
    "CVE-2022-49467",
    "CVE-2022-49473",
    "CVE-2022-49474",
    "CVE-2022-49475",
    "CVE-2022-49478",
    "CVE-2022-49481",
    "CVE-2022-49482",
    "CVE-2022-49488",
    "CVE-2022-49489",
    "CVE-2022-49490",
    "CVE-2022-49491",
    "CVE-2022-49493",
    "CVE-2022-49495",
    "CVE-2022-49498",
    "CVE-2022-49503",
    "CVE-2022-49504",
    "CVE-2022-49505",
    "CVE-2022-49508",
    "CVE-2022-49514",
    "CVE-2022-49517",
    "CVE-2022-49521",
    "CVE-2022-49522",
    "CVE-2022-49524",
    "CVE-2022-49525",
    "CVE-2022-49526",
    "CVE-2022-49527",
    "CVE-2022-49532",
    "CVE-2022-49534",
    "CVE-2022-49535",
    "CVE-2022-49536",
    "CVE-2022-49537",
    "CVE-2022-49541",
    "CVE-2022-49542",
    "CVE-2022-49544",
    "CVE-2022-49545",
    "CVE-2022-49546",
    "CVE-2022-49555",
    "CVE-2022-49563",
    "CVE-2022-49564",
    "CVE-2022-49566",
    "CVE-2022-49609",
    "CVE-2022-49610",
    "CVE-2022-49611",
    "CVE-2022-49623",
    "CVE-2022-49627",
    "CVE-2022-49631",
    "CVE-2022-49640",
    "CVE-2022-49641",
    "CVE-2022-49643",
    "CVE-2022-49644",
    "CVE-2022-49645",
    "CVE-2022-49646",
    "CVE-2022-49647",
    "CVE-2022-49648",
    "CVE-2022-49649",
    "CVE-2022-49652",
    "CVE-2022-49657",
    "CVE-2022-49661",
    "CVE-2022-49670",
    "CVE-2022-49671",
    "CVE-2022-49673",
    "CVE-2022-49674",
    "CVE-2022-49678",
    "CVE-2022-49685",
    "CVE-2022-49687",
    "CVE-2022-49693",
    "CVE-2022-49700",
    "CVE-2022-49701",
    "CVE-2022-49703",
    "CVE-2022-49707",
    "CVE-2022-49708",
    "CVE-2022-49710",
    "CVE-2022-49711",
    "CVE-2022-49712",
    "CVE-2022-49713",
    "CVE-2022-49720",
    "CVE-2022-49723",
    "CVE-2022-49724",
    "CVE-2022-49729",
    "CVE-2022-49730",
    "CVE-2022-49731",
    "CVE-2022-49733",
    "CVE-2022-49739",
    "CVE-2023-2162",
    "CVE-2023-3567",
    "CVE-2023-52935",
    "CVE-2023-52973",
    "CVE-2023-52974",
    "CVE-2023-53000",
    "CVE-2023-53015",
    "CVE-2023-53024",
    "CVE-2024-50290",
    "CVE-2024-53063",
    "CVE-2024-56642",
    "CVE-2024-56651",
    "CVE-2024-57996",
    "CVE-2024-58014",
    "CVE-2025-21772",
    "CVE-2025-21780"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1263-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2025:1263-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2025:1263-1 advisory.

    The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2021-47248: udp: fix race between close() and udp_abort() (bsc#1224867).
    - CVE-2022-49051: net: usb: aqc111: Fix out-of-bounds accesses in RX fixup (bsc#1237903).
    - CVE-2022-49053: scsi: target: tcmu: Fix possible page UAF (bsc#1237918).
    - CVE-2022-49275: can: m_can: m_can_tx_handler(): fix use after free of skb (bsc#1238719).
    - CVE-2022-49413: bfq: Update cgroup information before merging bio (bsc#1238710).
    - CVE-2022-49465: blk-throttle: Set BIO_THROTTLED when bio has been throttled (bsc#1238919).
    - CVE-2022-49545: ALSA: usb-audio: Cancel pending work at closing a MIDI substream (bsc#1238729).
    - CVE-2022-49563: crypto: qat - add param check for RSA (bsc#1238787).
    - CVE-2022-49564: crypto: qat - add param check for DH (bsc#1238789).
    - CVE-2022-49739: gfs2: Always check inode size of inline inodes (bsc#1240207).
    - CVE-2023-52935: mm/khugepaged: fix ->anon_vma race (bsc#1240276).
    - CVE-2024-56642: tipc: Fix use-after-free of kernel socket in cleanup_bearer() (bsc#1235433).
    - CVE-2024-56651: can: hi311x: hi3110_can_ist(): fix potential use-after-free (bsc#1235528).
    - CVE-2024-57996: net_sched: sch_sfq: do not allow 1 packet limit (bsc#1239076).
    - CVE-2024-58014: wifi: brcmsmac: add gain range check to wlc_phy_iqcal_gainparams_nphy() (bsc#1239109).
    - CVE-2025-21772: partitions: mac: fix handling of bogus partition table (bsc#1238911).
    - CVE-2025-21780: drm/amdgpu: avoid buffer overflow attach in smu_sys_set_pp_table() (bsc#1239115).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200217");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201193");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203769");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237783");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237839");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237918");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1237998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238096");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238146");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238156");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238184");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238228");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238257");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238263");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238336");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238337");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238338");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238372");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238394");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238419");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238633");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238662");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238663");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238809");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238835");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1238952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239115");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1239969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1240288");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-April/020707.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86522940");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-5753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47248");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47650");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-47659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0168");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3303");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49044");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49051");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49053");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49058");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49059");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49065");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49073");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49076");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49083");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49091");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49100");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49111");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49122");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49137");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49145");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49151");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49153");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49157");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49159");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49164");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49175");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49185");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49189");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49196");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49200");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49201");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49206");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49212");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49213");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49216");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49217");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49224");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49226");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49232");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49235");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49239");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49242");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49243");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49247");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49248");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49253");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49259");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49261");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49263");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49264");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49271");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49272");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49275");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49279");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49280");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49281");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49287");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49291");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49292");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49293");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49295");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49297");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49298");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49299");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49300");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49301");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49302");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49304");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49305");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49307");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49313");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49314");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49315");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49316");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49320");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49321");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49326");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49327");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49331");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49332");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49335");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49343");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49347");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49349");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49352");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49357");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49370");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49371");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49373");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49375");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49376");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49382");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49385");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49389");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49394");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49396");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49397");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49398");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49399");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49404");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49409");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49410");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49411");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49413");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49414");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49416");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49421");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49422");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49437");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49438");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49441");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49442");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49446");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49451");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49455");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49459");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49460");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49462");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49465");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49467");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49473");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49474");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49475");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49478");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49481");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49482");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49488");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49489");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49490");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49491");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49493");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49495");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49498");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49503");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49504");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49505");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49508");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49514");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49517");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49522");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49524");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49525");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49526");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49527");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49532");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49534");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49535");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49536");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49537");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49541");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49542");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49544");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49555");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49563");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49564");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49566");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49623");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49627");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49643");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49644");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49646");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49647");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49648");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49649");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49652");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49661");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49670");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49671");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49673");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49674");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49687");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49693");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49700");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49701");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49703");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49710");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49711");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49712");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49724");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49729");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49730");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49731");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-49739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52973");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52974");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53000");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53015");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-53024");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-50290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-53063");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56642");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-56651");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-57996");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-58014");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21780");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1048");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-56651");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/16");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_201-default");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.201.1.150300.18.120.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-devel-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-macros-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-source-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-64kb-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-64kb-devel-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.201.1.150300.18.120.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.201.1.150300.18.120.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-devel-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-macros-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-source-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'cluster-md-kmp-default-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'dlm-kmp-default-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'gfs2-kmp-default-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'ocfs2-kmp-default-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'kernel-default-livepatch-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-default-livepatch-devel-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-livepatch-5_3_18-150300_59_201-default-1-150300.7.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.201.1.150300.18.120.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-zfcpdump-5.3.18-150300.59.201.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.201.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
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
      severity   : SECURITY_WARNING,
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
