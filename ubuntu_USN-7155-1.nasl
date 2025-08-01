#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7155-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212723);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/12");

  script_cve_id(
    "CVE-2023-52889",
    "CVE-2023-52918",
    "CVE-2024-39472",
    "CVE-2024-42258",
    "CVE-2024-42259",
    "CVE-2024-42260",
    "CVE-2024-42261",
    "CVE-2024-42262",
    "CVE-2024-42263",
    "CVE-2024-42264",
    "CVE-2024-42265",
    "CVE-2024-42267",
    "CVE-2024-42268",
    "CVE-2024-42269",
    "CVE-2024-42270",
    "CVE-2024-42272",
    "CVE-2024-42273",
    "CVE-2024-42274",
    "CVE-2024-42276",
    "CVE-2024-42277",
    "CVE-2024-42278",
    "CVE-2024-42279",
    "CVE-2024-42281",
    "CVE-2024-42283",
    "CVE-2024-42284",
    "CVE-2024-42285",
    "CVE-2024-42286",
    "CVE-2024-42287",
    "CVE-2024-42288",
    "CVE-2024-42289",
    "CVE-2024-42290",
    "CVE-2024-42291",
    "CVE-2024-42292",
    "CVE-2024-42294",
    "CVE-2024-42295",
    "CVE-2024-42296",
    "CVE-2024-42297",
    "CVE-2024-42298",
    "CVE-2024-42299",
    "CVE-2024-42301",
    "CVE-2024-42302",
    "CVE-2024-42303",
    "CVE-2024-42304",
    "CVE-2024-42305",
    "CVE-2024-42306",
    "CVE-2024-42307",
    "CVE-2024-42309",
    "CVE-2024-42310",
    "CVE-2024-42311",
    "CVE-2024-42312",
    "CVE-2024-42313",
    "CVE-2024-42314",
    "CVE-2024-42315",
    "CVE-2024-42316",
    "CVE-2024-42317",
    "CVE-2024-42318",
    "CVE-2024-42319",
    "CVE-2024-42320",
    "CVE-2024-42321",
    "CVE-2024-42322",
    "CVE-2024-43817",
    "CVE-2024-43818",
    "CVE-2024-43819",
    "CVE-2024-43820",
    "CVE-2024-43821",
    "CVE-2024-43823",
    "CVE-2024-43824",
    "CVE-2024-43825",
    "CVE-2024-43826",
    "CVE-2024-43827",
    "CVE-2024-43828",
    "CVE-2024-43829",
    "CVE-2024-43830",
    "CVE-2024-43831",
    "CVE-2024-43832",
    "CVE-2024-43833",
    "CVE-2024-43834",
    "CVE-2024-43835",
    "CVE-2024-43837",
    "CVE-2024-43839",
    "CVE-2024-43840",
    "CVE-2024-43841",
    "CVE-2024-43842",
    "CVE-2024-43843",
    "CVE-2024-43845",
    "CVE-2024-43846",
    "CVE-2024-43847",
    "CVE-2024-43849",
    "CVE-2024-43850",
    "CVE-2024-43852",
    "CVE-2024-43853",
    "CVE-2024-43854",
    "CVE-2024-43856",
    "CVE-2024-43857",
    "CVE-2024-43859",
    "CVE-2024-43860",
    "CVE-2024-43861",
    "CVE-2024-43863",
    "CVE-2024-43864",
    "CVE-2024-43866",
    "CVE-2024-43867",
    "CVE-2024-43868",
    "CVE-2024-43869",
    "CVE-2024-43870",
    "CVE-2024-43871",
    "CVE-2024-43873",
    "CVE-2024-43875",
    "CVE-2024-43876",
    "CVE-2024-43877",
    "CVE-2024-43879",
    "CVE-2024-43880",
    "CVE-2024-43881",
    "CVE-2024-43883",
    "CVE-2024-43884",
    "CVE-2024-43886",
    "CVE-2024-43887",
    "CVE-2024-43888",
    "CVE-2024-43889",
    "CVE-2024-43890",
    "CVE-2024-43891",
    "CVE-2024-43892",
    "CVE-2024-43893",
    "CVE-2024-43894",
    "CVE-2024-43895",
    "CVE-2024-43899",
    "CVE-2024-43900",
    "CVE-2024-43902",
    "CVE-2024-43904",
    "CVE-2024-43905",
    "CVE-2024-43906",
    "CVE-2024-43907",
    "CVE-2024-43908",
    "CVE-2024-43909",
    "CVE-2024-43910",
    "CVE-2024-43911",
    "CVE-2024-43912",
    "CVE-2024-43913",
    "CVE-2024-43914",
    "CVE-2024-44931",
    "CVE-2024-44934",
    "CVE-2024-44935",
    "CVE-2024-44937",
    "CVE-2024-44938",
    "CVE-2024-44939",
    "CVE-2024-44940",
    "CVE-2024-44941",
    "CVE-2024-44942",
    "CVE-2024-44943",
    "CVE-2024-44944",
    "CVE-2024-44946",
    "CVE-2024-44947",
    "CVE-2024-44948",
    "CVE-2024-44950",
    "CVE-2024-44953",
    "CVE-2024-44954",
    "CVE-2024-44956",
    "CVE-2024-44957",
    "CVE-2024-44958",
    "CVE-2024-44959",
    "CVE-2024-44960",
    "CVE-2024-44961",
    "CVE-2024-44962",
    "CVE-2024-44963",
    "CVE-2024-44965",
    "CVE-2024-44966",
    "CVE-2024-44967",
    "CVE-2024-44969",
    "CVE-2024-44970",
    "CVE-2024-44971",
    "CVE-2024-44972",
    "CVE-2024-44973",
    "CVE-2024-44974",
    "CVE-2024-44975",
    "CVE-2024-44977",
    "CVE-2024-44978",
    "CVE-2024-44979",
    "CVE-2024-44980",
    "CVE-2024-44982",
    "CVE-2024-44983",
    "CVE-2024-44984",
    "CVE-2024-44985",
    "CVE-2024-44986",
    "CVE-2024-44987",
    "CVE-2024-44988",
    "CVE-2024-44989",
    "CVE-2024-44990",
    "CVE-2024-44991",
    "CVE-2024-44993",
    "CVE-2024-44995",
    "CVE-2024-44996",
    "CVE-2024-44998",
    "CVE-2024-44999",
    "CVE-2024-45000",
    "CVE-2024-45002",
    "CVE-2024-45003",
    "CVE-2024-45005",
    "CVE-2024-45006",
    "CVE-2024-45007",
    "CVE-2024-45008",
    "CVE-2024-45009",
    "CVE-2024-45010",
    "CVE-2024-45011",
    "CVE-2024-45012",
    "CVE-2024-45013",
    "CVE-2024-45015",
    "CVE-2024-45017",
    "CVE-2024-45018",
    "CVE-2024-45019",
    "CVE-2024-45020",
    "CVE-2024-45021",
    "CVE-2024-45022",
    "CVE-2024-45025",
    "CVE-2024-45026",
    "CVE-2024-45027",
    "CVE-2024-45028",
    "CVE-2024-45029",
    "CVE-2024-45030",
    "CVE-2024-46672",
    "CVE-2024-46673",
    "CVE-2024-46675",
    "CVE-2024-46676",
    "CVE-2024-46677",
    "CVE-2024-46678",
    "CVE-2024-46679",
    "CVE-2024-46680",
    "CVE-2024-46681",
    "CVE-2024-46683",
    "CVE-2024-46685",
    "CVE-2024-46686",
    "CVE-2024-46687",
    "CVE-2024-46689",
    "CVE-2024-46691",
    "CVE-2024-46692",
    "CVE-2024-46693",
    "CVE-2024-46694",
    "CVE-2024-46695",
    "CVE-2024-46697",
    "CVE-2024-46698",
    "CVE-2024-46701",
    "CVE-2024-46702",
    "CVE-2024-46703",
    "CVE-2024-46705",
    "CVE-2024-46706",
    "CVE-2024-46707",
    "CVE-2024-46708",
    "CVE-2024-46709",
    "CVE-2024-46710",
    "CVE-2024-46711",
    "CVE-2024-46713",
    "CVE-2024-46714",
    "CVE-2024-46715",
    "CVE-2024-46716",
    "CVE-2024-46717",
    "CVE-2024-46718",
    "CVE-2024-46719",
    "CVE-2024-46720",
    "CVE-2024-46721",
    "CVE-2024-46722",
    "CVE-2024-46723",
    "CVE-2024-46724",
    "CVE-2024-46725",
    "CVE-2024-46726",
    "CVE-2024-46727",
    "CVE-2024-46728",
    "CVE-2024-46729",
    "CVE-2024-46730",
    "CVE-2024-46731",
    "CVE-2024-46732",
    "CVE-2024-46733",
    "CVE-2024-46735",
    "CVE-2024-46737",
    "CVE-2024-46738",
    "CVE-2024-46739",
    "CVE-2024-46740",
    "CVE-2024-46741",
    "CVE-2024-46743",
    "CVE-2024-46744",
    "CVE-2024-46745",
    "CVE-2024-46746",
    "CVE-2024-46747",
    "CVE-2024-46749",
    "CVE-2024-46750",
    "CVE-2024-46751",
    "CVE-2024-46752",
    "CVE-2024-46753",
    "CVE-2024-46754",
    "CVE-2024-46755",
    "CVE-2024-46756",
    "CVE-2024-46757",
    "CVE-2024-46758",
    "CVE-2024-46759",
    "CVE-2024-46760",
    "CVE-2024-46761",
    "CVE-2024-46762",
    "CVE-2024-46763",
    "CVE-2024-46765",
    "CVE-2024-46766",
    "CVE-2024-46767",
    "CVE-2024-46768",
    "CVE-2024-46770",
    "CVE-2024-46771",
    "CVE-2024-46772",
    "CVE-2024-46773",
    "CVE-2024-46774",
    "CVE-2024-46775",
    "CVE-2024-46776",
    "CVE-2024-46777",
    "CVE-2024-46778",
    "CVE-2024-46779",
    "CVE-2024-46780",
    "CVE-2024-46781",
    "CVE-2024-46782",
    "CVE-2024-46783",
    "CVE-2024-46784",
    "CVE-2024-46785",
    "CVE-2024-46786",
    "CVE-2024-46787",
    "CVE-2024-46788",
    "CVE-2024-46791",
    "CVE-2024-46792",
    "CVE-2024-46793",
    "CVE-2024-46794",
    "CVE-2024-46795",
    "CVE-2024-46797",
    "CVE-2024-46798",
    "CVE-2024-46802",
    "CVE-2024-46803",
    "CVE-2024-46804",
    "CVE-2024-46805",
    "CVE-2024-46806",
    "CVE-2024-46807",
    "CVE-2024-46808",
    "CVE-2024-46809",
    "CVE-2024-46810",
    "CVE-2024-46811",
    "CVE-2024-46812",
    "CVE-2024-46813",
    "CVE-2024-46814",
    "CVE-2024-46815",
    "CVE-2024-46816",
    "CVE-2024-46817",
    "CVE-2024-46818",
    "CVE-2024-46819",
    "CVE-2024-46821",
    "CVE-2024-46822",
    "CVE-2024-46823",
    "CVE-2024-46824",
    "CVE-2024-46825",
    "CVE-2024-46826",
    "CVE-2024-46827",
    "CVE-2024-46828",
    "CVE-2024-46829",
    "CVE-2024-46830",
    "CVE-2024-46831",
    "CVE-2024-46832",
    "CVE-2024-46834",
    "CVE-2024-46835",
    "CVE-2024-46836",
    "CVE-2024-46838",
    "CVE-2024-46840",
    "CVE-2024-46841",
    "CVE-2024-46842",
    "CVE-2024-46843",
    "CVE-2024-46844",
    "CVE-2024-46845",
    "CVE-2024-46846",
    "CVE-2024-46847",
    "CVE-2024-46848",
    "CVE-2024-46849",
    "CVE-2024-46850",
    "CVE-2024-46851",
    "CVE-2024-46852",
    "CVE-2024-46853",
    "CVE-2024-46854",
    "CVE-2024-46855",
    "CVE-2024-46857",
    "CVE-2024-46858",
    "CVE-2024-46859",
    "CVE-2024-46860",
    "CVE-2024-46861",
    "CVE-2024-46864",
    "CVE-2024-46866",
    "CVE-2024-46867",
    "CVE-2024-46868",
    "CVE-2024-46870",
    "CVE-2024-46871",
    "CVE-2024-47658",
    "CVE-2024-47659",
    "CVE-2024-47660",
    "CVE-2024-47661",
    "CVE-2024-47662",
    "CVE-2024-47663",
    "CVE-2024-47664",
    "CVE-2024-47665",
    "CVE-2024-47666",
    "CVE-2024-47667",
    "CVE-2024-47668",
    "CVE-2024-47669",
    "CVE-2024-47674",
    "CVE-2024-47683",
    "CVE-2024-49984"
  );
  script_xref(name:"USN", value:"7155-1");

  script_name(english:"Ubuntu 22.04 LTS / 24.04 LTS : Linux kernel (NVIDIA) vulnerabilities (USN-7155-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 24.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-7155-1 advisory.

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM64 architecture;

    - MIPS architecture;

    - PowerPC architecture;

    - RISC-V architecture;

    - S390 architecture;

    - User-Mode Linux (UML);

    - x86 architecture;

    - Block layer subsystem;

    - Android drivers;

    - ATM drivers;

    - Drivers core;

    - Ublk userspace block driver;

    - Bluetooth drivers;

    - Character device driver;

    - Hardware crypto device drivers;

    - Buffer Sharing and Synchronization framework;

    - DMA engine subsystem;

    - Qualcomm firmware drivers;

    - GPIO subsystem;

    - GPU drivers;

    - HID subsystem;

    - Hardware monitoring drivers;

    - I2C subsystem;

    - I3C subsystem;

    - IIO subsystem;

    - InfiniBand drivers;

    - Input Device core drivers;

    - Input Device (Miscellaneous) drivers;

    - IOMMU subsystem;

    - IRQ chip drivers;

    - LED subsystem;

    - Mailbox framework;

    - Multiple devices driver;

    - Media drivers;

    - Fastrpc Driver;

    - VMware VMCI Driver;

    - MMC subsystem;

    - Ethernet bonding driver;

    - Network drivers;

    - Mellanox network drivers;

    - Microsoft Azure Network Adapter (MANA) driver;

    - Near Field Communication (NFC) drivers;

    - NVME drivers;

    - Device tree and open firmware driver;

    - Parport drivers;

    - PCI subsystem;

    - Pin controllers subsystem;

    - x86 platform drivers;

    - Power supply drivers;

    - Remote Processor subsystem;

    - S/390 drivers;

    - SCSI subsystem;

    - QCOM SoC drivers;

    - SPI subsystem;

    - Direct Digital Synthesis drivers;

    - Thunderbolt and USB4 drivers;

    - TTY drivers;

    - UFS subsystem;

    - Userspace I/O drivers;

    - DesignWare USB3 driver;

    - USB Gadget drivers;

    - USB Host Controller drivers;

    - USB Type-C Connector System Software Interface driver;

    - USB over IP driver;

    - Virtio Host (VHOST) subsystem;

    - Framebuffer layer;

    - Xen hypervisor drivers;

    - File systems infrastructure;

    - BTRFS file system;

    - Ext4 file system;

    - F2FS file system;

    - JFS file system;

    - Network file systems library;

    - Network file system (NFS) client;

    - Network file system (NFS) server daemon;

    - NILFS2 file system;

    - File system notification infrastructure;

    - NTFS3 file system;

    - Proc file system;

    - SMB network file system;

    - Tracing file system;

    - Bitmap API;

    - BPF subsystem;

    - Memory Management;

    - Objagg library;

    - Perf events;

    - Virtio network driver;

    - VMware vSockets driver;

    - KCM (Kernel Connection Multiplexor) sockets driver;

    - Control group (cgroup);

    - DMA mapping infrastructure;

    - Locking primitives;

    - Padata parallel execution mechanism;

    - Scheduler infrastructure;

    - Tracing infrastructure;

    - Radix Tree data structure library;

    - Kernel userspace event delivery library;

    - KUnit for arithmetic overflow checks;

    - Memory management;

    - Bluetooth subsystem;

    - Ethernet bridge;

    - CAN network layer;

    - Networking core;

    - Ethtool driver;

    - IPv4 networking;

    - IPv6 networking;

    - MAC80211 subsystem;

    - Multipath TCP;

    - Netfilter;

    - Network traffic control;

    - SCTP protocol;

    - TIPC protocol;

    - Wireless networking;

    - AppArmor security module;

    - Landlock security;

    - SELinux security module;

    - Simplified Mandatory Access Control Kernel framework;

    - FireWire sound drivers;

    - AMD SoC Alsa drivers;

    - Texas InstrumentS Audio (ASoC/HDA) drivers;

    - SoC Audio for Freescale CPUs drivers;

    - Intel ASoC drivers;

    - Amlogic Meson SoC drivers;

    - SoC audio core drivers;

    - USB sound devices;

    - Real-Time Linux Analysis tools; (CVE-2024-43845, CVE-2024-42311, CVE-2024-46757, CVE-2024-46738,
    CVE-2024-44961, CVE-2024-44935, CVE-2024-46845, CVE-2024-46783, CVE-2024-42315, CVE-2023-52918,
    CVE-2024-46708, CVE-2024-44934, CVE-2024-42298, CVE-2024-46786, CVE-2024-46778, CVE-2024-44960,
    CVE-2024-42295, CVE-2024-43881, CVE-2024-44971, CVE-2024-43849, CVE-2024-43914, CVE-2024-44962,
    CVE-2024-43841, CVE-2024-46794, CVE-2024-46752, CVE-2024-46853, CVE-2024-46861, CVE-2024-47664,
    CVE-2024-46717, CVE-2024-46806, CVE-2024-46797, CVE-2024-42261, CVE-2024-46828, CVE-2024-45013,
    CVE-2024-46870, CVE-2024-42258, CVE-2024-46689, CVE-2024-43818, CVE-2024-46762, CVE-2024-46825,
    CVE-2024-46698, CVE-2024-46816, CVE-2024-46728, CVE-2024-46726, CVE-2024-43835, CVE-2024-45000,
    CVE-2024-43850, CVE-2024-43840, CVE-2024-46846, CVE-2024-43846, CVE-2024-46725, CVE-2024-46867,
    CVE-2024-42310, CVE-2024-42274, CVE-2024-46760, CVE-2024-46683, CVE-2024-42304, CVE-2024-43839,
    CVE-2024-44954, CVE-2024-43895, CVE-2024-44967, CVE-2024-43889, CVE-2024-46854, CVE-2024-46860,
    CVE-2024-45029, CVE-2024-44938, CVE-2024-46785, CVE-2024-46713, CVE-2024-46715, CVE-2024-46731,
    CVE-2024-42297, CVE-2024-43912, CVE-2024-46751, CVE-2024-46711, CVE-2024-46695, CVE-2024-42317,
    CVE-2024-44957, CVE-2024-46792, CVE-2024-45020, CVE-2024-44985, CVE-2024-46746, CVE-2024-43868,
    CVE-2024-45017, CVE-2024-46824, CVE-2024-46787, CVE-2024-42288, CVE-2024-46681, CVE-2024-42306,
    CVE-2024-46755, CVE-2024-46826, CVE-2024-46777, CVE-2024-46844, CVE-2024-44972, CVE-2024-43883,
    CVE-2024-43909, CVE-2024-46676, CVE-2024-46798, CVE-2024-42273, CVE-2024-44990, CVE-2024-46744,
    CVE-2024-42305, CVE-2024-45006, CVE-2024-42309, CVE-2024-46722, CVE-2024-44956, CVE-2024-46739,
    CVE-2024-46680, CVE-2024-46765, CVE-2024-46714, CVE-2024-46771, CVE-2024-46847, CVE-2024-43879,
    CVE-2024-46703, CVE-2024-46733, CVE-2024-46815, CVE-2024-46802, CVE-2024-45027, CVE-2024-42281,
    CVE-2024-43891, CVE-2024-45030, CVE-2024-47662, CVE-2024-43887, CVE-2024-46836, CVE-2024-46782,
    CVE-2024-46835, CVE-2024-43907, CVE-2024-46779, CVE-2024-43869, CVE-2024-43821, CVE-2024-44978,
    CVE-2024-42286, CVE-2023-52889, CVE-2024-43852, CVE-2024-42320, CVE-2024-44931, CVE-2024-44993,
    CVE-2024-46829, CVE-2024-46701, CVE-2024-42272, CVE-2024-47660, CVE-2024-49984, CVE-2024-44973,
    CVE-2024-43817, CVE-2024-42322, CVE-2024-43830, CVE-2024-42301, CVE-2024-44969, CVE-2024-47674,
    CVE-2024-46702, CVE-2024-45025, CVE-2024-46710, CVE-2024-43866, CVE-2024-46718, CVE-2024-46773,
    CVE-2024-43834, CVE-2024-46754, CVE-2024-46871, CVE-2024-44942, CVE-2024-43913, CVE-2024-46818,
    CVE-2024-42318, CVE-2024-43831, CVE-2024-43832, CVE-2024-43908, CVE-2024-43827, CVE-2024-46737,
    CVE-2024-47665, CVE-2024-43854, CVE-2024-46707, CVE-2024-42303, CVE-2024-43860, CVE-2024-43824,
    CVE-2024-45019, CVE-2024-44984, CVE-2024-46813, CVE-2024-45022, CVE-2024-44970, CVE-2024-46791,
    CVE-2024-45012, CVE-2024-43829, CVE-2024-46850, CVE-2024-44987, CVE-2024-44940, CVE-2024-43864,
    CVE-2024-46723, CVE-2024-44999, CVE-2024-43884, CVE-2024-42287, CVE-2024-46675, CVE-2024-44974,
    CVE-2024-46721, CVE-2024-44937, CVE-2024-45008, CVE-2024-43853, CVE-2024-46697, CVE-2024-43899,
    CVE-2024-43823, CVE-2024-46747, CVE-2024-45007, CVE-2024-46822, CVE-2024-42262, CVE-2024-47661,
    CVE-2024-44953, CVE-2024-46859, CVE-2024-46694, CVE-2024-42279, CVE-2024-43873, CVE-2024-43828,
    CVE-2024-46851, CVE-2024-42296, CVE-2024-46719, CVE-2024-46677, CVE-2024-42259, CVE-2024-44941,
    CVE-2024-44946, CVE-2024-46745, CVE-2024-42299, CVE-2024-46724, CVE-2024-46749, CVE-2024-46706,
    CVE-2024-42267, CVE-2024-46774, CVE-2024-46685, CVE-2024-42292, CVE-2024-47667, CVE-2024-42319,
    CVE-2024-43888, CVE-2024-46729, CVE-2024-44947, CVE-2024-45003, CVE-2024-46827, CVE-2024-46693,
    CVE-2024-46705, CVE-2024-46767, CVE-2024-46838, CVE-2024-46805, CVE-2024-43904, CVE-2024-43906,
    CVE-2024-42265, CVE-2024-42278, CVE-2024-46750, CVE-2024-46692, CVE-2024-43847, CVE-2024-44995,
    CVE-2024-43825, CVE-2024-46803, CVE-2024-47669, CVE-2024-46830, CVE-2024-46784, CVE-2024-46840,
    CVE-2024-44939, CVE-2024-46848, CVE-2024-42313, CVE-2024-46823, CVE-2024-44989, CVE-2024-42270,
    CVE-2024-43856, CVE-2024-46716, CVE-2024-43859, CVE-2024-46841, CVE-2024-47658, CVE-2024-46811,
    CVE-2024-45028, CVE-2024-46781, CVE-2024-42290, CVE-2024-44991, CVE-2024-43894, CVE-2024-44979,
    CVE-2024-46804, CVE-2024-43826, CVE-2024-43877, CVE-2024-42284, CVE-2024-43876, CVE-2024-45011,
    CVE-2024-43819, CVE-2024-46709, CVE-2024-43867, CVE-2024-44963, CVE-2024-45010, CVE-2024-46753,
    CVE-2024-46759, CVE-2024-43880, CVE-2024-44977, CVE-2024-46772, CVE-2024-44950, CVE-2024-46687,
    CVE-2024-46834, CVE-2024-43911, CVE-2024-45015, CVE-2024-46819, CVE-2024-43875, CVE-2024-44996,
    CVE-2024-44988, CVE-2024-46673, CVE-2024-44943, CVE-2024-42316, CVE-2024-47683, CVE-2024-42307,
    CVE-2024-46788, CVE-2024-43892, CVE-2024-47659, CVE-2024-46857, CVE-2024-43820, CVE-2024-46832,
    CVE-2024-42312, CVE-2024-43910, CVE-2024-43886, CVE-2024-43905, CVE-2024-46766, CVE-2024-42263,
    CVE-2024-46821, CVE-2024-43842, CVE-2024-43857, CVE-2024-42276, CVE-2024-42268, CVE-2024-46740,
    CVE-2024-46843, CVE-2024-46807, CVE-2024-46780, CVE-2024-46678, CVE-2024-44944, CVE-2024-42264,
    CVE-2024-43863, CVE-2024-39472, CVE-2024-46691, CVE-2024-44959, CVE-2024-44958, CVE-2024-46679,
    CVE-2024-43843, CVE-2024-43900, CVE-2024-45021, CVE-2024-44982, CVE-2024-46793, CVE-2024-42260,
    CVE-2024-43890, CVE-2024-43871, CVE-2024-42269, CVE-2024-42277, CVE-2024-46720, CVE-2024-45005,
    CVE-2024-46727, CVE-2024-46808, CVE-2024-46852, CVE-2024-47668, CVE-2024-42321, CVE-2024-46743,
    CVE-2024-45002, CVE-2024-46763, CVE-2024-46817, CVE-2024-42285, CVE-2024-46770, CVE-2024-45026,
    CVE-2024-46768, CVE-2024-42314, CVE-2024-42291, CVE-2024-46756, CVE-2024-42283, CVE-2024-45018,
    CVE-2024-44966, CVE-2024-42289, CVE-2024-42294, CVE-2024-46814, CVE-2024-44986, CVE-2024-43870,
    CVE-2024-44980, CVE-2024-43902, CVE-2024-47666, CVE-2024-46864, CVE-2024-46761, CVE-2024-46831,
    CVE-2024-46758, CVE-2024-46735, CVE-2024-46858, CVE-2024-46795, CVE-2024-46810, CVE-2024-46849,
    CVE-2024-46775, CVE-2024-46868, CVE-2024-46809, CVE-2024-46776, CVE-2024-46866, CVE-2024-44983,
    CVE-2024-46741, CVE-2024-43837, CVE-2024-43833, CVE-2024-46672, CVE-2024-43861, CVE-2024-42302,
    CVE-2024-47663, CVE-2024-46812, CVE-2024-43893, CVE-2024-46686, CVE-2024-44948, CVE-2024-46732,
    CVE-2024-44965, CVE-2024-46855, CVE-2024-45009, CVE-2024-46842, CVE-2024-46730, CVE-2024-44975,
    CVE-2024-44998)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7155-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47659");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1019-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1019-nvidia-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1019-nvidia-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1019-nvidia-lowlatency-64k");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('22.04' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '22.04': {
    '6.8.0': {
      'nvidia': '6.8.0-1019',
      'nvidia-64k': '6.8.0-1019'
    }
  },
  '24.04': {
    '6.8.0': {
      'nvidia-lowlatency': '6.8.0-1019',
      'nvidia-lowlatency-64k': '6.8.0-1019'
    }
  }
};

var host_kernel_release = get_kb_item('Host/uptrack-uname-r');
if (empty_or_null(host_kernel_release)) host_kernel_release = get_kb_item_or_exit('Host/uname-r');
var host_kernel_base_version = get_kb_item_or_exit('Host/Debian/kernel-base-version');
var host_kernel_type = get_kb_item_or_exit('Host/Debian/kernel-type');
if(empty_or_null(kernel_mappings[os_release][host_kernel_base_version][host_kernel_type])) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + host_kernel_release);

var extra = '';
var kernel_fixed_version = kernel_mappings[os_release][host_kernel_base_version][host_kernel_type] + "-" + host_kernel_type;
if (deb_ver_cmp(ver1:host_kernel_release, ver2:kernel_fixed_version) < 0)
{
  extra += 'Running Kernel level of ' + host_kernel_release + ' does not meet the minimum fixed level of ' + kernel_fixed_version + ' for this advisory.\n\n';
}
  else
{
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7155-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-52889', 'CVE-2023-52918', 'CVE-2024-39472', 'CVE-2024-42258', 'CVE-2024-42259', 'CVE-2024-42260', 'CVE-2024-42261', 'CVE-2024-42262', 'CVE-2024-42263', 'CVE-2024-42264', 'CVE-2024-42265', 'CVE-2024-42267', 'CVE-2024-42268', 'CVE-2024-42269', 'CVE-2024-42270', 'CVE-2024-42272', 'CVE-2024-42273', 'CVE-2024-42274', 'CVE-2024-42276', 'CVE-2024-42277', 'CVE-2024-42278', 'CVE-2024-42279', 'CVE-2024-42281', 'CVE-2024-42283', 'CVE-2024-42284', 'CVE-2024-42285', 'CVE-2024-42286', 'CVE-2024-42287', 'CVE-2024-42288', 'CVE-2024-42289', 'CVE-2024-42290', 'CVE-2024-42291', 'CVE-2024-42292', 'CVE-2024-42294', 'CVE-2024-42295', 'CVE-2024-42296', 'CVE-2024-42297', 'CVE-2024-42298', 'CVE-2024-42299', 'CVE-2024-42301', 'CVE-2024-42302', 'CVE-2024-42303', 'CVE-2024-42304', 'CVE-2024-42305', 'CVE-2024-42306', 'CVE-2024-42307', 'CVE-2024-42309', 'CVE-2024-42310', 'CVE-2024-42311', 'CVE-2024-42312', 'CVE-2024-42313', 'CVE-2024-42314', 'CVE-2024-42315', 'CVE-2024-42316', 'CVE-2024-42317', 'CVE-2024-42318', 'CVE-2024-42319', 'CVE-2024-42320', 'CVE-2024-42321', 'CVE-2024-42322', 'CVE-2024-43817', 'CVE-2024-43818', 'CVE-2024-43819', 'CVE-2024-43820', 'CVE-2024-43821', 'CVE-2024-43823', 'CVE-2024-43824', 'CVE-2024-43825', 'CVE-2024-43826', 'CVE-2024-43827', 'CVE-2024-43828', 'CVE-2024-43829', 'CVE-2024-43830', 'CVE-2024-43831', 'CVE-2024-43832', 'CVE-2024-43833', 'CVE-2024-43834', 'CVE-2024-43835', 'CVE-2024-43837', 'CVE-2024-43839', 'CVE-2024-43840', 'CVE-2024-43841', 'CVE-2024-43842', 'CVE-2024-43843', 'CVE-2024-43845', 'CVE-2024-43846', 'CVE-2024-43847', 'CVE-2024-43849', 'CVE-2024-43850', 'CVE-2024-43852', 'CVE-2024-43853', 'CVE-2024-43854', 'CVE-2024-43856', 'CVE-2024-43857', 'CVE-2024-43859', 'CVE-2024-43860', 'CVE-2024-43861', 'CVE-2024-43863', 'CVE-2024-43864', 'CVE-2024-43866', 'CVE-2024-43867', 'CVE-2024-43868', 'CVE-2024-43869', 'CVE-2024-43870', 'CVE-2024-43871', 'CVE-2024-43873', 'CVE-2024-43875', 'CVE-2024-43876', 'CVE-2024-43877', 'CVE-2024-43879', 'CVE-2024-43880', 'CVE-2024-43881', 'CVE-2024-43883', 'CVE-2024-43884', 'CVE-2024-43886', 'CVE-2024-43887', 'CVE-2024-43888', 'CVE-2024-43889', 'CVE-2024-43890', 'CVE-2024-43891', 'CVE-2024-43892', 'CVE-2024-43893', 'CVE-2024-43894', 'CVE-2024-43895', 'CVE-2024-43899', 'CVE-2024-43900', 'CVE-2024-43902', 'CVE-2024-43904', 'CVE-2024-43905', 'CVE-2024-43906', 'CVE-2024-43907', 'CVE-2024-43908', 'CVE-2024-43909', 'CVE-2024-43910', 'CVE-2024-43911', 'CVE-2024-43912', 'CVE-2024-43913', 'CVE-2024-43914', 'CVE-2024-44931', 'CVE-2024-44934', 'CVE-2024-44935', 'CVE-2024-44937', 'CVE-2024-44938', 'CVE-2024-44939', 'CVE-2024-44940', 'CVE-2024-44941', 'CVE-2024-44942', 'CVE-2024-44943', 'CVE-2024-44944', 'CVE-2024-44946', 'CVE-2024-44947', 'CVE-2024-44948', 'CVE-2024-44950', 'CVE-2024-44953', 'CVE-2024-44954', 'CVE-2024-44956', 'CVE-2024-44957', 'CVE-2024-44958', 'CVE-2024-44959', 'CVE-2024-44960', 'CVE-2024-44961', 'CVE-2024-44962', 'CVE-2024-44963', 'CVE-2024-44965', 'CVE-2024-44966', 'CVE-2024-44967', 'CVE-2024-44969', 'CVE-2024-44970', 'CVE-2024-44971', 'CVE-2024-44972', 'CVE-2024-44973', 'CVE-2024-44974', 'CVE-2024-44975', 'CVE-2024-44977', 'CVE-2024-44978', 'CVE-2024-44979', 'CVE-2024-44980', 'CVE-2024-44982', 'CVE-2024-44983', 'CVE-2024-44984', 'CVE-2024-44985', 'CVE-2024-44986', 'CVE-2024-44987', 'CVE-2024-44988', 'CVE-2024-44989', 'CVE-2024-44990', 'CVE-2024-44991', 'CVE-2024-44993', 'CVE-2024-44995', 'CVE-2024-44996', 'CVE-2024-44998', 'CVE-2024-44999', 'CVE-2024-45000', 'CVE-2024-45002', 'CVE-2024-45003', 'CVE-2024-45005', 'CVE-2024-45006', 'CVE-2024-45007', 'CVE-2024-45008', 'CVE-2024-45009', 'CVE-2024-45010', 'CVE-2024-45011', 'CVE-2024-45012', 'CVE-2024-45013', 'CVE-2024-45015', 'CVE-2024-45017', 'CVE-2024-45018', 'CVE-2024-45019', 'CVE-2024-45020', 'CVE-2024-45021', 'CVE-2024-45022', 'CVE-2024-45025', 'CVE-2024-45026', 'CVE-2024-45027', 'CVE-2024-45028', 'CVE-2024-45029', 'CVE-2024-45030', 'CVE-2024-46672', 'CVE-2024-46673', 'CVE-2024-46675', 'CVE-2024-46676', 'CVE-2024-46677', 'CVE-2024-46678', 'CVE-2024-46679', 'CVE-2024-46680', 'CVE-2024-46681', 'CVE-2024-46683', 'CVE-2024-46685', 'CVE-2024-46686', 'CVE-2024-46687', 'CVE-2024-46689', 'CVE-2024-46691', 'CVE-2024-46692', 'CVE-2024-46693', 'CVE-2024-46694', 'CVE-2024-46695', 'CVE-2024-46697', 'CVE-2024-46698', 'CVE-2024-46701', 'CVE-2024-46702', 'CVE-2024-46703', 'CVE-2024-46705', 'CVE-2024-46706', 'CVE-2024-46707', 'CVE-2024-46708', 'CVE-2024-46709', 'CVE-2024-46710', 'CVE-2024-46711', 'CVE-2024-46713', 'CVE-2024-46714', 'CVE-2024-46715', 'CVE-2024-46716', 'CVE-2024-46717', 'CVE-2024-46718', 'CVE-2024-46719', 'CVE-2024-46720', 'CVE-2024-46721', 'CVE-2024-46722', 'CVE-2024-46723', 'CVE-2024-46724', 'CVE-2024-46725', 'CVE-2024-46726', 'CVE-2024-46727', 'CVE-2024-46728', 'CVE-2024-46729', 'CVE-2024-46730', 'CVE-2024-46731', 'CVE-2024-46732', 'CVE-2024-46733', 'CVE-2024-46735', 'CVE-2024-46737', 'CVE-2024-46738', 'CVE-2024-46739', 'CVE-2024-46740', 'CVE-2024-46741', 'CVE-2024-46743', 'CVE-2024-46744', 'CVE-2024-46745', 'CVE-2024-46746', 'CVE-2024-46747', 'CVE-2024-46749', 'CVE-2024-46750', 'CVE-2024-46751', 'CVE-2024-46752', 'CVE-2024-46753', 'CVE-2024-46754', 'CVE-2024-46755', 'CVE-2024-46756', 'CVE-2024-46757', 'CVE-2024-46758', 'CVE-2024-46759', 'CVE-2024-46760', 'CVE-2024-46761', 'CVE-2024-46762', 'CVE-2024-46763', 'CVE-2024-46765', 'CVE-2024-46766', 'CVE-2024-46767', 'CVE-2024-46768', 'CVE-2024-46770', 'CVE-2024-46771', 'CVE-2024-46772', 'CVE-2024-46773', 'CVE-2024-46774', 'CVE-2024-46775', 'CVE-2024-46776', 'CVE-2024-46777', 'CVE-2024-46778', 'CVE-2024-46779', 'CVE-2024-46780', 'CVE-2024-46781', 'CVE-2024-46782', 'CVE-2024-46783', 'CVE-2024-46784', 'CVE-2024-46785', 'CVE-2024-46786', 'CVE-2024-46787', 'CVE-2024-46788', 'CVE-2024-46791', 'CVE-2024-46792', 'CVE-2024-46793', 'CVE-2024-46794', 'CVE-2024-46795', 'CVE-2024-46797', 'CVE-2024-46798', 'CVE-2024-46802', 'CVE-2024-46803', 'CVE-2024-46804', 'CVE-2024-46805', 'CVE-2024-46806', 'CVE-2024-46807', 'CVE-2024-46808', 'CVE-2024-46809', 'CVE-2024-46810', 'CVE-2024-46811', 'CVE-2024-46812', 'CVE-2024-46813', 'CVE-2024-46814', 'CVE-2024-46815', 'CVE-2024-46816', 'CVE-2024-46817', 'CVE-2024-46818', 'CVE-2024-46819', 'CVE-2024-46821', 'CVE-2024-46822', 'CVE-2024-46823', 'CVE-2024-46824', 'CVE-2024-46825', 'CVE-2024-46826', 'CVE-2024-46827', 'CVE-2024-46828', 'CVE-2024-46829', 'CVE-2024-46830', 'CVE-2024-46831', 'CVE-2024-46832', 'CVE-2024-46834', 'CVE-2024-46835', 'CVE-2024-46836', 'CVE-2024-46838', 'CVE-2024-46840', 'CVE-2024-46841', 'CVE-2024-46842', 'CVE-2024-46843', 'CVE-2024-46844', 'CVE-2024-46845', 'CVE-2024-46846', 'CVE-2024-46847', 'CVE-2024-46848', 'CVE-2024-46849', 'CVE-2024-46850', 'CVE-2024-46851', 'CVE-2024-46852', 'CVE-2024-46853', 'CVE-2024-46854', 'CVE-2024-46855', 'CVE-2024-46857', 'CVE-2024-46858', 'CVE-2024-46859', 'CVE-2024-46860', 'CVE-2024-46861', 'CVE-2024-46864', 'CVE-2024-46866', 'CVE-2024-46867', 'CVE-2024-46868', 'CVE-2024-46870', 'CVE-2024-46871', 'CVE-2024-47658', 'CVE-2024-47659', 'CVE-2024-47660', 'CVE-2024-47661', 'CVE-2024-47662', 'CVE-2024-47663', 'CVE-2024-47664', 'CVE-2024-47665', 'CVE-2024-47666', 'CVE-2024-47667', 'CVE-2024-47668', 'CVE-2024-47669', 'CVE-2024-47674', 'CVE-2024-47683', 'CVE-2024-49984');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7155-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
