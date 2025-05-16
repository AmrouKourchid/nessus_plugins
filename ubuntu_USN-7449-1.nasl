#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7449-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234776);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/23");

  script_cve_id(
    "CVE-2022-49034",
    "CVE-2024-41014",
    "CVE-2024-41932",
    "CVE-2024-41935",
    "CVE-2024-42122",
    "CVE-2024-43098",
    "CVE-2024-44955",
    "CVE-2024-45828",
    "CVE-2024-47141",
    "CVE-2024-47143",
    "CVE-2024-47794",
    "CVE-2024-47809",
    "CVE-2024-48873",
    "CVE-2024-48875",
    "CVE-2024-48876",
    "CVE-2024-48881",
    "CVE-2024-49569",
    "CVE-2024-49899",
    "CVE-2024-49906",
    "CVE-2024-50010",
    "CVE-2024-50051",
    "CVE-2024-50067",
    "CVE-2024-50103",
    "CVE-2024-50104",
    "CVE-2024-50105",
    "CVE-2024-50107",
    "CVE-2024-50108",
    "CVE-2024-50110",
    "CVE-2024-50111",
    "CVE-2024-50112",
    "CVE-2024-50115",
    "CVE-2024-50116",
    "CVE-2024-50118",
    "CVE-2024-50120",
    "CVE-2024-50121",
    "CVE-2024-50124",
    "CVE-2024-50125",
    "CVE-2024-50126",
    "CVE-2024-50127",
    "CVE-2024-50128",
    "CVE-2024-50130",
    "CVE-2024-50131",
    "CVE-2024-50133",
    "CVE-2024-50135",
    "CVE-2024-50136",
    "CVE-2024-50137",
    "CVE-2024-50138",
    "CVE-2024-50139",
    "CVE-2024-50140",
    "CVE-2024-50141",
    "CVE-2024-50142",
    "CVE-2024-50143",
    "CVE-2024-50145",
    "CVE-2024-50146",
    "CVE-2024-50147",
    "CVE-2024-50150",
    "CVE-2024-50151",
    "CVE-2024-50152",
    "CVE-2024-50153",
    "CVE-2024-50154",
    "CVE-2024-50155",
    "CVE-2024-50156",
    "CVE-2024-50158",
    "CVE-2024-50159",
    "CVE-2024-50160",
    "CVE-2024-50162",
    "CVE-2024-50163",
    "CVE-2024-50164",
    "CVE-2024-50166",
    "CVE-2024-50167",
    "CVE-2024-50169",
    "CVE-2024-50170",
    "CVE-2024-50172",
    "CVE-2024-50203",
    "CVE-2024-50205",
    "CVE-2024-50206",
    "CVE-2024-50207",
    "CVE-2024-50208",
    "CVE-2024-50209",
    "CVE-2024-50210",
    "CVE-2024-50211",
    "CVE-2024-50215",
    "CVE-2024-50216",
    "CVE-2024-50218",
    "CVE-2024-50220",
    "CVE-2024-50221",
    "CVE-2024-50222",
    "CVE-2024-50223",
    "CVE-2024-50224",
    "CVE-2024-50225",
    "CVE-2024-50226",
    "CVE-2024-50230",
    "CVE-2024-50231",
    "CVE-2024-50232",
    "CVE-2024-50234",
    "CVE-2024-50235",
    "CVE-2024-50236",
    "CVE-2024-50237",
    "CVE-2024-50238",
    "CVE-2024-50239",
    "CVE-2024-50240",
    "CVE-2024-50242",
    "CVE-2024-50243",
    "CVE-2024-50244",
    "CVE-2024-50245",
    "CVE-2024-50246",
    "CVE-2024-50247",
    "CVE-2024-50248",
    "CVE-2024-50249",
    "CVE-2024-50250",
    "CVE-2024-50251",
    "CVE-2024-50252",
    "CVE-2024-50255",
    "CVE-2024-50256",
    "CVE-2024-50257",
    "CVE-2024-50258",
    "CVE-2024-50259",
    "CVE-2024-50261",
    "CVE-2024-50262",
    "CVE-2024-50263",
    "CVE-2024-50265",
    "CVE-2024-50267",
    "CVE-2024-50268",
    "CVE-2024-50269",
    "CVE-2024-50270",
    "CVE-2024-50271",
    "CVE-2024-50272",
    "CVE-2024-50273",
    "CVE-2024-50274",
    "CVE-2024-50275",
    "CVE-2024-50276",
    "CVE-2024-50278",
    "CVE-2024-50279",
    "CVE-2024-50280",
    "CVE-2024-50282",
    "CVE-2024-50283",
    "CVE-2024-50284",
    "CVE-2024-50285",
    "CVE-2024-50286",
    "CVE-2024-50287",
    "CVE-2024-50288",
    "CVE-2024-50289",
    "CVE-2024-50290",
    "CVE-2024-50291",
    "CVE-2024-50292",
    "CVE-2024-50294",
    "CVE-2024-50295",
    "CVE-2024-50296",
    "CVE-2024-50297",
    "CVE-2024-50298",
    "CVE-2024-50299",
    "CVE-2024-50300",
    "CVE-2024-50301",
    "CVE-2024-50303",
    "CVE-2024-50304",
    "CVE-2024-52332",
    "CVE-2024-53042",
    "CVE-2024-53043",
    "CVE-2024-53044",
    "CVE-2024-53045",
    "CVE-2024-53046",
    "CVE-2024-53047",
    "CVE-2024-53048",
    "CVE-2024-53050",
    "CVE-2024-53051",
    "CVE-2024-53052",
    "CVE-2024-53053",
    "CVE-2024-53055",
    "CVE-2024-53058",
    "CVE-2024-53059",
    "CVE-2024-53060",
    "CVE-2024-53061",
    "CVE-2024-53062",
    "CVE-2024-53066",
    "CVE-2024-53067",
    "CVE-2024-53068",
    "CVE-2024-53072",
    "CVE-2024-53076",
    "CVE-2024-53079",
    "CVE-2024-53081",
    "CVE-2024-53082",
    "CVE-2024-53083",
    "CVE-2024-53084",
    "CVE-2024-53085",
    "CVE-2024-53086",
    "CVE-2024-53087",
    "CVE-2024-53088",
    "CVE-2024-53089",
    "CVE-2024-53090",
    "CVE-2024-53091",
    "CVE-2024-53093",
    "CVE-2024-53094",
    "CVE-2024-53095",
    "CVE-2024-53096",
    "CVE-2024-53099",
    "CVE-2024-53100",
    "CVE-2024-53101",
    "CVE-2024-53105",
    "CVE-2024-53106",
    "CVE-2024-53107",
    "CVE-2024-53108",
    "CVE-2024-53109",
    "CVE-2024-53110",
    "CVE-2024-53111",
    "CVE-2024-53112",
    "CVE-2024-53113",
    "CVE-2024-53114",
    "CVE-2024-53115",
    "CVE-2024-53117",
    "CVE-2024-53118",
    "CVE-2024-53119",
    "CVE-2024-53120",
    "CVE-2024-53121",
    "CVE-2024-53122",
    "CVE-2024-53123",
    "CVE-2024-53126",
    "CVE-2024-53127",
    "CVE-2024-53128",
    "CVE-2024-53129",
    "CVE-2024-53130",
    "CVE-2024-53131",
    "CVE-2024-53133",
    "CVE-2024-53134",
    "CVE-2024-53135",
    "CVE-2024-53138",
    "CVE-2024-53139",
    "CVE-2024-53142",
    "CVE-2024-53145",
    "CVE-2024-53146",
    "CVE-2024-53147",
    "CVE-2024-53148",
    "CVE-2024-53150",
    "CVE-2024-53151",
    "CVE-2024-53154",
    "CVE-2024-53155",
    "CVE-2024-53157",
    "CVE-2024-53158",
    "CVE-2024-53160",
    "CVE-2024-53161",
    "CVE-2024-53162",
    "CVE-2024-53163",
    "CVE-2024-53166",
    "CVE-2024-53168",
    "CVE-2024-53169",
    "CVE-2024-53171",
    "CVE-2024-53172",
    "CVE-2024-53173",
    "CVE-2024-53174",
    "CVE-2024-53175",
    "CVE-2024-53176",
    "CVE-2024-53177",
    "CVE-2024-53178",
    "CVE-2024-53180",
    "CVE-2024-53181",
    "CVE-2024-53183",
    "CVE-2024-53184",
    "CVE-2024-53185",
    "CVE-2024-53187",
    "CVE-2024-53188",
    "CVE-2024-53190",
    "CVE-2024-53191",
    "CVE-2024-53194",
    "CVE-2024-53195",
    "CVE-2024-53196",
    "CVE-2024-53197",
    "CVE-2024-53198",
    "CVE-2024-53200",
    "CVE-2024-53201",
    "CVE-2024-53202",
    "CVE-2024-53203",
    "CVE-2024-53208",
    "CVE-2024-53209",
    "CVE-2024-53210",
    "CVE-2024-53213",
    "CVE-2024-53214",
    "CVE-2024-53215",
    "CVE-2024-53217",
    "CVE-2024-53218",
    "CVE-2024-53219",
    "CVE-2024-53220",
    "CVE-2024-53221",
    "CVE-2024-53222",
    "CVE-2024-53223",
    "CVE-2024-53224",
    "CVE-2024-53226",
    "CVE-2024-53227",
    "CVE-2024-53228",
    "CVE-2024-53229",
    "CVE-2024-53230",
    "CVE-2024-53231",
    "CVE-2024-53232",
    "CVE-2024-53233",
    "CVE-2024-53234",
    "CVE-2024-53236",
    "CVE-2024-53237",
    "CVE-2024-53239",
    "CVE-2024-53680",
    "CVE-2024-56531",
    "CVE-2024-56532",
    "CVE-2024-56533",
    "CVE-2024-56538",
    "CVE-2024-56539",
    "CVE-2024-56540",
    "CVE-2024-56543",
    "CVE-2024-56545",
    "CVE-2024-56546",
    "CVE-2024-56548",
    "CVE-2024-56549",
    "CVE-2024-56550",
    "CVE-2024-56551",
    "CVE-2024-56557",
    "CVE-2024-56558",
    "CVE-2024-56561",
    "CVE-2024-56562",
    "CVE-2024-56565",
    "CVE-2024-56566",
    "CVE-2024-56567",
    "CVE-2024-56568",
    "CVE-2024-56569",
    "CVE-2024-56570",
    "CVE-2024-56572",
    "CVE-2024-56573",
    "CVE-2024-56574",
    "CVE-2024-56575",
    "CVE-2024-56576",
    "CVE-2024-56577",
    "CVE-2024-56578",
    "CVE-2024-56579",
    "CVE-2024-56580",
    "CVE-2024-56581",
    "CVE-2024-56583",
    "CVE-2024-56584",
    "CVE-2024-56586",
    "CVE-2024-56587",
    "CVE-2024-56588",
    "CVE-2024-56589",
    "CVE-2024-56590",
    "CVE-2024-56592",
    "CVE-2024-56593",
    "CVE-2024-56594",
    "CVE-2024-56596",
    "CVE-2024-56597",
    "CVE-2024-56599",
    "CVE-2024-56600",
    "CVE-2024-56601",
    "CVE-2024-56602",
    "CVE-2024-56603",
    "CVE-2024-56604",
    "CVE-2024-56605",
    "CVE-2024-56606",
    "CVE-2024-56607",
    "CVE-2024-56608",
    "CVE-2024-56609",
    "CVE-2024-56610",
    "CVE-2024-56611",
    "CVE-2024-56613",
    "CVE-2024-56615",
    "CVE-2024-56616",
    "CVE-2024-56619",
    "CVE-2024-56620",
    "CVE-2024-56621",
    "CVE-2024-56622",
    "CVE-2024-56623",
    "CVE-2024-56625",
    "CVE-2024-56626",
    "CVE-2024-56627",
    "CVE-2024-56629",
    "CVE-2024-56630",
    "CVE-2024-56631",
    "CVE-2024-56632",
    "CVE-2024-56633",
    "CVE-2024-56634",
    "CVE-2024-56635",
    "CVE-2024-56636",
    "CVE-2024-56637",
    "CVE-2024-56638",
    "CVE-2024-56640",
    "CVE-2024-56641",
    "CVE-2024-56642",
    "CVE-2024-56643",
    "CVE-2024-56644",
    "CVE-2024-56645",
    "CVE-2024-56647",
    "CVE-2024-56648",
    "CVE-2024-56649",
    "CVE-2024-56650",
    "CVE-2024-56651",
    "CVE-2024-56677",
    "CVE-2024-56678",
    "CVE-2024-56679",
    "CVE-2024-56681",
    "CVE-2024-56683",
    "CVE-2024-56685",
    "CVE-2024-56687",
    "CVE-2024-56688",
    "CVE-2024-56689",
    "CVE-2024-56690",
    "CVE-2024-56691",
    "CVE-2024-56692",
    "CVE-2024-56693",
    "CVE-2024-56694",
    "CVE-2024-56698",
    "CVE-2024-56700",
    "CVE-2024-56701",
    "CVE-2024-56703",
    "CVE-2024-56704",
    "CVE-2024-56705",
    "CVE-2024-56707",
    "CVE-2024-56708",
    "CVE-2024-56720",
    "CVE-2024-56721",
    "CVE-2024-56722",
    "CVE-2024-56723",
    "CVE-2024-56724",
    "CVE-2024-56725",
    "CVE-2024-56726",
    "CVE-2024-56727",
    "CVE-2024-56728",
    "CVE-2024-56729",
    "CVE-2024-56739",
    "CVE-2024-56742",
    "CVE-2024-56744",
    "CVE-2024-56745",
    "CVE-2024-56746",
    "CVE-2024-56747",
    "CVE-2024-56748",
    "CVE-2024-56751",
    "CVE-2024-56752",
    "CVE-2024-56754",
    "CVE-2024-56755",
    "CVE-2024-56756",
    "CVE-2024-56765",
    "CVE-2024-56771",
    "CVE-2024-56772",
    "CVE-2024-56773",
    "CVE-2024-56774",
    "CVE-2024-56775",
    "CVE-2024-56776",
    "CVE-2024-56777",
    "CVE-2024-56778",
    "CVE-2024-56779",
    "CVE-2024-56780",
    "CVE-2024-56781",
    "CVE-2024-56782",
    "CVE-2024-56783",
    "CVE-2024-56785",
    "CVE-2024-56786",
    "CVE-2024-56787",
    "CVE-2024-57838",
    "CVE-2024-57843",
    "CVE-2024-57849",
    "CVE-2024-57850",
    "CVE-2024-57872",
    "CVE-2024-57874",
    "CVE-2024-57876",
    "CVE-2025-21700",
    "CVE-2025-21701",
    "CVE-2025-21702",
    "CVE-2025-21756",
    "CVE-2025-21831",
    "CVE-2025-21993"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/30");
  script_xref(name:"USN", value:"7449-1");

  script_name(english:"Ubuntu 22.04 LTS / 24.04 LTS : Linux kernel vulnerabilities (USN-7449-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 24.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-7449-1 advisory.

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM64 architecture;

    - MIPS architecture;

    - PowerPC architecture;

    - RISC-V architecture;

    - S390 architecture;

    - SuperH RISC architecture;

    - User-Mode Linux (UML);

    - x86 architecture;

    - Block layer subsystem;

    - Cryptographic API;

    - Compute Acceleration Framework;

    - ACPI drivers;

    - Drivers core;

    - RAM backed block device driver;

    - Compressed RAM block device driver;

    - TPM device driver;

    - Clock framework and drivers;

    - Data acquisition framework and drivers;

    - CPU frequency scaling framework;

    - Hardware crypto device drivers;

    - CXL (Compute Express Link) drivers;

    - EDAC drivers;

    - ARM SCMI message protocol;

    - ARM SCPI message protocol;

    - EFI core;

    - GPIO subsystem;

    - GPU drivers;

    - HID subsystem;

    - I3C subsystem;

    - IIO ADC drivers;

    - IIO subsystem;

    - InfiniBand drivers;

    - IOMMU subsystem;

    - LED subsystem;

    - Multiple devices driver;

    - Media drivers;

    - Multifunction device drivers;

    - MMC subsystem;

    - MTD block device drivers;

    - Network drivers;

    - Mellanox network drivers;

    - STMicroelectronics network drivers;

    - NVME drivers;

    - PCI subsystem;

    - PHY drivers;

    - Pin controllers subsystem;

    - x86 platform drivers;

    - i.MX PM domains;

    - Voltage and Current Regulator drivers;

    - StarFive reset controller drivers;

    - Real Time Clock drivers;

    - SCSI subsystem;

    - i.MX SoC drivers;

    - QCOM SoC drivers;

    - Xilinx SoC drivers;

    - SPI subsystem;

    - Media staging drivers;

    - TCM subsystem;

    - UFS subsystem;

    - DesignWare USB3 driver;

    - USB Dual Role (OTG-ready) Controller drivers;

    - USB Serial drivers;

    - USB Type-C support driver;

    - USB Type-C Port Controller Manager driver;

    - USB Type-C Connector System Software Interface driver;

    - vDPA drivers;

    - VFIO drivers;

    - Framebuffer layer;

    - Xen hypervisor drivers;

    - AFS file system;

    - BTRFS file system;

    - File systems infrastructure;

    - EROFS file system;

    - F2FS file system;

    - JFFS2 file system;

    - JFS file system;

    - Network file systems library;

    - Network file system (NFS) client;

    - Network file system (NFS) server daemon;

    - NILFS2 file system;

    - NTFS3 file system;

    - Overlay file system;

    - Proc file system;

    - Diskquota system;

    - SMB network file system;

    - UBI file system;

    - DRM display driver;

    - BPF subsystem;

    - StackDepot library;

    - Bluetooth subsystem;

    - IP tunnels definitions;

    - Netfilter;

    - Tracing infrastructure;

    - User-space API (UAPI);

    - Kernel init infrastructure;

    - io_uring subsystem;

    - IPC subsystem;

    - DMA mapping infrastructure;

    - Kernel fork() syscall;

    - KCSAN framework;

    - RCU subsystem;

    - Arbitrary resource management;

    - Scheduler infrastructure;

    - Signal handling mechanism;

    - Task handling mechanism;

    - Timer subsystem;

    - KUnit library;

    - Memory management;

    - 9P file system network protocol;

    - CAN network layer;

    - Networking core;

    - DCCP (Datagram Congestion Control Protocol);

    - Ethtool driver;

    - HSR network protocol;

    - IEEE802154.4 network protocol;

    - IPv4 networking;

    - IPv6 networking;

    - IUCV driver;

    - MAC80211 subsystem;

    - Multipath TCP;

    - Packet sockets;

    - RxRPC session sockets;

    - Network traffic control;

    - SCTP protocol;

    - SMC sockets;

    - Sun RPC protocol;

    - TIPC protocol;

    - VMware vSockets driver;

    - Wireless networking;

    - eXpress Data Path;

    - XFRM subsystem;

    - Integrity Measurement Architecture(IMA) framework;

    - Key management;

    - ALSA framework;

    - FireWire sound drivers;

    - HD-audio driver;

    - MediaTek ASoC drivers;

    - QCOM ASoC drivers;

    - SoC audio core drivers;

    - STMicroelectronics SoC drivers;

    - USB sound devices; (CVE-2024-50288, CVE-2024-56568, CVE-2024-50280, CVE-2024-56677, CVE-2024-56620,
    CVE-2024-53108, CVE-2024-53115, CVE-2024-53061, CVE-2024-53215, CVE-2024-50275, CVE-2024-53133,
    CVE-2024-50279, CVE-2025-21831, CVE-2025-21756, CVE-2024-56727, CVE-2024-50208, CVE-2024-50142,
    CVE-2024-53148, CVE-2024-56781, CVE-2024-53171, CVE-2024-56608, CVE-2024-53177, CVE-2024-56708,
    CVE-2024-50207, CVE-2024-50278, CVE-2024-50166, CVE-2024-56629, CVE-2024-56723, CVE-2024-50172,
    CVE-2024-56707, CVE-2024-50051, CVE-2024-56606, CVE-2024-56700, CVE-2024-56599, CVE-2024-53051,
    CVE-2024-56632, CVE-2024-47143, CVE-2024-53135, CVE-2024-53111, CVE-2024-56634, CVE-2024-50262,
    CVE-2024-56587, CVE-2024-50125, CVE-2024-53145, CVE-2024-53185, CVE-2024-56575, CVE-2024-53231,
    CVE-2024-53072, CVE-2024-50110, CVE-2024-53172, CVE-2024-50258, CVE-2024-53226, CVE-2024-50211,
    CVE-2024-43098, CVE-2024-50224, CVE-2024-56642, CVE-2024-53082, CVE-2024-50108, CVE-2024-53094,
    CVE-2024-53184, CVE-2024-56648, CVE-2024-50140, CVE-2024-53166, CVE-2024-53090, CVE-2024-50301,
    CVE-2024-56625, CVE-2024-50230, CVE-2024-56586, CVE-2024-53052, CVE-2024-56574, CVE-2024-53168,
    CVE-2024-53209, CVE-2024-56640, CVE-2024-49899, CVE-2024-50247, CVE-2024-50150, CVE-2024-53058,
    CVE-2024-50153, CVE-2024-56689, CVE-2024-50283, CVE-2024-50251, CVE-2024-56578, CVE-2024-50303,
    CVE-2024-56569, CVE-2024-53134, CVE-2024-50158, CVE-2024-56592, CVE-2024-50300, CVE-2024-57838,
    CVE-2024-50205, CVE-2024-56562, CVE-2024-57843, CVE-2024-53084, CVE-2024-56532, CVE-2024-50127,
    CVE-2024-56584, CVE-2024-53196, CVE-2024-56722, CVE-2024-50215, CVE-2022-49034, CVE-2024-47809,
    CVE-2024-56744, CVE-2024-50121, CVE-2024-53083, CVE-2024-56540, CVE-2024-50209, CVE-2024-56787,
    CVE-2024-48873, CVE-2024-53221, CVE-2024-56746, CVE-2024-50238, CVE-2024-50226, CVE-2024-52332,
    CVE-2024-56649, CVE-2024-56546, CVE-2024-53223, CVE-2024-50259, CVE-2024-50287, CVE-2024-56701,
    CVE-2024-56692, CVE-2024-50243, CVE-2024-53160, CVE-2024-56619, CVE-2024-50128, CVE-2024-53173,
    CVE-2024-53127, CVE-2024-56720, CVE-2024-56633, CVE-2024-48875, CVE-2024-56775, CVE-2024-50155,
    CVE-2024-56611, CVE-2024-56539, CVE-2024-50282, CVE-2024-56600, CVE-2024-53110, CVE-2024-50111,
    CVE-2024-56773, CVE-2024-53161, CVE-2024-56615, CVE-2024-56786, CVE-2024-56783, CVE-2024-56645,
    CVE-2024-50216, CVE-2024-56605, CVE-2024-56622, CVE-2024-56613, CVE-2024-50245, CVE-2024-50240,
    CVE-2024-53222, CVE-2024-53203, CVE-2024-53042, CVE-2024-56724, CVE-2024-57876, CVE-2024-49906,
    CVE-2024-56596, CVE-2024-50234, CVE-2024-41014, CVE-2024-53053, CVE-2024-48881, CVE-2024-56601,
    CVE-2024-56581, CVE-2024-56609, CVE-2024-56576, CVE-2024-53044, CVE-2024-53680, CVE-2024-50170,
    CVE-2024-50116, CVE-2024-56705, CVE-2024-53138, CVE-2024-53162, CVE-2024-50136, CVE-2024-53210,
    CVE-2024-50167, CVE-2024-50292, CVE-2024-53067, CVE-2024-53101, CVE-2024-56691, CVE-2024-53200,
    CVE-2024-50255, CVE-2024-53142, CVE-2025-21700, CVE-2024-50104, CVE-2024-56687, CVE-2024-50163,
    CVE-2024-56756, CVE-2024-50218, CVE-2024-56550, CVE-2024-53202, CVE-2024-50137, CVE-2024-50270,
    CVE-2024-56641, CVE-2024-53154, CVE-2024-53224, CVE-2024-53155, CVE-2024-50124, CVE-2024-41935,
    CVE-2024-50265, CVE-2024-53190, CVE-2024-50256, CVE-2024-53234, CVE-2024-56693, CVE-2024-50143,
    CVE-2024-53181, CVE-2024-50154, CVE-2024-53233, CVE-2024-56771, CVE-2024-53236, CVE-2024-53227,
    CVE-2024-56572, CVE-2024-53126, CVE-2024-56551, CVE-2024-50299, CVE-2024-53218, CVE-2024-50135,
    CVE-2024-53188, CVE-2024-56635, CVE-2024-53055, CVE-2024-56751, CVE-2024-56577, CVE-2024-50289,
    CVE-2024-56590, CVE-2024-56745, CVE-2024-53176, CVE-2024-56681, CVE-2024-50160, CVE-2024-56557,
    CVE-2024-53213, CVE-2024-50267, CVE-2024-50146, CVE-2024-56627, CVE-2024-50290, CVE-2024-56565,
    CVE-2024-56752, CVE-2024-56603, CVE-2024-50246, CVE-2024-56690, CVE-2024-50222, CVE-2024-53087,
    CVE-2024-53091, CVE-2024-50115, CVE-2024-53106, CVE-2024-50250, CVE-2024-50242, CVE-2024-50248,
    CVE-2024-53229, CVE-2024-56588, CVE-2024-56785, CVE-2024-53195, CVE-2025-21702, CVE-2024-53059,
    CVE-2024-50107, CVE-2024-50139, CVE-2024-50276, CVE-2024-56543, CVE-2024-53228, CVE-2024-50232,
    CVE-2024-53128, CVE-2024-56651, CVE-2024-53047, CVE-2024-56726, CVE-2024-50159, CVE-2024-50231,
    CVE-2024-56545, CVE-2024-56778, CVE-2024-56602, CVE-2024-50221, CVE-2024-56754, CVE-2024-56704,
    CVE-2024-56650, CVE-2024-57850, CVE-2024-50206, CVE-2024-56573, CVE-2024-56703, CVE-2024-53208,
    CVE-2024-53158, CVE-2024-50274, CVE-2024-56638, CVE-2024-50151, CVE-2024-53239, CVE-2024-56742,
    CVE-2024-50237, CVE-2024-53066, CVE-2024-56580, CVE-2024-56688, CVE-2024-53089, CVE-2024-56777,
    CVE-2024-50138, CVE-2024-53198, CVE-2024-56589, CVE-2024-56694, CVE-2024-50261, CVE-2024-53147,
    CVE-2024-50263, CVE-2024-56644, CVE-2024-56597, CVE-2024-53197, CVE-2024-50164, CVE-2024-53191,
    CVE-2024-56549, CVE-2024-50284, CVE-2024-57849, CVE-2024-56594, CVE-2024-56782, CVE-2024-50235,
    CVE-2024-49569, CVE-2024-53237, CVE-2024-56643, CVE-2024-53109, CVE-2024-53157, CVE-2024-56637,
    CVE-2024-56623, CVE-2024-56683, CVE-2024-50257, CVE-2024-56765, CVE-2024-53201, CVE-2024-53050,
    CVE-2024-53120, CVE-2024-53121, CVE-2024-50126, CVE-2024-56774, CVE-2024-53219, CVE-2024-56616,
    CVE-2024-50223, CVE-2024-41932, CVE-2024-50271, CVE-2024-56593, CVE-2024-50285, CVE-2024-53113,
    CVE-2025-21993, CVE-2024-56607, CVE-2024-50252, CVE-2024-56610, CVE-2024-53043, CVE-2024-50120,
    CVE-2024-44955, CVE-2024-50118, CVE-2024-53130, CVE-2024-56566, CVE-2024-53146, CVE-2024-56721,
    CVE-2024-53079, CVE-2024-56685, CVE-2024-50145, CVE-2024-56755, CVE-2024-50268, CVE-2024-53046,
    CVE-2024-50010, CVE-2024-56531, CVE-2024-53129, CVE-2024-47794, CVE-2024-53119, CVE-2024-50297,
    CVE-2024-56728, CVE-2025-21701, CVE-2024-53163, CVE-2024-56739, CVE-2024-56538, CVE-2024-50294,
    CVE-2024-53183, CVE-2024-53131, CVE-2024-56626, CVE-2024-50133, CVE-2024-53151, CVE-2024-56679,
    CVE-2024-50225, CVE-2024-50152, CVE-2024-53174, CVE-2024-56698, CVE-2024-53105, CVE-2024-53085,
    CVE-2024-53220, CVE-2024-53180, CVE-2024-53060, CVE-2024-53139, CVE-2024-56631, CVE-2024-53175,
    CVE-2024-57872, CVE-2024-56779, CVE-2024-50220, CVE-2024-50169, CVE-2024-56772, CVE-2024-53230,
    CVE-2024-53122, CVE-2024-50067, CVE-2024-56558, CVE-2024-45828, CVE-2024-57874, CVE-2024-50239,
    CVE-2024-53214, CVE-2024-56621, CVE-2024-50156, CVE-2024-56583, CVE-2024-56776, CVE-2024-50298,
    CVE-2024-56533, CVE-2024-56748, CVE-2024-53114, CVE-2024-53187, CVE-2024-50269, CVE-2024-50286,
    CVE-2024-56579, CVE-2024-56548, CVE-2024-50210, CVE-2024-50244, CVE-2024-50291, CVE-2024-56567,
    CVE-2024-56780, CVE-2024-53150, CVE-2024-56636, CVE-2024-56561, CVE-2024-53194, CVE-2024-53093,
    CVE-2024-53117, CVE-2024-53062, CVE-2024-53123, CVE-2024-50236, CVE-2024-56630, CVE-2024-56678,
    CVE-2024-48876, CVE-2024-50249, CVE-2024-53099, CVE-2024-53048, CVE-2024-50296, CVE-2024-50131,
    CVE-2024-50105, CVE-2024-50141, CVE-2024-56729, CVE-2024-53217, CVE-2024-50295, CVE-2024-50130,
    CVE-2024-56725, CVE-2024-42122, CVE-2024-56570, CVE-2024-53118, CVE-2024-50112, CVE-2024-50203,
    CVE-2024-53178, CVE-2024-53068, CVE-2024-50272, CVE-2024-53232, CVE-2024-53088, CVE-2024-56647,
    CVE-2024-53076, CVE-2024-53100, CVE-2024-53096, CVE-2024-56747, CVE-2024-53045, CVE-2024-53086,
    CVE-2024-50147, CVE-2024-53081, CVE-2024-50273, CVE-2024-50103, CVE-2024-53107, CVE-2024-53095,
    CVE-2024-47141, CVE-2024-56604, CVE-2024-50304, CVE-2024-53169, CVE-2024-50162, CVE-2024-53112)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7449-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-57850");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1024-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1024-oracle-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1026-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1026-nvidia-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1026-nvidia-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1026-nvidia-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1027-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1027-azure-fde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-58-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-58-lowlatency-64k");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'lowlatency': '6.8.0-58',
      'lowlatency-64k': '6.8.0-58',
      'oracle': '6.8.0-1024',
      'oracle-64k': '6.8.0-1024',
      'nvidia': '6.8.0-1026',
      'nvidia-64k': '6.8.0-1026',
      'azure': '6.8.0-1027',
      'azure-fde': '6.8.0-1027'
    }
  },
  '24.04': {
    '6.8.0': {
      'lowlatency': '6.8.0-58',
      'lowlatency-64k': '6.8.0-58',
      'oracle': '6.8.0-1024',
      'oracle-64k': '6.8.0-1024',
      'nvidia-lowlatency': '6.8.0-1026',
      'nvidia-lowlatency-64k': '6.8.0-1026',
      'azure': '6.8.0-1027',
      'azure-fde': '6.8.0-1027'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7449-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-49034', 'CVE-2024-41014', 'CVE-2024-41932', 'CVE-2024-41935', 'CVE-2024-42122', 'CVE-2024-43098', 'CVE-2024-44955', 'CVE-2024-45828', 'CVE-2024-47141', 'CVE-2024-47143', 'CVE-2024-47794', 'CVE-2024-47809', 'CVE-2024-48873', 'CVE-2024-48875', 'CVE-2024-48876', 'CVE-2024-48881', 'CVE-2024-49569', 'CVE-2024-49899', 'CVE-2024-49906', 'CVE-2024-50010', 'CVE-2024-50051', 'CVE-2024-50067', 'CVE-2024-50103', 'CVE-2024-50104', 'CVE-2024-50105', 'CVE-2024-50107', 'CVE-2024-50108', 'CVE-2024-50110', 'CVE-2024-50111', 'CVE-2024-50112', 'CVE-2024-50115', 'CVE-2024-50116', 'CVE-2024-50118', 'CVE-2024-50120', 'CVE-2024-50121', 'CVE-2024-50124', 'CVE-2024-50125', 'CVE-2024-50126', 'CVE-2024-50127', 'CVE-2024-50128', 'CVE-2024-50130', 'CVE-2024-50131', 'CVE-2024-50133', 'CVE-2024-50135', 'CVE-2024-50136', 'CVE-2024-50137', 'CVE-2024-50138', 'CVE-2024-50139', 'CVE-2024-50140', 'CVE-2024-50141', 'CVE-2024-50142', 'CVE-2024-50143', 'CVE-2024-50145', 'CVE-2024-50146', 'CVE-2024-50147', 'CVE-2024-50150', 'CVE-2024-50151', 'CVE-2024-50152', 'CVE-2024-50153', 'CVE-2024-50154', 'CVE-2024-50155', 'CVE-2024-50156', 'CVE-2024-50158', 'CVE-2024-50159', 'CVE-2024-50160', 'CVE-2024-50162', 'CVE-2024-50163', 'CVE-2024-50164', 'CVE-2024-50166', 'CVE-2024-50167', 'CVE-2024-50169', 'CVE-2024-50170', 'CVE-2024-50172', 'CVE-2024-50203', 'CVE-2024-50205', 'CVE-2024-50206', 'CVE-2024-50207', 'CVE-2024-50208', 'CVE-2024-50209', 'CVE-2024-50210', 'CVE-2024-50211', 'CVE-2024-50215', 'CVE-2024-50216', 'CVE-2024-50218', 'CVE-2024-50220', 'CVE-2024-50221', 'CVE-2024-50222', 'CVE-2024-50223', 'CVE-2024-50224', 'CVE-2024-50225', 'CVE-2024-50226', 'CVE-2024-50230', 'CVE-2024-50231', 'CVE-2024-50232', 'CVE-2024-50234', 'CVE-2024-50235', 'CVE-2024-50236', 'CVE-2024-50237', 'CVE-2024-50238', 'CVE-2024-50239', 'CVE-2024-50240', 'CVE-2024-50242', 'CVE-2024-50243', 'CVE-2024-50244', 'CVE-2024-50245', 'CVE-2024-50246', 'CVE-2024-50247', 'CVE-2024-50248', 'CVE-2024-50249', 'CVE-2024-50250', 'CVE-2024-50251', 'CVE-2024-50252', 'CVE-2024-50255', 'CVE-2024-50256', 'CVE-2024-50257', 'CVE-2024-50258', 'CVE-2024-50259', 'CVE-2024-50261', 'CVE-2024-50262', 'CVE-2024-50263', 'CVE-2024-50265', 'CVE-2024-50267', 'CVE-2024-50268', 'CVE-2024-50269', 'CVE-2024-50270', 'CVE-2024-50271', 'CVE-2024-50272', 'CVE-2024-50273', 'CVE-2024-50274', 'CVE-2024-50275', 'CVE-2024-50276', 'CVE-2024-50278', 'CVE-2024-50279', 'CVE-2024-50280', 'CVE-2024-50282', 'CVE-2024-50283', 'CVE-2024-50284', 'CVE-2024-50285', 'CVE-2024-50286', 'CVE-2024-50287', 'CVE-2024-50288', 'CVE-2024-50289', 'CVE-2024-50290', 'CVE-2024-50291', 'CVE-2024-50292', 'CVE-2024-50294', 'CVE-2024-50295', 'CVE-2024-50296', 'CVE-2024-50297', 'CVE-2024-50298', 'CVE-2024-50299', 'CVE-2024-50300', 'CVE-2024-50301', 'CVE-2024-50303', 'CVE-2024-50304', 'CVE-2024-52332', 'CVE-2024-53042', 'CVE-2024-53043', 'CVE-2024-53044', 'CVE-2024-53045', 'CVE-2024-53046', 'CVE-2024-53047', 'CVE-2024-53048', 'CVE-2024-53050', 'CVE-2024-53051', 'CVE-2024-53052', 'CVE-2024-53053', 'CVE-2024-53055', 'CVE-2024-53058', 'CVE-2024-53059', 'CVE-2024-53060', 'CVE-2024-53061', 'CVE-2024-53062', 'CVE-2024-53066', 'CVE-2024-53067', 'CVE-2024-53068', 'CVE-2024-53072', 'CVE-2024-53076', 'CVE-2024-53079', 'CVE-2024-53081', 'CVE-2024-53082', 'CVE-2024-53083', 'CVE-2024-53084', 'CVE-2024-53085', 'CVE-2024-53086', 'CVE-2024-53087', 'CVE-2024-53088', 'CVE-2024-53089', 'CVE-2024-53090', 'CVE-2024-53091', 'CVE-2024-53093', 'CVE-2024-53094', 'CVE-2024-53095', 'CVE-2024-53096', 'CVE-2024-53099', 'CVE-2024-53100', 'CVE-2024-53101', 'CVE-2024-53105', 'CVE-2024-53106', 'CVE-2024-53107', 'CVE-2024-53108', 'CVE-2024-53109', 'CVE-2024-53110', 'CVE-2024-53111', 'CVE-2024-53112', 'CVE-2024-53113', 'CVE-2024-53114', 'CVE-2024-53115', 'CVE-2024-53117', 'CVE-2024-53118', 'CVE-2024-53119', 'CVE-2024-53120', 'CVE-2024-53121', 'CVE-2024-53122', 'CVE-2024-53123', 'CVE-2024-53126', 'CVE-2024-53127', 'CVE-2024-53128', 'CVE-2024-53129', 'CVE-2024-53130', 'CVE-2024-53131', 'CVE-2024-53133', 'CVE-2024-53134', 'CVE-2024-53135', 'CVE-2024-53138', 'CVE-2024-53139', 'CVE-2024-53142', 'CVE-2024-53145', 'CVE-2024-53146', 'CVE-2024-53147', 'CVE-2024-53148', 'CVE-2024-53150', 'CVE-2024-53151', 'CVE-2024-53154', 'CVE-2024-53155', 'CVE-2024-53157', 'CVE-2024-53158', 'CVE-2024-53160', 'CVE-2024-53161', 'CVE-2024-53162', 'CVE-2024-53163', 'CVE-2024-53166', 'CVE-2024-53168', 'CVE-2024-53169', 'CVE-2024-53171', 'CVE-2024-53172', 'CVE-2024-53173', 'CVE-2024-53174', 'CVE-2024-53175', 'CVE-2024-53176', 'CVE-2024-53177', 'CVE-2024-53178', 'CVE-2024-53180', 'CVE-2024-53181', 'CVE-2024-53183', 'CVE-2024-53184', 'CVE-2024-53185', 'CVE-2024-53187', 'CVE-2024-53188', 'CVE-2024-53190', 'CVE-2024-53191', 'CVE-2024-53194', 'CVE-2024-53195', 'CVE-2024-53196', 'CVE-2024-53197', 'CVE-2024-53198', 'CVE-2024-53200', 'CVE-2024-53201', 'CVE-2024-53202', 'CVE-2024-53203', 'CVE-2024-53208', 'CVE-2024-53209', 'CVE-2024-53210', 'CVE-2024-53213', 'CVE-2024-53214', 'CVE-2024-53215', 'CVE-2024-53217', 'CVE-2024-53218', 'CVE-2024-53219', 'CVE-2024-53220', 'CVE-2024-53221', 'CVE-2024-53222', 'CVE-2024-53223', 'CVE-2024-53224', 'CVE-2024-53226', 'CVE-2024-53227', 'CVE-2024-53228', 'CVE-2024-53229', 'CVE-2024-53230', 'CVE-2024-53231', 'CVE-2024-53232', 'CVE-2024-53233', 'CVE-2024-53234', 'CVE-2024-53236', 'CVE-2024-53237', 'CVE-2024-53239', 'CVE-2024-53680', 'CVE-2024-56531', 'CVE-2024-56532', 'CVE-2024-56533', 'CVE-2024-56538', 'CVE-2024-56539', 'CVE-2024-56540', 'CVE-2024-56543', 'CVE-2024-56545', 'CVE-2024-56546', 'CVE-2024-56548', 'CVE-2024-56549', 'CVE-2024-56550', 'CVE-2024-56551', 'CVE-2024-56557', 'CVE-2024-56558', 'CVE-2024-56561', 'CVE-2024-56562', 'CVE-2024-56565', 'CVE-2024-56566', 'CVE-2024-56567', 'CVE-2024-56568', 'CVE-2024-56569', 'CVE-2024-56570', 'CVE-2024-56572', 'CVE-2024-56573', 'CVE-2024-56574', 'CVE-2024-56575', 'CVE-2024-56576', 'CVE-2024-56577', 'CVE-2024-56578', 'CVE-2024-56579', 'CVE-2024-56580', 'CVE-2024-56581', 'CVE-2024-56583', 'CVE-2024-56584', 'CVE-2024-56586', 'CVE-2024-56587', 'CVE-2024-56588', 'CVE-2024-56589', 'CVE-2024-56590', 'CVE-2024-56592', 'CVE-2024-56593', 'CVE-2024-56594', 'CVE-2024-56596', 'CVE-2024-56597', 'CVE-2024-56599', 'CVE-2024-56600', 'CVE-2024-56601', 'CVE-2024-56602', 'CVE-2024-56603', 'CVE-2024-56604', 'CVE-2024-56605', 'CVE-2024-56606', 'CVE-2024-56607', 'CVE-2024-56608', 'CVE-2024-56609', 'CVE-2024-56610', 'CVE-2024-56611', 'CVE-2024-56613', 'CVE-2024-56615', 'CVE-2024-56616', 'CVE-2024-56619', 'CVE-2024-56620', 'CVE-2024-56621', 'CVE-2024-56622', 'CVE-2024-56623', 'CVE-2024-56625', 'CVE-2024-56626', 'CVE-2024-56627', 'CVE-2024-56629', 'CVE-2024-56630', 'CVE-2024-56631', 'CVE-2024-56632', 'CVE-2024-56633', 'CVE-2024-56634', 'CVE-2024-56635', 'CVE-2024-56636', 'CVE-2024-56637', 'CVE-2024-56638', 'CVE-2024-56640', 'CVE-2024-56641', 'CVE-2024-56642', 'CVE-2024-56643', 'CVE-2024-56644', 'CVE-2024-56645', 'CVE-2024-56647', 'CVE-2024-56648', 'CVE-2024-56649', 'CVE-2024-56650', 'CVE-2024-56651', 'CVE-2024-56677', 'CVE-2024-56678', 'CVE-2024-56679', 'CVE-2024-56681', 'CVE-2024-56683', 'CVE-2024-56685', 'CVE-2024-56687', 'CVE-2024-56688', 'CVE-2024-56689', 'CVE-2024-56690', 'CVE-2024-56691', 'CVE-2024-56692', 'CVE-2024-56693', 'CVE-2024-56694', 'CVE-2024-56698', 'CVE-2024-56700', 'CVE-2024-56701', 'CVE-2024-56703', 'CVE-2024-56704', 'CVE-2024-56705', 'CVE-2024-56707', 'CVE-2024-56708', 'CVE-2024-56720', 'CVE-2024-56721', 'CVE-2024-56722', 'CVE-2024-56723', 'CVE-2024-56724', 'CVE-2024-56725', 'CVE-2024-56726', 'CVE-2024-56727', 'CVE-2024-56728', 'CVE-2024-56729', 'CVE-2024-56739', 'CVE-2024-56742', 'CVE-2024-56744', 'CVE-2024-56745', 'CVE-2024-56746', 'CVE-2024-56747', 'CVE-2024-56748', 'CVE-2024-56751', 'CVE-2024-56752', 'CVE-2024-56754', 'CVE-2024-56755', 'CVE-2024-56756', 'CVE-2024-56765', 'CVE-2024-56771', 'CVE-2024-56772', 'CVE-2024-56773', 'CVE-2024-56774', 'CVE-2024-56775', 'CVE-2024-56776', 'CVE-2024-56777', 'CVE-2024-56778', 'CVE-2024-56779', 'CVE-2024-56780', 'CVE-2024-56781', 'CVE-2024-56782', 'CVE-2024-56783', 'CVE-2024-56785', 'CVE-2024-56786', 'CVE-2024-56787', 'CVE-2024-57838', 'CVE-2024-57843', 'CVE-2024-57849', 'CVE-2024-57850', 'CVE-2024-57872', 'CVE-2024-57874', 'CVE-2024-57876', 'CVE-2025-21700', 'CVE-2025-21701', 'CVE-2025-21702', 'CVE-2025-21756', 'CVE-2025-21831', 'CVE-2025-21993');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7449-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
