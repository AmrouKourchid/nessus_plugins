#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6919-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204794);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2022-38096",
    "CVE-2022-48808",
    "CVE-2023-6270",
    "CVE-2023-7042",
    "CVE-2023-52434",
    "CVE-2023-52447",
    "CVE-2023-52488",
    "CVE-2023-52497",
    "CVE-2023-52620",
    "CVE-2023-52640",
    "CVE-2023-52641",
    "CVE-2023-52644",
    "CVE-2023-52645",
    "CVE-2023-52650",
    "CVE-2023-52652",
    "CVE-2023-52656",
    "CVE-2023-52662",
    "CVE-2023-52699",
    "CVE-2023-52880",
    "CVE-2024-0841",
    "CVE-2024-21823",
    "CVE-2024-22099",
    "CVE-2024-23307",
    "CVE-2024-24857",
    "CVE-2024-24858",
    "CVE-2024-24859",
    "CVE-2024-24861",
    "CVE-2024-25739",
    "CVE-2024-26583",
    "CVE-2024-26584",
    "CVE-2024-26585",
    "CVE-2024-26601",
    "CVE-2024-26603",
    "CVE-2024-26629",
    "CVE-2024-26642",
    "CVE-2024-26643",
    "CVE-2024-26651",
    "CVE-2024-26654",
    "CVE-2024-26659",
    "CVE-2024-26687",
    "CVE-2024-26688",
    "CVE-2024-26733",
    "CVE-2024-26735",
    "CVE-2024-26736",
    "CVE-2024-26737",
    "CVE-2024-26743",
    "CVE-2024-26744",
    "CVE-2024-26747",
    "CVE-2024-26748",
    "CVE-2024-26749",
    "CVE-2024-26750",
    "CVE-2024-26751",
    "CVE-2024-26752",
    "CVE-2024-26754",
    "CVE-2024-26763",
    "CVE-2024-26764",
    "CVE-2024-26766",
    "CVE-2024-26769",
    "CVE-2024-26771",
    "CVE-2024-26772",
    "CVE-2024-26773",
    "CVE-2024-26774",
    "CVE-2024-26776",
    "CVE-2024-26777",
    "CVE-2024-26778",
    "CVE-2024-26779",
    "CVE-2024-26782",
    "CVE-2024-26787",
    "CVE-2024-26788",
    "CVE-2024-26790",
    "CVE-2024-26791",
    "CVE-2024-26792",
    "CVE-2024-26793",
    "CVE-2024-26795",
    "CVE-2024-26798",
    "CVE-2024-26801",
    "CVE-2024-26802",
    "CVE-2024-26803",
    "CVE-2024-26804",
    "CVE-2024-26805",
    "CVE-2024-26809",
    "CVE-2024-26810",
    "CVE-2024-26811",
    "CVE-2024-26812",
    "CVE-2024-26813",
    "CVE-2024-26814",
    "CVE-2024-26816",
    "CVE-2024-26817",
    "CVE-2024-26820",
    "CVE-2024-26828",
    "CVE-2024-26833",
    "CVE-2024-26835",
    "CVE-2024-26838",
    "CVE-2024-26839",
    "CVE-2024-26840",
    "CVE-2024-26843",
    "CVE-2024-26845",
    "CVE-2024-26846",
    "CVE-2024-26848",
    "CVE-2024-26851",
    "CVE-2024-26852",
    "CVE-2024-26855",
    "CVE-2024-26856",
    "CVE-2024-26857",
    "CVE-2024-26859",
    "CVE-2024-26861",
    "CVE-2024-26862",
    "CVE-2024-26863",
    "CVE-2024-26870",
    "CVE-2024-26872",
    "CVE-2024-26874",
    "CVE-2024-26875",
    "CVE-2024-26877",
    "CVE-2024-26878",
    "CVE-2024-26879",
    "CVE-2024-26880",
    "CVE-2024-26881",
    "CVE-2024-26882",
    "CVE-2024-26883",
    "CVE-2024-26884",
    "CVE-2024-26885",
    "CVE-2024-26889",
    "CVE-2024-26891",
    "CVE-2024-26894",
    "CVE-2024-26895",
    "CVE-2024-26897",
    "CVE-2024-26898",
    "CVE-2024-26901",
    "CVE-2024-26903",
    "CVE-2024-26906",
    "CVE-2024-26907",
    "CVE-2024-26915",
    "CVE-2024-26922",
    "CVE-2024-26923",
    "CVE-2024-26924",
    "CVE-2024-26925",
    "CVE-2024-26926",
    "CVE-2024-26929",
    "CVE-2024-26931",
    "CVE-2024-26934",
    "CVE-2024-26935",
    "CVE-2024-26937",
    "CVE-2024-26950",
    "CVE-2024-26951",
    "CVE-2024-26955",
    "CVE-2024-26956",
    "CVE-2024-26957",
    "CVE-2024-26958",
    "CVE-2024-26960",
    "CVE-2024-26961",
    "CVE-2024-26964",
    "CVE-2024-26965",
    "CVE-2024-26966",
    "CVE-2024-26969",
    "CVE-2024-26970",
    "CVE-2024-26973",
    "CVE-2024-26974",
    "CVE-2024-26976",
    "CVE-2024-26977",
    "CVE-2024-26981",
    "CVE-2024-26984",
    "CVE-2024-26988",
    "CVE-2024-26989",
    "CVE-2024-26993",
    "CVE-2024-26994",
    "CVE-2024-26996",
    "CVE-2024-26999",
    "CVE-2024-27000",
    "CVE-2024-27001",
    "CVE-2024-27004",
    "CVE-2024-27008",
    "CVE-2024-27009",
    "CVE-2024-27013",
    "CVE-2024-27015",
    "CVE-2024-27016",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27024",
    "CVE-2024-27028",
    "CVE-2024-27030",
    "CVE-2024-27034",
    "CVE-2024-27037",
    "CVE-2024-27038",
    "CVE-2024-27039",
    "CVE-2024-27043",
    "CVE-2024-27044",
    "CVE-2024-27045",
    "CVE-2024-27046",
    "CVE-2024-27047",
    "CVE-2024-27051",
    "CVE-2024-27052",
    "CVE-2024-27053",
    "CVE-2024-27054",
    "CVE-2024-27059",
    "CVE-2024-27065",
    "CVE-2024-27073",
    "CVE-2024-27074",
    "CVE-2024-27075",
    "CVE-2024-27076",
    "CVE-2024-27077",
    "CVE-2024-27078",
    "CVE-2024-27388",
    "CVE-2024-27390",
    "CVE-2024-27393",
    "CVE-2024-27395",
    "CVE-2024-27396",
    "CVE-2024-27403",
    "CVE-2024-27405",
    "CVE-2024-27410",
    "CVE-2024-27412",
    "CVE-2024-27413",
    "CVE-2024-27414",
    "CVE-2024-27415",
    "CVE-2024-27416",
    "CVE-2024-27417",
    "CVE-2024-27419",
    "CVE-2024-27431",
    "CVE-2024-27432",
    "CVE-2024-27436",
    "CVE-2024-27437",
    "CVE-2024-35785",
    "CVE-2024-35789",
    "CVE-2024-35791",
    "CVE-2024-35796",
    "CVE-2024-35804",
    "CVE-2024-35805",
    "CVE-2024-35806",
    "CVE-2024-35807",
    "CVE-2024-35809",
    "CVE-2024-35813",
    "CVE-2024-35817",
    "CVE-2024-35819",
    "CVE-2024-35821",
    "CVE-2024-35822",
    "CVE-2024-35823",
    "CVE-2024-35825",
    "CVE-2024-35828",
    "CVE-2024-35829",
    "CVE-2024-35830",
    "CVE-2024-35844",
    "CVE-2024-35845",
    "CVE-2024-35847",
    "CVE-2024-35849",
    "CVE-2024-35851",
    "CVE-2024-35852",
    "CVE-2024-35853",
    "CVE-2024-35854",
    "CVE-2024-35855",
    "CVE-2024-35857",
    "CVE-2024-35871",
    "CVE-2024-35872",
    "CVE-2024-35877",
    "CVE-2024-35879",
    "CVE-2024-35884",
    "CVE-2024-35885",
    "CVE-2024-35886",
    "CVE-2024-35888",
    "CVE-2024-35890",
    "CVE-2024-35893",
    "CVE-2024-35895",
    "CVE-2024-35896",
    "CVE-2024-35897",
    "CVE-2024-35898",
    "CVE-2024-35899",
    "CVE-2024-35900",
    "CVE-2024-35905",
    "CVE-2024-35907",
    "CVE-2024-35910",
    "CVE-2024-35912",
    "CVE-2024-35915",
    "CVE-2024-35918",
    "CVE-2024-35922",
    "CVE-2024-35925",
    "CVE-2024-35930",
    "CVE-2024-35933",
    "CVE-2024-35934",
    "CVE-2024-35935",
    "CVE-2024-35936",
    "CVE-2024-35938",
    "CVE-2024-35940",
    "CVE-2024-35944",
    "CVE-2024-35950",
    "CVE-2024-35955",
    "CVE-2024-35958",
    "CVE-2024-35960",
    "CVE-2024-35969",
    "CVE-2024-35970",
    "CVE-2024-35973",
    "CVE-2024-35976",
    "CVE-2024-35978",
    "CVE-2024-35982",
    "CVE-2024-35984",
    "CVE-2024-35988",
    "CVE-2024-35989",
    "CVE-2024-35990",
    "CVE-2024-35997",
    "CVE-2024-36004",
    "CVE-2024-36005",
    "CVE-2024-36006",
    "CVE-2024-36007",
    "CVE-2024-36008",
    "CVE-2024-36020",
    "CVE-2024-36025",
    "CVE-2024-36029"
  );
  script_xref(name:"USN", value:"6919-1");

  script_name(english:"Ubuntu 22.04 LTS : Linux kernel vulnerabilities (USN-6919-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6919-1 advisory.

    Ziming Zhang discovered that the DRM driver for VMware Virtual GPU did not properly handle certain error
    conditions, leading to a NULL pointer dereference. A local attacker could possibly trigger this
    vulnerability to cause a denial of service. (CVE-2022-38096)

    It was discovered that the ATA over Ethernet (AoE) driver in the Linux kernel contained a race condition,
    leading to a use-after-free vulnerability. An attacker could use this to cause a denial of service or
    possibly execute arbitrary code. (CVE-2023-6270)

    It was discovered that the Atheros 802.11ac wireless driver did not properly validate certain data
    structures, leading to a NULL pointer dereference. An attacker could possibly use this to cause a denial
    of service. (CVE-2023-7042)

    It was discovered that the HugeTLB file system component of the Linux Kernel contained a NULL pointer
    dereference vulnerability. A privileged attacker could possibly use this to to cause a denial of service.
    (CVE-2024-0841)

    It was discovered that the Intel Data Streaming and Intel Analytics Accelerator drivers in the Linux
    kernel allowed direct access to the devices for unprivileged users and virtual machines. A local attacker
    could use this to cause a denial of service. (CVE-2024-21823)

    Yuxuan Hu discovered that the Bluetooth RFCOMM protocol driver in the Linux Kernel contained a race
    condition, leading to a NULL pointer dereference. An attacker could possibly use this to cause a denial of
    service (system crash). (CVE-2024-22099)

    Gui-Dong Han discovered that the software RAID driver in the Linux kernel contained a race condition,
    leading to an integer overflow vulnerability. A privileged attacker could possibly use this to cause a
    denial of service (system crash). (CVE-2024-23307)

    It was discovered that a race condition existed in the Bluetooth subsystem in the Linux kernel when
    modifying certain settings values through debugfs. A privileged local attacker could use this to cause a
    denial of service. (CVE-2024-24857, CVE-2024-24858, CVE-2024-24859)

    Bai Jiaju discovered that the Xceive XC4000 silicon tuner device driver in the Linux kernel contained a
    race condition, leading to an integer overflow vulnerability. An attacker could possibly use this to cause
    a denial of service (system crash). (CVE-2024-24861)

    Chenyuan Yang discovered that the Unsorted Block Images (UBI) flash device volume management subsystem did
    not properly validate logical eraseblock sizes in certain situations. An attacker could possibly use this
    to cause a denial of service (system crash). (CVE-2024-25739)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM32 architecture;

    - ARM64 architecture;

    - RISC-V architecture;

    - x86 architecture;

    - Block layer subsystem;

    - Accessibility subsystem;

    - ACPI drivers;

    - Android drivers;

    - Bluetooth drivers;

    - Clock framework and drivers;

    - Data acquisition framework and drivers;

    - CPU frequency scaling framework;

    - Cryptographic API;

    - DMA engine subsystem;

    - EFI core;

    - GPU drivers;

    - HID subsystem;

    - I2C subsystem;

    - InfiniBand drivers;

    - IOMMU subsystem;

    - IRQ chip drivers;

    - Multiple devices driver;

    - Media drivers;

    - VMware VMCI Driver;

    - MMC subsystem;

    - Network drivers;

    - NTB driver;

    - NVME drivers;

    - Device tree and open firmware driver;

    - PCI subsystem;

    - MediaTek PM domains;

    - Power supply drivers;

    - S/390 drivers;

    - SCSI drivers;

    - Freescale SoC drivers;

    - SPI subsystem;

    - Media staging drivers;

    - TCM subsystem;

    - Trusted Execution Environment drivers;

    - TTY drivers;

    - USB subsystem;

    - VFIO drivers;

    - Framebuffer layer;

    - Xen hypervisor drivers;

    - AFS file system;

    - File systems infrastructure;

    - BTRFS file system;

    - EROFS file system;

    - Ext4 file system;

    - F2FS file system;

    - FAT file system;

    - Network file system client;

    - Network file system server daemon;

    - NILFS2 file system;

    - NTFS3 file system;

    - Pstore file system;

    - Diskquota system;

    - SMB network file system;

    - UBI file system;

    - BPF subsystem;

    - Netfilter;

    - TLS protocol;

    - io_uring subsystem;

    - Core kernel;

    - PCI iomap interfaces;

    - Memory management;

    - B.A.T.M.A.N. meshing protocol;

    - Bluetooth subsystem;

    - Ethernet bridge;

    - Networking core;

    - Distributed Switch Architecture;

    - HSR network protocol;

    - IPv4 networking;

    - IPv6 networking;

    - L2TP protocol;

    - MAC80211 subsystem;

    - IEEE 802.15.4 subsystem;

    - Multipath TCP;

    - Netlink;

    - NET/ROM layer;

    - NFC subsystem;

    - Open vSwitch;

    - Packet sockets;

    - RDS protocol;

    - Network traffic control;

    - SMC sockets;

    - Sun RPC protocol;

    - Unix domain sockets;

    - Wireless networking;

    - eXpress Data Path;

    - ALSA SH drivers;

    - USB sound devices;

    - KVM core; (CVE-2024-26984, CVE-2024-26838, CVE-2024-26925, CVE-2024-26790, CVE-2024-26955,
    CVE-2024-27431, CVE-2024-26737, CVE-2024-27044, CVE-2024-26964, CVE-2024-26880, CVE-2024-26926,
    CVE-2024-26843, CVE-2024-26735, CVE-2024-26881, CVE-2023-52644, CVE-2024-26747, CVE-2024-27405,
    CVE-2024-26875, CVE-2024-35896, CVE-2024-35829, CVE-2024-26877, CVE-2024-26855, CVE-2024-27414,
    CVE-2024-35897, CVE-2024-35845, CVE-2024-26601, CVE-2024-35817, CVE-2024-36006, CVE-2024-26957,
    CVE-2024-27019, CVE-2024-35830, CVE-2024-26977, CVE-2024-26803, CVE-2024-26629, CVE-2024-26994,
    CVE-2024-27078, CVE-2024-35789, CVE-2023-52641, CVE-2024-27016, CVE-2024-26752, CVE-2024-27028,
    CVE-2024-26817, CVE-2024-26840, CVE-2024-26969, CVE-2024-26965, CVE-2023-52656, CVE-2024-35973,
    CVE-2024-35852, CVE-2024-26651, CVE-2024-27432, CVE-2024-27416, CVE-2024-26792, CVE-2024-35877,
    CVE-2024-26584, CVE-2024-26903, CVE-2024-26951, CVE-2024-36004, CVE-2024-26861, CVE-2024-27412,
    CVE-2024-26788, CVE-2024-35813, CVE-2024-26931, CVE-2023-52620, CVE-2024-27075, CVE-2024-36008,
    CVE-2024-35855, CVE-2024-27059, CVE-2024-35806, CVE-2024-26763, CVE-2024-35955, CVE-2024-35936,
    CVE-2024-26856, CVE-2024-26966, CVE-2024-35969, CVE-2024-35960, CVE-2024-35796, CVE-2024-26810,
    CVE-2024-26862, CVE-2023-52434, CVE-2024-27046, CVE-2024-26999, CVE-2024-26778, CVE-2023-52497,
    CVE-2024-35872, CVE-2024-26585, CVE-2024-35978, CVE-2024-35918, CVE-2024-35879, CVE-2024-27388,
    CVE-2024-26898, CVE-2024-26879, CVE-2024-26882, CVE-2023-52650, CVE-2024-35884, CVE-2024-27396,
    CVE-2024-35785, CVE-2024-36005, CVE-2024-35989, CVE-2023-52662, CVE-2024-35857, CVE-2024-26828,
    CVE-2024-27054, CVE-2024-26688, CVE-2024-35997, CVE-2024-26603, CVE-2024-26820, CVE-2024-35915,
    CVE-2024-35982, CVE-2024-26874, CVE-2024-26801, CVE-2024-26814, CVE-2024-27045, CVE-2024-26897,
    CVE-2024-35895, CVE-2024-35944, CVE-2024-35804, CVE-2024-26805, CVE-2024-27052, CVE-2024-35851,
    CVE-2024-35900, CVE-2024-35807, CVE-2024-26816, CVE-2024-26769, CVE-2024-27004, CVE-2024-27001,
    CVE-2024-27415, CVE-2024-35825, CVE-2024-26777, CVE-2024-27000, CVE-2024-27030, CVE-2024-26878,
    CVE-2024-26804, CVE-2024-27051, CVE-2024-26934, CVE-2024-27043, CVE-2024-26791, CVE-2024-27009,
    CVE-2024-26795, CVE-2023-52640, CVE-2024-35893, CVE-2024-35898, CVE-2024-26859, CVE-2024-27393,
    CVE-2024-26766, CVE-2024-26659, CVE-2024-26642, CVE-2024-26989, CVE-2024-26811, CVE-2024-26846,
    CVE-2024-26743, CVE-2024-35823, CVE-2024-27076, CVE-2024-26935, CVE-2023-52645, CVE-2024-26813,
    CVE-2024-26782, CVE-2024-26970, CVE-2024-26915, CVE-2024-27039, CVE-2024-26906, CVE-2024-35791,
    CVE-2024-35990, CVE-2024-26845, CVE-2024-35805, CVE-2024-35912, CVE-2024-27437, CVE-2024-27436,
    CVE-2024-26772, CVE-2024-26812, CVE-2024-26754, CVE-2024-26958, CVE-2024-26956, CVE-2024-26749,
    CVE-2024-27413, CVE-2024-27037, CVE-2023-52447, CVE-2024-27403, CVE-2023-52652, CVE-2024-36025,
    CVE-2024-26996, CVE-2024-35847, CVE-2022-48808, CVE-2024-26976, CVE-2024-26802, CVE-2024-36020,
    CVE-2024-27034, CVE-2024-26993, CVE-2024-27065, CVE-2024-35930, CVE-2024-26774, CVE-2024-26872,
    CVE-2024-26924, CVE-2024-26852, CVE-2024-26923, CVE-2024-26771, CVE-2024-35933, CVE-2024-35925,
    CVE-2024-26937, CVE-2024-26894, CVE-2024-26839, CVE-2024-35899, CVE-2024-26889, CVE-2024-35958,
    CVE-2024-35885, CVE-2024-35828, CVE-2024-26870, CVE-2024-26583, CVE-2024-26736, CVE-2024-35938,
    CVE-2024-26793, CVE-2024-26891, CVE-2024-35910, CVE-2024-26654, CVE-2024-35940, CVE-2024-26851,
    CVE-2024-35984, CVE-2024-26809, CVE-2024-35819, CVE-2024-35821, CVE-2024-26643, CVE-2024-36029,
    CVE-2024-35888, CVE-2024-27390, CVE-2024-26773, CVE-2024-26733, CVE-2024-26961, CVE-2024-35822,
    CVE-2024-35854, CVE-2024-35950, CVE-2024-35970, CVE-2024-27053, CVE-2024-26907, CVE-2024-26776,
    CVE-2024-26748, CVE-2024-26988, CVE-2024-35935, CVE-2024-26744, CVE-2024-27008, CVE-2024-35905,
    CVE-2024-26974, CVE-2024-26950, CVE-2024-26787, CVE-2024-27077, CVE-2024-35886, CVE-2024-35907,
    CVE-2024-27020, CVE-2024-26764, CVE-2024-26835, CVE-2024-35988, CVE-2024-26687, CVE-2024-35809,
    CVE-2024-35844, CVE-2024-26901, CVE-2024-26848, CVE-2024-26857, CVE-2024-26751, CVE-2024-27074,
    CVE-2024-26885, CVE-2024-26884, CVE-2024-27410, CVE-2024-35871, CVE-2024-26883, CVE-2023-52699,
    CVE-2024-35922, CVE-2024-26895, CVE-2024-26798, CVE-2024-26981, CVE-2024-27013, CVE-2024-27419,
    CVE-2024-26779, CVE-2024-27395, CVE-2024-27015, CVE-2024-35890, CVE-2024-26863, CVE-2024-26922,
    CVE-2024-27417, CVE-2023-52488, CVE-2024-26929, CVE-2024-26960, CVE-2024-26833, CVE-2024-26750,
    CVE-2024-27024, CVE-2024-36007, CVE-2024-27047, CVE-2024-35853, CVE-2024-26973, CVE-2024-27038,
    CVE-2024-35934, CVE-2024-27073, CVE-2024-35849, CVE-2023-52880, CVE-2024-35976)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6919-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52434");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1058-raspi");
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
if (! ('22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '22.04': {
    '5.15.0': {
      'raspi': '5.15.0-1058'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6919-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-38096', 'CVE-2022-48808', 'CVE-2023-6270', 'CVE-2023-7042', 'CVE-2023-52434', 'CVE-2023-52447', 'CVE-2023-52488', 'CVE-2023-52497', 'CVE-2023-52620', 'CVE-2023-52640', 'CVE-2023-52641', 'CVE-2023-52644', 'CVE-2023-52645', 'CVE-2023-52650', 'CVE-2023-52652', 'CVE-2023-52656', 'CVE-2023-52662', 'CVE-2023-52699', 'CVE-2023-52880', 'CVE-2024-0841', 'CVE-2024-21823', 'CVE-2024-22099', 'CVE-2024-23307', 'CVE-2024-24857', 'CVE-2024-24858', 'CVE-2024-24859', 'CVE-2024-24861', 'CVE-2024-25739', 'CVE-2024-26583', 'CVE-2024-26584', 'CVE-2024-26585', 'CVE-2024-26601', 'CVE-2024-26603', 'CVE-2024-26629', 'CVE-2024-26642', 'CVE-2024-26643', 'CVE-2024-26651', 'CVE-2024-26654', 'CVE-2024-26659', 'CVE-2024-26687', 'CVE-2024-26688', 'CVE-2024-26733', 'CVE-2024-26735', 'CVE-2024-26736', 'CVE-2024-26737', 'CVE-2024-26743', 'CVE-2024-26744', 'CVE-2024-26747', 'CVE-2024-26748', 'CVE-2024-26749', 'CVE-2024-26750', 'CVE-2024-26751', 'CVE-2024-26752', 'CVE-2024-26754', 'CVE-2024-26763', 'CVE-2024-26764', 'CVE-2024-26766', 'CVE-2024-26769', 'CVE-2024-26771', 'CVE-2024-26772', 'CVE-2024-26773', 'CVE-2024-26774', 'CVE-2024-26776', 'CVE-2024-26777', 'CVE-2024-26778', 'CVE-2024-26779', 'CVE-2024-26782', 'CVE-2024-26787', 'CVE-2024-26788', 'CVE-2024-26790', 'CVE-2024-26791', 'CVE-2024-26792', 'CVE-2024-26793', 'CVE-2024-26795', 'CVE-2024-26798', 'CVE-2024-26801', 'CVE-2024-26802', 'CVE-2024-26803', 'CVE-2024-26804', 'CVE-2024-26805', 'CVE-2024-26809', 'CVE-2024-26810', 'CVE-2024-26811', 'CVE-2024-26812', 'CVE-2024-26813', 'CVE-2024-26814', 'CVE-2024-26816', 'CVE-2024-26817', 'CVE-2024-26820', 'CVE-2024-26828', 'CVE-2024-26833', 'CVE-2024-26835', 'CVE-2024-26838', 'CVE-2024-26839', 'CVE-2024-26840', 'CVE-2024-26843', 'CVE-2024-26845', 'CVE-2024-26846', 'CVE-2024-26848', 'CVE-2024-26851', 'CVE-2024-26852', 'CVE-2024-26855', 'CVE-2024-26856', 'CVE-2024-26857', 'CVE-2024-26859', 'CVE-2024-26861', 'CVE-2024-26862', 'CVE-2024-26863', 'CVE-2024-26870', 'CVE-2024-26872', 'CVE-2024-26874', 'CVE-2024-26875', 'CVE-2024-26877', 'CVE-2024-26878', 'CVE-2024-26879', 'CVE-2024-26880', 'CVE-2024-26881', 'CVE-2024-26882', 'CVE-2024-26883', 'CVE-2024-26884', 'CVE-2024-26885', 'CVE-2024-26889', 'CVE-2024-26891', 'CVE-2024-26894', 'CVE-2024-26895', 'CVE-2024-26897', 'CVE-2024-26898', 'CVE-2024-26901', 'CVE-2024-26903', 'CVE-2024-26906', 'CVE-2024-26907', 'CVE-2024-26915', 'CVE-2024-26922', 'CVE-2024-26923', 'CVE-2024-26924', 'CVE-2024-26925', 'CVE-2024-26926', 'CVE-2024-26929', 'CVE-2024-26931', 'CVE-2024-26934', 'CVE-2024-26935', 'CVE-2024-26937', 'CVE-2024-26950', 'CVE-2024-26951', 'CVE-2024-26955', 'CVE-2024-26956', 'CVE-2024-26957', 'CVE-2024-26958', 'CVE-2024-26960', 'CVE-2024-26961', 'CVE-2024-26964', 'CVE-2024-26965', 'CVE-2024-26966', 'CVE-2024-26969', 'CVE-2024-26970', 'CVE-2024-26973', 'CVE-2024-26974', 'CVE-2024-26976', 'CVE-2024-26977', 'CVE-2024-26981', 'CVE-2024-26984', 'CVE-2024-26988', 'CVE-2024-26989', 'CVE-2024-26993', 'CVE-2024-26994', 'CVE-2024-26996', 'CVE-2024-26999', 'CVE-2024-27000', 'CVE-2024-27001', 'CVE-2024-27004', 'CVE-2024-27008', 'CVE-2024-27009', 'CVE-2024-27013', 'CVE-2024-27015', 'CVE-2024-27016', 'CVE-2024-27019', 'CVE-2024-27020', 'CVE-2024-27024', 'CVE-2024-27028', 'CVE-2024-27030', 'CVE-2024-27034', 'CVE-2024-27037', 'CVE-2024-27038', 'CVE-2024-27039', 'CVE-2024-27043', 'CVE-2024-27044', 'CVE-2024-27045', 'CVE-2024-27046', 'CVE-2024-27047', 'CVE-2024-27051', 'CVE-2024-27052', 'CVE-2024-27053', 'CVE-2024-27054', 'CVE-2024-27059', 'CVE-2024-27065', 'CVE-2024-27073', 'CVE-2024-27074', 'CVE-2024-27075', 'CVE-2024-27076', 'CVE-2024-27077', 'CVE-2024-27078', 'CVE-2024-27388', 'CVE-2024-27390', 'CVE-2024-27393', 'CVE-2024-27395', 'CVE-2024-27396', 'CVE-2024-27403', 'CVE-2024-27405', 'CVE-2024-27410', 'CVE-2024-27412', 'CVE-2024-27413', 'CVE-2024-27414', 'CVE-2024-27415', 'CVE-2024-27416', 'CVE-2024-27417', 'CVE-2024-27419', 'CVE-2024-27431', 'CVE-2024-27432', 'CVE-2024-27436', 'CVE-2024-27437', 'CVE-2024-35785', 'CVE-2024-35789', 'CVE-2024-35791', 'CVE-2024-35796', 'CVE-2024-35804', 'CVE-2024-35805', 'CVE-2024-35806', 'CVE-2024-35807', 'CVE-2024-35809', 'CVE-2024-35813', 'CVE-2024-35817', 'CVE-2024-35819', 'CVE-2024-35821', 'CVE-2024-35822', 'CVE-2024-35823', 'CVE-2024-35825', 'CVE-2024-35828', 'CVE-2024-35829', 'CVE-2024-35830', 'CVE-2024-35844', 'CVE-2024-35845', 'CVE-2024-35847', 'CVE-2024-35849', 'CVE-2024-35851', 'CVE-2024-35852', 'CVE-2024-35853', 'CVE-2024-35854', 'CVE-2024-35855', 'CVE-2024-35857', 'CVE-2024-35871', 'CVE-2024-35872', 'CVE-2024-35877', 'CVE-2024-35879', 'CVE-2024-35884', 'CVE-2024-35885', 'CVE-2024-35886', 'CVE-2024-35888', 'CVE-2024-35890', 'CVE-2024-35893', 'CVE-2024-35895', 'CVE-2024-35896', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-35899', 'CVE-2024-35900', 'CVE-2024-35905', 'CVE-2024-35907', 'CVE-2024-35910', 'CVE-2024-35912', 'CVE-2024-35915', 'CVE-2024-35918', 'CVE-2024-35922', 'CVE-2024-35925', 'CVE-2024-35930', 'CVE-2024-35933', 'CVE-2024-35934', 'CVE-2024-35935', 'CVE-2024-35936', 'CVE-2024-35938', 'CVE-2024-35940', 'CVE-2024-35944', 'CVE-2024-35950', 'CVE-2024-35955', 'CVE-2024-35958', 'CVE-2024-35960', 'CVE-2024-35969', 'CVE-2024-35970', 'CVE-2024-35973', 'CVE-2024-35976', 'CVE-2024-35978', 'CVE-2024-35982', 'CVE-2024-35984', 'CVE-2024-35988', 'CVE-2024-35989', 'CVE-2024-35990', 'CVE-2024-35997', 'CVE-2024-36004', 'CVE-2024-36005', 'CVE-2024-36006', 'CVE-2024-36007', 'CVE-2024-36008', 'CVE-2024-36020', 'CVE-2024-36025', 'CVE-2024-36029');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6919-1');
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
