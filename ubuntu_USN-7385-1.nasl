#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7385-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233480);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id(
    "CVE-2024-8805",
    "CVE-2024-41016",
    "CVE-2024-47670",
    "CVE-2024-47671",
    "CVE-2024-47672",
    "CVE-2024-47673",
    "CVE-2024-47675",
    "CVE-2024-47677",
    "CVE-2024-47678",
    "CVE-2024-47679",
    "CVE-2024-47681",
    "CVE-2024-47682",
    "CVE-2024-47684",
    "CVE-2024-47685",
    "CVE-2024-47686",
    "CVE-2024-47687",
    "CVE-2024-47688",
    "CVE-2024-47689",
    "CVE-2024-47690",
    "CVE-2024-47691",
    "CVE-2024-47692",
    "CVE-2024-47693",
    "CVE-2024-47695",
    "CVE-2024-47696",
    "CVE-2024-47697",
    "CVE-2024-47698",
    "CVE-2024-47699",
    "CVE-2024-47700",
    "CVE-2024-47701",
    "CVE-2024-47702",
    "CVE-2024-47703",
    "CVE-2024-47704",
    "CVE-2024-47705",
    "CVE-2024-47706",
    "CVE-2024-47707",
    "CVE-2024-47709",
    "CVE-2024-47710",
    "CVE-2024-47711",
    "CVE-2024-47712",
    "CVE-2024-47713",
    "CVE-2024-47714",
    "CVE-2024-47715",
    "CVE-2024-47716",
    "CVE-2024-47718",
    "CVE-2024-47719",
    "CVE-2024-47720",
    "CVE-2024-47723",
    "CVE-2024-47726",
    "CVE-2024-47727",
    "CVE-2024-47728",
    "CVE-2024-47730",
    "CVE-2024-47731",
    "CVE-2024-47732",
    "CVE-2024-47733",
    "CVE-2024-47734",
    "CVE-2024-47735",
    "CVE-2024-47737",
    "CVE-2024-47738",
    "CVE-2024-47739",
    "CVE-2024-47740",
    "CVE-2024-47741",
    "CVE-2024-47742",
    "CVE-2024-47743",
    "CVE-2024-47744",
    "CVE-2024-47745",
    "CVE-2024-47747",
    "CVE-2024-47748",
    "CVE-2024-47749",
    "CVE-2024-47750",
    "CVE-2024-47751",
    "CVE-2024-47752",
    "CVE-2024-47753",
    "CVE-2024-47754",
    "CVE-2024-47756",
    "CVE-2024-47757",
    "CVE-2024-49850",
    "CVE-2024-49851",
    "CVE-2024-49852",
    "CVE-2024-49853",
    "CVE-2024-49855",
    "CVE-2024-49856",
    "CVE-2024-49858",
    "CVE-2024-49859",
    "CVE-2024-49860",
    "CVE-2024-49861",
    "CVE-2024-49862",
    "CVE-2024-49863",
    "CVE-2024-49864",
    "CVE-2024-49865",
    "CVE-2024-49866",
    "CVE-2024-49867",
    "CVE-2024-49868",
    "CVE-2024-49870",
    "CVE-2024-49871",
    "CVE-2024-49874",
    "CVE-2024-49875",
    "CVE-2024-49876",
    "CVE-2024-49877",
    "CVE-2024-49878",
    "CVE-2024-49879",
    "CVE-2024-49880",
    "CVE-2024-49881",
    "CVE-2024-49882",
    "CVE-2024-49883",
    "CVE-2024-49884",
    "CVE-2024-49885",
    "CVE-2024-49886",
    "CVE-2024-49888",
    "CVE-2024-49889",
    "CVE-2024-49890",
    "CVE-2024-49891",
    "CVE-2024-49892",
    "CVE-2024-49893",
    "CVE-2024-49894",
    "CVE-2024-49895",
    "CVE-2024-49896",
    "CVE-2024-49897",
    "CVE-2024-49898",
    "CVE-2024-49900",
    "CVE-2024-49901",
    "CVE-2024-49902",
    "CVE-2024-49903",
    "CVE-2024-49905",
    "CVE-2024-49907",
    "CVE-2024-49909",
    "CVE-2024-49911",
    "CVE-2024-49912",
    "CVE-2024-49913",
    "CVE-2024-49914",
    "CVE-2024-49915",
    "CVE-2024-49917",
    "CVE-2024-49918",
    "CVE-2024-49919",
    "CVE-2024-49920",
    "CVE-2024-49921",
    "CVE-2024-49922",
    "CVE-2024-49923",
    "CVE-2024-49924",
    "CVE-2024-49925",
    "CVE-2024-49926",
    "CVE-2024-49927",
    "CVE-2024-49928",
    "CVE-2024-49929",
    "CVE-2024-49930",
    "CVE-2024-49931",
    "CVE-2024-49933",
    "CVE-2024-49934",
    "CVE-2024-49935",
    "CVE-2024-49936",
    "CVE-2024-49937",
    "CVE-2024-49938",
    "CVE-2024-49939",
    "CVE-2024-49942",
    "CVE-2024-49944",
    "CVE-2024-49945",
    "CVE-2024-49946",
    "CVE-2024-49947",
    "CVE-2024-49948",
    "CVE-2024-49949",
    "CVE-2024-49950",
    "CVE-2024-49951",
    "CVE-2024-49952",
    "CVE-2024-49953",
    "CVE-2024-49954",
    "CVE-2024-49955",
    "CVE-2024-49957",
    "CVE-2024-49958",
    "CVE-2024-49959",
    "CVE-2024-49960",
    "CVE-2024-49961",
    "CVE-2024-49962",
    "CVE-2024-49963",
    "CVE-2024-49965",
    "CVE-2024-49966",
    "CVE-2024-49968",
    "CVE-2024-49969",
    "CVE-2024-49972",
    "CVE-2024-49973",
    "CVE-2024-49974",
    "CVE-2024-49975",
    "CVE-2024-49976",
    "CVE-2024-49977",
    "CVE-2024-49978",
    "CVE-2024-49980",
    "CVE-2024-49981",
    "CVE-2024-49982",
    "CVE-2024-49983",
    "CVE-2024-49985",
    "CVE-2024-49986",
    "CVE-2024-49987",
    "CVE-2024-49988",
    "CVE-2024-49989",
    "CVE-2024-49991",
    "CVE-2024-49992",
    "CVE-2024-49994",
    "CVE-2024-49995",
    "CVE-2024-49996",
    "CVE-2024-49997",
    "CVE-2024-49998",
    "CVE-2024-49999",
    "CVE-2024-50000",
    "CVE-2024-50001",
    "CVE-2024-50002",
    "CVE-2024-50005",
    "CVE-2024-50006",
    "CVE-2024-50007",
    "CVE-2024-50008",
    "CVE-2024-50009",
    "CVE-2024-50012",
    "CVE-2024-50013",
    "CVE-2024-50014",
    "CVE-2024-50015",
    "CVE-2024-50016",
    "CVE-2024-50017",
    "CVE-2024-50019",
    "CVE-2024-50020",
    "CVE-2024-50021",
    "CVE-2024-50022",
    "CVE-2024-50023",
    "CVE-2024-50024",
    "CVE-2024-50025",
    "CVE-2024-50026",
    "CVE-2024-50027",
    "CVE-2024-50028",
    "CVE-2024-50029",
    "CVE-2024-50030",
    "CVE-2024-50031",
    "CVE-2024-50033",
    "CVE-2024-50035",
    "CVE-2024-50036",
    "CVE-2024-50038",
    "CVE-2024-50039",
    "CVE-2024-50040",
    "CVE-2024-50041",
    "CVE-2024-50042",
    "CVE-2024-50044",
    "CVE-2024-50045",
    "CVE-2024-50046",
    "CVE-2024-50047",
    "CVE-2024-50048",
    "CVE-2024-50049",
    "CVE-2024-50055",
    "CVE-2024-50056",
    "CVE-2024-50057",
    "CVE-2024-50058",
    "CVE-2024-50059",
    "CVE-2024-50060",
    "CVE-2024-50061",
    "CVE-2024-50062",
    "CVE-2024-50063",
    "CVE-2024-50064",
    "CVE-2024-50065",
    "CVE-2024-50066",
    "CVE-2024-50068",
    "CVE-2024-50069",
    "CVE-2024-50070",
    "CVE-2024-50072",
    "CVE-2024-50073",
    "CVE-2024-50074",
    "CVE-2024-50075",
    "CVE-2024-50076",
    "CVE-2024-50077",
    "CVE-2024-50078",
    "CVE-2024-50080",
    "CVE-2024-50082",
    "CVE-2024-50083",
    "CVE-2024-50084",
    "CVE-2024-50085",
    "CVE-2024-50086",
    "CVE-2024-50087",
    "CVE-2024-50088",
    "CVE-2024-50090",
    "CVE-2024-50093",
    "CVE-2024-50095",
    "CVE-2024-50096",
    "CVE-2024-50098",
    "CVE-2024-50099",
    "CVE-2024-50101",
    "CVE-2024-50117",
    "CVE-2024-50134",
    "CVE-2024-50148",
    "CVE-2024-50171",
    "CVE-2024-50175",
    "CVE-2024-50176",
    "CVE-2024-50179",
    "CVE-2024-50180",
    "CVE-2024-50182",
    "CVE-2024-50183",
    "CVE-2024-50184",
    "CVE-2024-50185",
    "CVE-2024-50186",
    "CVE-2024-50187",
    "CVE-2024-50188",
    "CVE-2024-50189",
    "CVE-2024-50191",
    "CVE-2024-50192",
    "CVE-2024-50193",
    "CVE-2024-50194",
    "CVE-2024-50195",
    "CVE-2024-50196",
    "CVE-2024-50197",
    "CVE-2024-50198",
    "CVE-2024-50199",
    "CVE-2024-50200",
    "CVE-2024-50201",
    "CVE-2024-50202",
    "CVE-2024-50229",
    "CVE-2024-50233",
    "CVE-2024-53104",
    "CVE-2024-53144",
    "CVE-2024-53156",
    "CVE-2024-53165",
    "CVE-2024-53170",
    "CVE-2024-56582",
    "CVE-2024-56614",
    "CVE-2024-56663",
    "CVE-2025-0927"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/26");
  script_xref(name:"USN", value:"7385-1");

  script_name(english:"Ubuntu 24.04 LTS : Linux kernel (IBM) vulnerabilities (USN-7385-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 24.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-7385-1 advisory.

    Michael Randrianantenaina discovered that the Bluetooth driver in the Linux Kernel contained an improper
    access control vulnerability. A nearby attacker could use this to connect a rougue device and possibly
    execute arbitrary code. (CVE-2024-8805)

    Attila Szsz discovered that the HFS+ file system implementation in the Linux Kernel contained a heap
    overflow vulnerability. An attacker could use a specially crafted file system image that, when mounted,
    could cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2025-0927)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM32 architecture;

    - ARM64 architecture;

    - x86 architecture;

    - Block layer subsystem;

    - Cryptographic API;

    - ACPI drivers;

    - Drivers core;

    - ATA over ethernet (AOE) driver;

    - Network block device driver;

    - Ublk userspace block driver;

    - Compressed RAM block device driver;

    - TPM device driver;

    - CPU frequency scaling framework;

    - Hardware crypto device drivers;

    - DAX dirext access to differentiated memory framework;

    - ARM SCMI message protocol;

    - EFI core;

    - GPU drivers;

    - HID subsystem;

    - I2C subsystem;

    - I3C subsystem;

    - IIO subsystem;

    - InfiniBand drivers;

    - Input Device core drivers;

    - IOMMU subsystem;

    - IRQ chip drivers;

    - Mailbox framework;

    - Media drivers;

    - Ethernet bonding driver;

    - Network drivers;

    - Mellanox network drivers;

    - STMicroelectronics network drivers;

    - NTB driver;

    - Virtio pmem driver;

    - Parport drivers;

    - PCI subsystem;

    - Alibaba DDR Sub-System Driveway PMU driver;

    - Pin controllers subsystem;

    - x86 platform drivers;

    - Powercap sysfs driver;

    - Remote Processor subsystem;

    - SCSI subsystem;

    - SuperH / SH-Mobile drivers;

    - Direct Digital Synthesis drivers;

    - Thermal drivers;

    - TTY drivers;

    - UFS subsystem;

    - USB Device Class drivers;

    - USB Gadget drivers;

    - USB Host Controller drivers;

    - TI TPS6598x USB Power Delivery controller driver;

    - vDPA drivers;

    - Virtio Host (VHOST) subsystem;

    - Framebuffer layer;

    - AFS file system;

    - BTRFS file system;

    - File systems infrastructure;

    - Ceph distributed file system;

    - Ext4 file system;

    - F2FS file system;

    - JFS file system;

    - Network file systems library;

    - Network file system (NFS) client;

    - Network file system (NFS) server daemon;

    - NILFS2 file system;

    - NTFS3 file system;

    - SMB network file system;

    - BPF subsystem;

    - Network file system (NFS) superblock;

    - Virtio network driver;

    - Network traffic control;

    - Network sockets;

    - TCP network protocol;

    - User-space API (UAPI);

    - io_uring subsystem;

    - Perf events;

    - Kernel thread helper (kthread);

    - Padata parallel execution mechanism;

    - RCU subsystem;

    - Arbitrary resource management;

    - Static call mechanism;

    - Timer subsystem;

    - Tracing infrastructure;

    - Maple Tree data structure library;

    - Memory management;

    - Bluetooth subsystem;

    - Ethernet bridge;

    - CAN network layer;

    - Networking core;

    - Distributed Switch Architecture;

    - IPv4 networking;

    - IPv6 networking;

    - MAC80211 subsystem;

    - IEEE 802.15.4 subsystem;

    - Multipath TCP;

    - NCSI (Network Controller Sideband Interface) driver;

    - Netfilter;

    - Netlink;

    - RxRPC session sockets;

    - SCTP protocol;

    - TIPC protocol;

    - Unix domain sockets;

    - Wireless networking;

    - eXpress Data Path;

    - AudioScience HPI driver;

    - KVM core; (CVE-2024-49927, CVE-2024-47719, CVE-2024-49878, CVE-2024-50200, CVE-2024-50013,
    CVE-2024-50187, CVE-2024-49852, CVE-2024-49913, CVE-2024-50080, CVE-2024-49903, CVE-2024-47745,
    CVE-2024-50184, CVE-2024-50117, CVE-2024-49863, CVE-2024-49973, CVE-2024-47727, CVE-2024-53170,
    CVE-2024-49933, CVE-2024-49900, CVE-2024-50095, CVE-2024-49928, CVE-2024-49858, CVE-2024-47731,
    CVE-2024-49896, CVE-2024-53104, CVE-2024-49972, CVE-2024-49969, CVE-2024-50176, CVE-2024-47739,
    CVE-2024-49995, CVE-2024-49982, CVE-2024-50044, CVE-2024-49957, CVE-2024-47748, CVE-2024-47744,
    CVE-2024-49978, CVE-2024-49879, CVE-2024-49987, CVE-2024-49929, CVE-2024-49905, CVE-2024-47723,
    CVE-2024-53144, CVE-2024-50066, CVE-2024-47735, CVE-2024-50057, CVE-2024-49890, CVE-2024-49963,
    CVE-2024-49955, CVE-2024-49974, CVE-2024-50049, CVE-2024-47710, CVE-2024-47682, CVE-2024-47734,
    CVE-2024-47691, CVE-2024-49999, CVE-2024-50098, CVE-2024-47672, CVE-2024-50056, CVE-2024-49983,
    CVE-2024-50005, CVE-2024-50045, CVE-2024-49866, CVE-2024-49953, CVE-2024-47750, CVE-2024-49917,
    CVE-2024-50026, CVE-2024-50009, CVE-2024-47718, CVE-2024-50070, CVE-2024-47700, CVE-2024-49986,
    CVE-2024-49907, CVE-2024-49884, CVE-2024-50085, CVE-2024-50087, CVE-2024-49875, CVE-2024-47728,
    CVE-2024-49861, CVE-2024-49851, CVE-2024-49980, CVE-2024-49898, CVE-2024-47681, CVE-2024-49965,
    CVE-2024-49960, CVE-2024-50020, CVE-2024-50012, CVE-2024-50186, CVE-2024-49889, CVE-2024-50030,
    CVE-2024-50046, CVE-2024-50180, CVE-2024-49966, CVE-2024-49897, CVE-2024-49985, CVE-2024-49918,
    CVE-2024-47754, CVE-2024-50082, CVE-2024-47757, CVE-2024-47711, CVE-2024-47737, CVE-2024-47716,
    CVE-2024-50069, CVE-2024-47696, CVE-2024-50031, CVE-2024-50202, CVE-2024-47713, CVE-2024-49894,
    CVE-2024-49921, CVE-2024-50022, CVE-2024-49856, CVE-2024-47740, CVE-2024-49868, CVE-2024-49919,
    CVE-2024-47679, CVE-2024-47695, CVE-2024-47714, CVE-2024-49996, CVE-2024-50196, CVE-2024-49997,
    CVE-2024-49883, CVE-2024-49936, CVE-2024-49962, CVE-2024-47673, CVE-2024-56663, CVE-2024-49892,
    CVE-2024-47685, CVE-2024-50233, CVE-2024-49891, CVE-2024-47738, CVE-2024-49870, CVE-2024-49885,
    CVE-2024-50025, CVE-2024-50006, CVE-2024-49968, CVE-2024-47709, CVE-2024-47751, CVE-2024-50058,
    CVE-2024-50086, CVE-2024-50072, CVE-2024-50195, CVE-2024-56582, CVE-2024-50014, CVE-2024-49886,
    CVE-2024-47743, CVE-2024-50185, CVE-2024-50193, CVE-2024-49909, CVE-2024-50077, CVE-2024-49930,
    CVE-2024-49946, CVE-2024-50192, CVE-2024-50041, CVE-2024-47698, CVE-2024-50188, CVE-2024-49977,
    CVE-2024-47687, CVE-2024-49945, CVE-2024-50008, CVE-2024-49859, CVE-2024-50062, CVE-2024-49880,
    CVE-2024-47671, CVE-2024-49867, CVE-2024-49912, CVE-2024-56614, CVE-2024-49862, CVE-2024-50021,
    CVE-2024-47670, CVE-2024-49911, CVE-2024-49855, CVE-2024-47712, CVE-2024-50229, CVE-2024-50096,
    CVE-2024-49895, CVE-2024-47677, CVE-2024-49934, CVE-2024-53156, CVE-2024-49893, CVE-2024-49925,
    CVE-2024-50063, CVE-2024-49926, CVE-2024-50201, CVE-2024-50033, CVE-2024-50199, CVE-2024-49874,
    CVE-2024-47732, CVE-2024-50078, CVE-2024-49935, CVE-2024-49902, CVE-2024-49989, CVE-2024-47675,
    CVE-2024-50064, CVE-2024-50015, CVE-2024-41016, CVE-2024-49949, CVE-2024-50090, CVE-2024-49860,
    CVE-2024-50036, CVE-2024-50084, CVE-2024-50182, CVE-2024-50061, CVE-2024-47702, CVE-2024-47730,
    CVE-2024-49951, CVE-2024-49938, CVE-2024-50088, CVE-2024-50198, CVE-2024-49998, CVE-2024-49931,
    CVE-2024-49944, CVE-2024-50000, CVE-2024-49954, CVE-2024-47753, CVE-2024-49976, CVE-2024-50048,
    CVE-2024-49881, CVE-2024-50093, CVE-2024-50019, CVE-2024-50059, CVE-2024-50016, CVE-2024-50068,
    CVE-2024-49920, CVE-2024-50035, CVE-2024-50197, CVE-2024-47699, CVE-2024-49914, CVE-2024-50191,
    CVE-2024-50083, CVE-2024-47701, CVE-2024-49877, CVE-2024-50017, CVE-2024-49915, CVE-2024-50001,
    CVE-2024-49864, CVE-2024-50189, CVE-2024-50101, CVE-2024-47704, CVE-2024-50024, CVE-2024-50038,
    CVE-2024-49850, CVE-2024-50027, CVE-2024-49952, CVE-2024-50074, CVE-2024-50171, CVE-2024-53165,
    CVE-2024-47689, CVE-2024-49865, CVE-2024-49853, CVE-2024-47742, CVE-2024-49994, CVE-2024-50179,
    CVE-2024-47686, CVE-2024-49975, CVE-2024-49948, CVE-2024-50099, CVE-2024-50175, CVE-2024-50028,
    CVE-2024-49947, CVE-2024-47741, CVE-2024-49888, CVE-2024-50055, CVE-2024-47749, CVE-2024-49992,
    CVE-2024-47715, CVE-2024-49922, CVE-2024-47756, CVE-2024-50023, CVE-2024-47720, CVE-2024-50194,
    CVE-2024-47688, CVE-2024-49991, CVE-2024-47705, CVE-2024-49942, CVE-2024-50047, CVE-2024-49981,
    CVE-2024-49950, CVE-2024-47684, CVE-2024-50065, CVE-2024-49939, CVE-2024-47726, CVE-2024-47697,
    CVE-2024-49959, CVE-2024-47690, CVE-2024-50040, CVE-2024-50002, CVE-2024-50029, CVE-2024-47752,
    CVE-2024-49924, CVE-2024-50073, CVE-2024-47733, CVE-2024-50075, CVE-2024-49937, CVE-2024-47707,
    CVE-2024-47692, CVE-2024-47703, CVE-2024-49988, CVE-2024-50060, CVE-2024-50039, CVE-2024-49961,
    CVE-2024-50042, CVE-2024-50148, CVE-2024-47678, CVE-2024-49923, CVE-2024-49901, CVE-2024-47706,
    CVE-2024-49882, CVE-2024-47693, CVE-2024-49876, CVE-2024-47747, CVE-2024-49871, CVE-2024-50076,
    CVE-2024-50183, CVE-2024-50007, CVE-2024-49958, CVE-2024-50134)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7385-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1022-ibm");
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
if (! ('24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '24.04': {
    '6.8.0': {
      'ibm': '6.8.0-1022'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7385-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2024-8805', 'CVE-2024-41016', 'CVE-2024-47670', 'CVE-2024-47671', 'CVE-2024-47672', 'CVE-2024-47673', 'CVE-2024-47675', 'CVE-2024-47677', 'CVE-2024-47678', 'CVE-2024-47679', 'CVE-2024-47681', 'CVE-2024-47682', 'CVE-2024-47684', 'CVE-2024-47685', 'CVE-2024-47686', 'CVE-2024-47687', 'CVE-2024-47688', 'CVE-2024-47689', 'CVE-2024-47690', 'CVE-2024-47691', 'CVE-2024-47692', 'CVE-2024-47693', 'CVE-2024-47695', 'CVE-2024-47696', 'CVE-2024-47697', 'CVE-2024-47698', 'CVE-2024-47699', 'CVE-2024-47700', 'CVE-2024-47701', 'CVE-2024-47702', 'CVE-2024-47703', 'CVE-2024-47704', 'CVE-2024-47705', 'CVE-2024-47706', 'CVE-2024-47707', 'CVE-2024-47709', 'CVE-2024-47710', 'CVE-2024-47711', 'CVE-2024-47712', 'CVE-2024-47713', 'CVE-2024-47714', 'CVE-2024-47715', 'CVE-2024-47716', 'CVE-2024-47718', 'CVE-2024-47719', 'CVE-2024-47720', 'CVE-2024-47723', 'CVE-2024-47726', 'CVE-2024-47727', 'CVE-2024-47728', 'CVE-2024-47730', 'CVE-2024-47731', 'CVE-2024-47732', 'CVE-2024-47733', 'CVE-2024-47734', 'CVE-2024-47735', 'CVE-2024-47737', 'CVE-2024-47738', 'CVE-2024-47739', 'CVE-2024-47740', 'CVE-2024-47741', 'CVE-2024-47742', 'CVE-2024-47743', 'CVE-2024-47744', 'CVE-2024-47745', 'CVE-2024-47747', 'CVE-2024-47748', 'CVE-2024-47749', 'CVE-2024-47750', 'CVE-2024-47751', 'CVE-2024-47752', 'CVE-2024-47753', 'CVE-2024-47754', 'CVE-2024-47756', 'CVE-2024-47757', 'CVE-2024-49850', 'CVE-2024-49851', 'CVE-2024-49852', 'CVE-2024-49853', 'CVE-2024-49855', 'CVE-2024-49856', 'CVE-2024-49858', 'CVE-2024-49859', 'CVE-2024-49860', 'CVE-2024-49861', 'CVE-2024-49862', 'CVE-2024-49863', 'CVE-2024-49864', 'CVE-2024-49865', 'CVE-2024-49866', 'CVE-2024-49867', 'CVE-2024-49868', 'CVE-2024-49870', 'CVE-2024-49871', 'CVE-2024-49874', 'CVE-2024-49875', 'CVE-2024-49876', 'CVE-2024-49877', 'CVE-2024-49878', 'CVE-2024-49879', 'CVE-2024-49880', 'CVE-2024-49881', 'CVE-2024-49882', 'CVE-2024-49883', 'CVE-2024-49884', 'CVE-2024-49885', 'CVE-2024-49886', 'CVE-2024-49888', 'CVE-2024-49889', 'CVE-2024-49890', 'CVE-2024-49891', 'CVE-2024-49892', 'CVE-2024-49893', 'CVE-2024-49894', 'CVE-2024-49895', 'CVE-2024-49896', 'CVE-2024-49897', 'CVE-2024-49898', 'CVE-2024-49900', 'CVE-2024-49901', 'CVE-2024-49902', 'CVE-2024-49903', 'CVE-2024-49905', 'CVE-2024-49907', 'CVE-2024-49909', 'CVE-2024-49911', 'CVE-2024-49912', 'CVE-2024-49913', 'CVE-2024-49914', 'CVE-2024-49915', 'CVE-2024-49917', 'CVE-2024-49918', 'CVE-2024-49919', 'CVE-2024-49920', 'CVE-2024-49921', 'CVE-2024-49922', 'CVE-2024-49923', 'CVE-2024-49924', 'CVE-2024-49925', 'CVE-2024-49926', 'CVE-2024-49927', 'CVE-2024-49928', 'CVE-2024-49929', 'CVE-2024-49930', 'CVE-2024-49931', 'CVE-2024-49933', 'CVE-2024-49934', 'CVE-2024-49935', 'CVE-2024-49936', 'CVE-2024-49937', 'CVE-2024-49938', 'CVE-2024-49939', 'CVE-2024-49942', 'CVE-2024-49944', 'CVE-2024-49945', 'CVE-2024-49946', 'CVE-2024-49947', 'CVE-2024-49948', 'CVE-2024-49949', 'CVE-2024-49950', 'CVE-2024-49951', 'CVE-2024-49952', 'CVE-2024-49953', 'CVE-2024-49954', 'CVE-2024-49955', 'CVE-2024-49957', 'CVE-2024-49958', 'CVE-2024-49959', 'CVE-2024-49960', 'CVE-2024-49961', 'CVE-2024-49962', 'CVE-2024-49963', 'CVE-2024-49965', 'CVE-2024-49966', 'CVE-2024-49968', 'CVE-2024-49969', 'CVE-2024-49972', 'CVE-2024-49973', 'CVE-2024-49974', 'CVE-2024-49975', 'CVE-2024-49976', 'CVE-2024-49977', 'CVE-2024-49978', 'CVE-2024-49980', 'CVE-2024-49981', 'CVE-2024-49982', 'CVE-2024-49983', 'CVE-2024-49985', 'CVE-2024-49986', 'CVE-2024-49987', 'CVE-2024-49988', 'CVE-2024-49989', 'CVE-2024-49991', 'CVE-2024-49992', 'CVE-2024-49994', 'CVE-2024-49995', 'CVE-2024-49996', 'CVE-2024-49997', 'CVE-2024-49998', 'CVE-2024-49999', 'CVE-2024-50000', 'CVE-2024-50001', 'CVE-2024-50002', 'CVE-2024-50005', 'CVE-2024-50006', 'CVE-2024-50007', 'CVE-2024-50008', 'CVE-2024-50009', 'CVE-2024-50012', 'CVE-2024-50013', 'CVE-2024-50014', 'CVE-2024-50015', 'CVE-2024-50016', 'CVE-2024-50017', 'CVE-2024-50019', 'CVE-2024-50020', 'CVE-2024-50021', 'CVE-2024-50022', 'CVE-2024-50023', 'CVE-2024-50024', 'CVE-2024-50025', 'CVE-2024-50026', 'CVE-2024-50027', 'CVE-2024-50028', 'CVE-2024-50029', 'CVE-2024-50030', 'CVE-2024-50031', 'CVE-2024-50033', 'CVE-2024-50035', 'CVE-2024-50036', 'CVE-2024-50038', 'CVE-2024-50039', 'CVE-2024-50040', 'CVE-2024-50041', 'CVE-2024-50042', 'CVE-2024-50044', 'CVE-2024-50045', 'CVE-2024-50046', 'CVE-2024-50047', 'CVE-2024-50048', 'CVE-2024-50049', 'CVE-2024-50055', 'CVE-2024-50056', 'CVE-2024-50057', 'CVE-2024-50058', 'CVE-2024-50059', 'CVE-2024-50060', 'CVE-2024-50061', 'CVE-2024-50062', 'CVE-2024-50063', 'CVE-2024-50064', 'CVE-2024-50065', 'CVE-2024-50066', 'CVE-2024-50068', 'CVE-2024-50069', 'CVE-2024-50070', 'CVE-2024-50072', 'CVE-2024-50073', 'CVE-2024-50074', 'CVE-2024-50075', 'CVE-2024-50076', 'CVE-2024-50077', 'CVE-2024-50078', 'CVE-2024-50080', 'CVE-2024-50082', 'CVE-2024-50083', 'CVE-2024-50084', 'CVE-2024-50085', 'CVE-2024-50086', 'CVE-2024-50087', 'CVE-2024-50088', 'CVE-2024-50090', 'CVE-2024-50093', 'CVE-2024-50095', 'CVE-2024-50096', 'CVE-2024-50098', 'CVE-2024-50099', 'CVE-2024-50101', 'CVE-2024-50117', 'CVE-2024-50134', 'CVE-2024-50148', 'CVE-2024-50171', 'CVE-2024-50175', 'CVE-2024-50176', 'CVE-2024-50179', 'CVE-2024-50180', 'CVE-2024-50182', 'CVE-2024-50183', 'CVE-2024-50184', 'CVE-2024-50185', 'CVE-2024-50186', 'CVE-2024-50187', 'CVE-2024-50188', 'CVE-2024-50189', 'CVE-2024-50191', 'CVE-2024-50192', 'CVE-2024-50193', 'CVE-2024-50194', 'CVE-2024-50195', 'CVE-2024-50196', 'CVE-2024-50197', 'CVE-2024-50198', 'CVE-2024-50199', 'CVE-2024-50200', 'CVE-2024-50201', 'CVE-2024-50202', 'CVE-2024-50229', 'CVE-2024-50233', 'CVE-2024-53104', 'CVE-2024-53144', 'CVE-2024-53156', 'CVE-2024-53165', 'CVE-2024-53170', 'CVE-2024-56582', 'CVE-2024-56614', 'CVE-2024-56663', 'CVE-2025-0927');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7385-1');
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
