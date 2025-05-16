#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7393-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233668);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id(
    "CVE-2021-47219",
    "CVE-2022-49034",
    "CVE-2023-52458",
    "CVE-2024-23848",
    "CVE-2024-35887",
    "CVE-2024-35896",
    "CVE-2024-38544",
    "CVE-2024-38588",
    "CVE-2024-40911",
    "CVE-2024-40953",
    "CVE-2024-40965",
    "CVE-2024-41016",
    "CVE-2024-41066",
    "CVE-2024-42252",
    "CVE-2024-43098",
    "CVE-2024-43863",
    "CVE-2024-43900",
    "CVE-2024-44931",
    "CVE-2024-44938",
    "CVE-2024-46731",
    "CVE-2024-46849",
    "CVE-2024-46853",
    "CVE-2024-46854",
    "CVE-2024-47670",
    "CVE-2024-47671",
    "CVE-2024-47672",
    "CVE-2024-47674",
    "CVE-2024-47679",
    "CVE-2024-47684",
    "CVE-2024-47685",
    "CVE-2024-47692",
    "CVE-2024-47696",
    "CVE-2024-47697",
    "CVE-2024-47698",
    "CVE-2024-47699",
    "CVE-2024-47701",
    "CVE-2024-47706",
    "CVE-2024-47707",
    "CVE-2024-47709",
    "CVE-2024-47710",
    "CVE-2024-47712",
    "CVE-2024-47713",
    "CVE-2024-47723",
    "CVE-2024-47737",
    "CVE-2024-47740",
    "CVE-2024-47742",
    "CVE-2024-47747",
    "CVE-2024-47749",
    "CVE-2024-47756",
    "CVE-2024-47757",
    "CVE-2024-48881",
    "CVE-2024-49851",
    "CVE-2024-49860",
    "CVE-2024-49867",
    "CVE-2024-49868",
    "CVE-2024-49877",
    "CVE-2024-49878",
    "CVE-2024-49879",
    "CVE-2024-49882",
    "CVE-2024-49883",
    "CVE-2024-49884",
    "CVE-2024-49892",
    "CVE-2024-49894",
    "CVE-2024-49896",
    "CVE-2024-49900",
    "CVE-2024-49902",
    "CVE-2024-49903",
    "CVE-2024-49924",
    "CVE-2024-49925",
    "CVE-2024-49936",
    "CVE-2024-49938",
    "CVE-2024-49944",
    "CVE-2024-49948",
    "CVE-2024-49949",
    "CVE-2024-49952",
    "CVE-2024-49955",
    "CVE-2024-49957",
    "CVE-2024-49958",
    "CVE-2024-49959",
    "CVE-2024-49962",
    "CVE-2024-49963",
    "CVE-2024-49965",
    "CVE-2024-49966",
    "CVE-2024-49973",
    "CVE-2024-49975",
    "CVE-2024-49981",
    "CVE-2024-49982",
    "CVE-2024-49985",
    "CVE-2024-49995",
    "CVE-2024-49996",
    "CVE-2024-49997",
    "CVE-2024-50006",
    "CVE-2024-50007",
    "CVE-2024-50008",
    "CVE-2024-50024",
    "CVE-2024-50033",
    "CVE-2024-50035",
    "CVE-2024-50039",
    "CVE-2024-50040",
    "CVE-2024-50044",
    "CVE-2024-50045",
    "CVE-2024-50051",
    "CVE-2024-50059",
    "CVE-2024-50074",
    "CVE-2024-50082",
    "CVE-2024-50096",
    "CVE-2024-50099",
    "CVE-2024-50116",
    "CVE-2024-50117",
    "CVE-2024-50127",
    "CVE-2024-50131",
    "CVE-2024-50134",
    "CVE-2024-50142",
    "CVE-2024-50143",
    "CVE-2024-50148",
    "CVE-2024-50150",
    "CVE-2024-50151",
    "CVE-2024-50167",
    "CVE-2024-50168",
    "CVE-2024-50171",
    "CVE-2024-50179",
    "CVE-2024-50180",
    "CVE-2024-50184",
    "CVE-2024-50194",
    "CVE-2024-50195",
    "CVE-2024-50199",
    "CVE-2024-50202",
    "CVE-2024-50205",
    "CVE-2024-50218",
    "CVE-2024-50229",
    "CVE-2024-50230",
    "CVE-2024-50233",
    "CVE-2024-50234",
    "CVE-2024-50236",
    "CVE-2024-50237",
    "CVE-2024-50251",
    "CVE-2024-50262",
    "CVE-2024-50265",
    "CVE-2024-50267",
    "CVE-2024-50269",
    "CVE-2024-50273",
    "CVE-2024-50278",
    "CVE-2024-50279",
    "CVE-2024-50282",
    "CVE-2024-50287",
    "CVE-2024-50290",
    "CVE-2024-50296",
    "CVE-2024-50299",
    "CVE-2024-50301",
    "CVE-2024-50302",
    "CVE-2024-52332",
    "CVE-2024-53059",
    "CVE-2024-53061",
    "CVE-2024-53063",
    "CVE-2024-53066",
    "CVE-2024-53101",
    "CVE-2024-53104",
    "CVE-2024-53112",
    "CVE-2024-53121",
    "CVE-2024-53124",
    "CVE-2024-53127",
    "CVE-2024-53130",
    "CVE-2024-53131",
    "CVE-2024-53135",
    "CVE-2024-53138",
    "CVE-2024-53140",
    "CVE-2024-53142",
    "CVE-2024-53145",
    "CVE-2024-53146",
    "CVE-2024-53148",
    "CVE-2024-53150",
    "CVE-2024-53155",
    "CVE-2024-53156",
    "CVE-2024-53157",
    "CVE-2024-53158",
    "CVE-2024-53161",
    "CVE-2024-53165",
    "CVE-2024-53171",
    "CVE-2024-53172",
    "CVE-2024-53173",
    "CVE-2024-53174",
    "CVE-2024-53181",
    "CVE-2024-53183",
    "CVE-2024-53184",
    "CVE-2024-53194",
    "CVE-2024-53197",
    "CVE-2024-53198",
    "CVE-2024-53214",
    "CVE-2024-53217",
    "CVE-2024-53227",
    "CVE-2024-53239",
    "CVE-2024-53680",
    "CVE-2024-53690",
    "CVE-2024-55916",
    "CVE-2024-56531",
    "CVE-2024-56532",
    "CVE-2024-56539",
    "CVE-2024-56548",
    "CVE-2024-56558",
    "CVE-2024-56562",
    "CVE-2024-56567",
    "CVE-2024-56569",
    "CVE-2024-56570",
    "CVE-2024-56572",
    "CVE-2024-56574",
    "CVE-2024-56576",
    "CVE-2024-56581",
    "CVE-2024-56586",
    "CVE-2024-56587",
    "CVE-2024-56593",
    "CVE-2024-56594",
    "CVE-2024-56595",
    "CVE-2024-56596",
    "CVE-2024-56597",
    "CVE-2024-56598",
    "CVE-2024-56600",
    "CVE-2024-56601",
    "CVE-2024-56602",
    "CVE-2024-56603",
    "CVE-2024-56605",
    "CVE-2024-56606",
    "CVE-2024-56614",
    "CVE-2024-56615",
    "CVE-2024-56619",
    "CVE-2024-56629",
    "CVE-2024-56630",
    "CVE-2024-56631",
    "CVE-2024-56633",
    "CVE-2024-56634",
    "CVE-2024-56637",
    "CVE-2024-56642",
    "CVE-2024-56643",
    "CVE-2024-56644",
    "CVE-2024-56645",
    "CVE-2024-56650",
    "CVE-2024-56659",
    "CVE-2024-56670",
    "CVE-2024-56681",
    "CVE-2024-56688",
    "CVE-2024-56690",
    "CVE-2024-56691",
    "CVE-2024-56694",
    "CVE-2024-56700",
    "CVE-2024-56704",
    "CVE-2024-56720",
    "CVE-2024-56723",
    "CVE-2024-56724",
    "CVE-2024-56739",
    "CVE-2024-56746",
    "CVE-2024-56747",
    "CVE-2024-56748",
    "CVE-2024-56756",
    "CVE-2024-56767",
    "CVE-2024-56769",
    "CVE-2024-56770",
    "CVE-2024-56779",
    "CVE-2024-56780",
    "CVE-2024-56781",
    "CVE-2024-57802",
    "CVE-2024-57807",
    "CVE-2024-57849",
    "CVE-2024-57850",
    "CVE-2024-57884",
    "CVE-2024-57889",
    "CVE-2024-57890",
    "CVE-2024-57892",
    "CVE-2024-57900",
    "CVE-2024-57901",
    "CVE-2024-57902",
    "CVE-2024-57904",
    "CVE-2024-57906",
    "CVE-2024-57908",
    "CVE-2024-57910",
    "CVE-2024-57911",
    "CVE-2024-57912",
    "CVE-2024-57913",
    "CVE-2024-57922",
    "CVE-2024-57929",
    "CVE-2024-57931",
    "CVE-2024-57938",
    "CVE-2024-57946",
    "CVE-2024-57948",
    "CVE-2024-57951",
    "CVE-2025-0927",
    "CVE-2025-21638",
    "CVE-2025-21639",
    "CVE-2025-21640",
    "CVE-2025-21653",
    "CVE-2025-21664",
    "CVE-2025-21678",
    "CVE-2025-21687",
    "CVE-2025-21689",
    "CVE-2025-21694",
    "CVE-2025-21697",
    "CVE-2025-21699"
  );
  script_xref(name:"USN", value:"7393-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/30");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/26");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/25");

  script_name(english:"Ubuntu Pro FIPS-updates 20.04 LTS : Linux kernel (FIPS) vulnerabilities (USN-7393-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu Pro FIPS-updates 20.04 LTS host has a package installed that is affected by multiple vulnerabilities
as referenced in the USN-7393-1 advisory.

    Chenyuan Yang discovered that the CEC driver driver in the Linux kernel contained a use-after-free
    vulnerability. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2024-23848)

    Attila Szsz discovered that the HFS+ file system implementation in the Linux Kernel contained a heap
    overflow vulnerability. An attacker could use a specially crafted file system image that, when mounted,
    could cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2025-0927)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM64 architecture;

    - PowerPC architecture;

    - S390 architecture;

    - SuperH RISC architecture;

    - User-Mode Linux (UML);

    - x86 architecture;

    - Block layer subsystem;

    - Cryptographic API;

    - ACPI drivers;

    - Drivers core;

    - ATA over ethernet (AOE) driver;

    - Virtio block driver;

    - TPM device driver;

    - Data acquisition framework and drivers;

    - Hardware crypto device drivers;

    - DMA engine subsystem;

    - EDAC drivers;

    - ARM SCPI message protocol;

    - GPIO subsystem;

    - GPU drivers;

    - HID subsystem;

    - Microsoft Hyper-V drivers;

    - I2C subsystem;

    - I3C subsystem;

    - IIO ADC drivers;

    - IIO subsystem;

    - InfiniBand drivers;

    - LED subsystem;

    - Mailbox framework;

    - Multiple devices driver;

    - Media drivers;

    - Multifunction device drivers;

    - MMC subsystem;

    - MTD block device drivers;

    - Network drivers;

    - Mellanox network drivers;

    - NTB driver;

    - Virtio pmem driver;

    - NVME drivers;

    - Parport drivers;

    - PCI subsystem;

    - Pin controllers subsystem;

    - x86 platform drivers;

    - Real Time Clock drivers;

    - SCSI subsystem;

    - SuperH / SH-Mobile drivers;

    - QCOM SoC drivers;

    - SPI subsystem;

    - Direct Digital Synthesis drivers;

    - USB Device Class drivers;

    - USB Gadget drivers;

    - USB Dual Role (OTG-ready) Controller drivers;

    - USB Serial drivers;

    - USB Type-C support driver;

    - USB Type-C Port Controller Manager driver;

    - VFIO drivers;

    - Framebuffer layer;

    - Xen hypervisor drivers;

    - BTRFS file system;

    - Ceph distributed file system;

    - Ext4 file system;

    - F2FS file system;

    - GFS2 file system;

    - File systems infrastructure;

    - JFFS2 file system;

    - JFS file system;

    - Network file system (NFS) client;

    - Network file system (NFS) server daemon;

    - NILFS2 file system;

    - Overlay file system;

    - Proc file system;

    - Diskquota system;

    - SMB network file system;

    - UBI file system;

    - Timer subsystem;

    - VLANs driver;

    - LAPB network protocol;

    - Network traffic control;

    - Network sockets;

    - TCP network protocol;

    - Kernel init infrastructure;

    - BPF subsystem;

    - Kernel CPU control infrastructure;

    - Perf events;

    - Arbitrary resource management;

    - Tracing infrastructure;

    - Closures library;

    - Memory management;

    - 9P file system network protocol;

    - Amateur Radio drivers;

    - Bluetooth subsystem;

    - Ethernet bridge;

    - CAN network layer;

    - Networking core;

    - DCCP (Datagram Congestion Control Protocol);

    - IEEE802154.4 network protocol;

    - IPv4 networking;

    - IPv6 networking;

    - MAC80211 subsystem;

    - IEEE 802.15.4 subsystem;

    - Netfilter;

    - Netlink;

    - NET/ROM layer;

    - Packet sockets;

    - SCTP protocol;

    - Sun RPC protocol;

    - TIPC protocol;

    - Wireless networking;

    - eXpress Data Path;

    - XFRM subsystem;

    - Key management;

    - SELinux security module;

    - FireWire sound drivers;

    - AudioScience HPI driver;

    - Amlogic Meson SoC drivers;

    - USB sound devices;

    - KVM core; (CVE-2024-49938, CVE-2024-41066, CVE-2024-57951, CVE-2024-56779, CVE-2024-50194,
    CVE-2024-50265, CVE-2024-56596, CVE-2024-57922, CVE-2024-56614, CVE-2024-57912, CVE-2024-50251,
    CVE-2024-56569, CVE-2024-56587, CVE-2024-57807, CVE-2024-50051, CVE-2024-49997, CVE-2024-57911,
    CVE-2024-50195, CVE-2024-50205, CVE-2024-35896, CVE-2025-21689, CVE-2024-43098, CVE-2024-47757,
    CVE-2025-21639, CVE-2024-57900, CVE-2024-56634, CVE-2024-50230, CVE-2024-57946, CVE-2024-53059,
    CVE-2024-50290, CVE-2024-49985, CVE-2024-50142, CVE-2024-49925, CVE-2024-50199, CVE-2024-47699,
    CVE-2024-53172, CVE-2024-53173, CVE-2024-56631, CVE-2024-57938, CVE-2024-53101, CVE-2024-53197,
    CVE-2024-49896, CVE-2024-47697, CVE-2024-56644, CVE-2024-50236, CVE-2024-46731, CVE-2024-47674,
    CVE-2024-38544, CVE-2024-46853, CVE-2024-47740, CVE-2024-53121, CVE-2024-50082, CVE-2024-53165,
    CVE-2024-50040, CVE-2024-57929, CVE-2024-57889, CVE-2024-49860, CVE-2024-50287, CVE-2022-49034,
    CVE-2024-56690, CVE-2024-50302, CVE-2024-50006, CVE-2024-49949, CVE-2024-49868, CVE-2024-49903,
    CVE-2024-47723, CVE-2024-49936, CVE-2024-49955, CVE-2024-50234, CVE-2024-50301, CVE-2024-47670,
    CVE-2024-56574, CVE-2024-50168, CVE-2024-57913, CVE-2024-56602, CVE-2024-56630, CVE-2024-53130,
    CVE-2024-53145, CVE-2024-56642, CVE-2024-50202, CVE-2024-38588, CVE-2024-56767, CVE-2024-50024,
    CVE-2024-53198, CVE-2024-56548, CVE-2024-50184, CVE-2024-47756, CVE-2024-50167, CVE-2025-21694,
    CVE-2024-53063, CVE-2024-49966, CVE-2024-50299, CVE-2024-50143, CVE-2024-49924, CVE-2024-53061,
    CVE-2024-53124, CVE-2024-49902, CVE-2024-56739, CVE-2024-49952, CVE-2025-21664, CVE-2024-49877,
    CVE-2024-47701, CVE-2024-52332, CVE-2024-49975, CVE-2024-56645, CVE-2024-53140, CVE-2024-49948,
    CVE-2024-56724, CVE-2024-49963, CVE-2025-21687, CVE-2024-47698, CVE-2024-50039, CVE-2024-56595,
    CVE-2024-50282, CVE-2023-52458, CVE-2024-56615, CVE-2024-40965, CVE-2024-49965, CVE-2024-53112,
    CVE-2024-53135, CVE-2024-56601, CVE-2024-56532, CVE-2024-53184, CVE-2024-47672, CVE-2024-53155,
    CVE-2024-50171, CVE-2024-50035, CVE-2024-56704, CVE-2024-53156, CVE-2024-47685, CVE-2024-50044,
    CVE-2024-47712, CVE-2024-47707, CVE-2024-50179, CVE-2024-56594, CVE-2024-56688, CVE-2024-50151,
    CVE-2025-21699, CVE-2024-56598, CVE-2024-47737, CVE-2024-57849, CVE-2024-56576, CVE-2025-21638,
    CVE-2024-53181, CVE-2024-50033, CVE-2024-49995, CVE-2024-56756, CVE-2024-49867, CVE-2025-21697,
    CVE-2024-56600, CVE-2024-56670, CVE-2024-47713, CVE-2024-46854, CVE-2024-47671, CVE-2024-53680,
    CVE-2024-49851, CVE-2024-49883, CVE-2024-56780, CVE-2024-56770, CVE-2024-56650, CVE-2024-53146,
    CVE-2024-50218, CVE-2024-56531, CVE-2024-47706, CVE-2024-56572, CVE-2024-47709, CVE-2024-49958,
    CVE-2024-57948, CVE-2024-40911, CVE-2024-57904, CVE-2024-56769, CVE-2024-35887, CVE-2025-21678,
    CVE-2024-57802, CVE-2024-56700, CVE-2024-43900, CVE-2024-47747, CVE-2024-50059, CVE-2024-56606,
    CVE-2024-53161, CVE-2024-50116, CVE-2024-50180, CVE-2024-50127, CVE-2024-53131, CVE-2024-53157,
    CVE-2024-50279, CVE-2024-57850, CVE-2024-56619, CVE-2024-49982, CVE-2024-56748, CVE-2024-53104,
    CVE-2024-49981, CVE-2024-56643, CVE-2024-49962, CVE-2024-50131, CVE-2024-56781, CVE-2024-50233,
    CVE-2024-56597, CVE-2024-56567, CVE-2024-57902, CVE-2024-43863, CVE-2024-56581, CVE-2024-53171,
    CVE-2024-56633, CVE-2024-50296, CVE-2024-49879, CVE-2024-56593, CVE-2024-47679, CVE-2024-53148,
    CVE-2024-50237, CVE-2024-49959, CVE-2024-50269, CVE-2024-53138, CVE-2024-49957, CVE-2024-50278,
    CVE-2024-49894, CVE-2024-49900, CVE-2024-56586, CVE-2024-50148, CVE-2024-50262, CVE-2024-56720,
    CVE-2024-50096, CVE-2024-57931, CVE-2024-56681, CVE-2021-47219, CVE-2025-21640, CVE-2024-56603,
    CVE-2024-50229, CVE-2024-53174, CVE-2024-50007, CVE-2024-49944, CVE-2024-50273, CVE-2024-49878,
    CVE-2024-56605, CVE-2024-53150, CVE-2024-44931, CVE-2024-53214, CVE-2024-49882, CVE-2024-53158,
    CVE-2024-55916, CVE-2024-50117, CVE-2024-56570, CVE-2024-44938, CVE-2024-53239, CVE-2024-53217,
    CVE-2024-50099, CVE-2024-50267, CVE-2024-56562, CVE-2024-40953, CVE-2024-57884, CVE-2024-49892,
    CVE-2024-56659, CVE-2024-56746, CVE-2024-50074, CVE-2024-41016, CVE-2024-53142, CVE-2024-57901,
    CVE-2024-56637, CVE-2024-47710, CVE-2024-46849, CVE-2024-57910, CVE-2024-47692, CVE-2024-48881,
    CVE-2024-53194, CVE-2024-56558, CVE-2024-56747, CVE-2024-56629, CVE-2024-47696, CVE-2024-56691,
    CVE-2024-53227, CVE-2024-57908, CVE-2024-57892, CVE-2024-53183, CVE-2024-56723, CVE-2024-42252,
    CVE-2024-57890, CVE-2024-50134, CVE-2024-56694, CVE-2024-57906, CVE-2024-56539, CVE-2024-53690,
    CVE-2024-53066, CVE-2024-49973, CVE-2024-47684, CVE-2024-50045, CVE-2024-49884, CVE-2025-21653,
    CVE-2024-47749, CVE-2024-47742, CVE-2024-50008, CVE-2024-50150, CVE-2024-53127, CVE-2024-49996)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7393-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:Pro:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1116-fips");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('Pro' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu Pro', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var kernel_mappings = {
  'Pro': {
    '5.4.0': {
      'fips': '5.4.0-1116'
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
if (!ubuntu_pro_detected) {
  extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
  extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
  extra += 'require an Ubuntu Pro subscription.\n\n';
}
if (deb_ver_cmp(ver1:host_kernel_release, ver2:kernel_fixed_version) < 0)
{
  extra += 'Running Kernel level of ' + host_kernel_release + ' does not meet the minimum fixed level of ' + kernel_fixed_version + ' for this advisory.\n\n';
}
  else
{
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7393-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-47219', 'CVE-2022-49034', 'CVE-2023-52458', 'CVE-2024-23848', 'CVE-2024-35887', 'CVE-2024-35896', 'CVE-2024-38544', 'CVE-2024-38588', 'CVE-2024-40911', 'CVE-2024-40953', 'CVE-2024-40965', 'CVE-2024-41016', 'CVE-2024-41066', 'CVE-2024-42252', 'CVE-2024-43098', 'CVE-2024-43863', 'CVE-2024-43900', 'CVE-2024-44931', 'CVE-2024-44938', 'CVE-2024-46731', 'CVE-2024-46849', 'CVE-2024-46853', 'CVE-2024-46854', 'CVE-2024-47670', 'CVE-2024-47671', 'CVE-2024-47672', 'CVE-2024-47674', 'CVE-2024-47679', 'CVE-2024-47684', 'CVE-2024-47685', 'CVE-2024-47692', 'CVE-2024-47696', 'CVE-2024-47697', 'CVE-2024-47698', 'CVE-2024-47699', 'CVE-2024-47701', 'CVE-2024-47706', 'CVE-2024-47707', 'CVE-2024-47709', 'CVE-2024-47710', 'CVE-2024-47712', 'CVE-2024-47713', 'CVE-2024-47723', 'CVE-2024-47737', 'CVE-2024-47740', 'CVE-2024-47742', 'CVE-2024-47747', 'CVE-2024-47749', 'CVE-2024-47756', 'CVE-2024-47757', 'CVE-2024-48881', 'CVE-2024-49851', 'CVE-2024-49860', 'CVE-2024-49867', 'CVE-2024-49868', 'CVE-2024-49877', 'CVE-2024-49878', 'CVE-2024-49879', 'CVE-2024-49882', 'CVE-2024-49883', 'CVE-2024-49884', 'CVE-2024-49892', 'CVE-2024-49894', 'CVE-2024-49896', 'CVE-2024-49900', 'CVE-2024-49902', 'CVE-2024-49903', 'CVE-2024-49924', 'CVE-2024-49925', 'CVE-2024-49936', 'CVE-2024-49938', 'CVE-2024-49944', 'CVE-2024-49948', 'CVE-2024-49949', 'CVE-2024-49952', 'CVE-2024-49955', 'CVE-2024-49957', 'CVE-2024-49958', 'CVE-2024-49959', 'CVE-2024-49962', 'CVE-2024-49963', 'CVE-2024-49965', 'CVE-2024-49966', 'CVE-2024-49973', 'CVE-2024-49975', 'CVE-2024-49981', 'CVE-2024-49982', 'CVE-2024-49985', 'CVE-2024-49995', 'CVE-2024-49996', 'CVE-2024-49997', 'CVE-2024-50006', 'CVE-2024-50007', 'CVE-2024-50008', 'CVE-2024-50024', 'CVE-2024-50033', 'CVE-2024-50035', 'CVE-2024-50039', 'CVE-2024-50040', 'CVE-2024-50044', 'CVE-2024-50045', 'CVE-2024-50051', 'CVE-2024-50059', 'CVE-2024-50074', 'CVE-2024-50082', 'CVE-2024-50096', 'CVE-2024-50099', 'CVE-2024-50116', 'CVE-2024-50117', 'CVE-2024-50127', 'CVE-2024-50131', 'CVE-2024-50134', 'CVE-2024-50142', 'CVE-2024-50143', 'CVE-2024-50148', 'CVE-2024-50150', 'CVE-2024-50151', 'CVE-2024-50167', 'CVE-2024-50168', 'CVE-2024-50171', 'CVE-2024-50179', 'CVE-2024-50180', 'CVE-2024-50184', 'CVE-2024-50194', 'CVE-2024-50195', 'CVE-2024-50199', 'CVE-2024-50202', 'CVE-2024-50205', 'CVE-2024-50218', 'CVE-2024-50229', 'CVE-2024-50230', 'CVE-2024-50233', 'CVE-2024-50234', 'CVE-2024-50236', 'CVE-2024-50237', 'CVE-2024-50251', 'CVE-2024-50262', 'CVE-2024-50265', 'CVE-2024-50267', 'CVE-2024-50269', 'CVE-2024-50273', 'CVE-2024-50278', 'CVE-2024-50279', 'CVE-2024-50282', 'CVE-2024-50287', 'CVE-2024-50290', 'CVE-2024-50296', 'CVE-2024-50299', 'CVE-2024-50301', 'CVE-2024-50302', 'CVE-2024-52332', 'CVE-2024-53059', 'CVE-2024-53061', 'CVE-2024-53063', 'CVE-2024-53066', 'CVE-2024-53101', 'CVE-2024-53104', 'CVE-2024-53112', 'CVE-2024-53121', 'CVE-2024-53124', 'CVE-2024-53127', 'CVE-2024-53130', 'CVE-2024-53131', 'CVE-2024-53135', 'CVE-2024-53138', 'CVE-2024-53140', 'CVE-2024-53142', 'CVE-2024-53145', 'CVE-2024-53146', 'CVE-2024-53148', 'CVE-2024-53150', 'CVE-2024-53155', 'CVE-2024-53156', 'CVE-2024-53157', 'CVE-2024-53158', 'CVE-2024-53161', 'CVE-2024-53165', 'CVE-2024-53171', 'CVE-2024-53172', 'CVE-2024-53173', 'CVE-2024-53174', 'CVE-2024-53181', 'CVE-2024-53183', 'CVE-2024-53184', 'CVE-2024-53194', 'CVE-2024-53197', 'CVE-2024-53198', 'CVE-2024-53214', 'CVE-2024-53217', 'CVE-2024-53227', 'CVE-2024-53239', 'CVE-2024-53680', 'CVE-2024-53690', 'CVE-2024-55916', 'CVE-2024-56531', 'CVE-2024-56532', 'CVE-2024-56539', 'CVE-2024-56548', 'CVE-2024-56558', 'CVE-2024-56562', 'CVE-2024-56567', 'CVE-2024-56569', 'CVE-2024-56570', 'CVE-2024-56572', 'CVE-2024-56574', 'CVE-2024-56576', 'CVE-2024-56581', 'CVE-2024-56586', 'CVE-2024-56587', 'CVE-2024-56593', 'CVE-2024-56594', 'CVE-2024-56595', 'CVE-2024-56596', 'CVE-2024-56597', 'CVE-2024-56598', 'CVE-2024-56600', 'CVE-2024-56601', 'CVE-2024-56602', 'CVE-2024-56603', 'CVE-2024-56605', 'CVE-2024-56606', 'CVE-2024-56614', 'CVE-2024-56615', 'CVE-2024-56619', 'CVE-2024-56629', 'CVE-2024-56630', 'CVE-2024-56631', 'CVE-2024-56633', 'CVE-2024-56634', 'CVE-2024-56637', 'CVE-2024-56642', 'CVE-2024-56643', 'CVE-2024-56644', 'CVE-2024-56645', 'CVE-2024-56650', 'CVE-2024-56659', 'CVE-2024-56670', 'CVE-2024-56681', 'CVE-2024-56688', 'CVE-2024-56690', 'CVE-2024-56691', 'CVE-2024-56694', 'CVE-2024-56700', 'CVE-2024-56704', 'CVE-2024-56720', 'CVE-2024-56723', 'CVE-2024-56724', 'CVE-2024-56739', 'CVE-2024-56746', 'CVE-2024-56747', 'CVE-2024-56748', 'CVE-2024-56756', 'CVE-2024-56767', 'CVE-2024-56769', 'CVE-2024-56770', 'CVE-2024-56779', 'CVE-2024-56780', 'CVE-2024-56781', 'CVE-2024-57802', 'CVE-2024-57807', 'CVE-2024-57849', 'CVE-2024-57850', 'CVE-2024-57884', 'CVE-2024-57889', 'CVE-2024-57890', 'CVE-2024-57892', 'CVE-2024-57900', 'CVE-2024-57901', 'CVE-2024-57902', 'CVE-2024-57904', 'CVE-2024-57906', 'CVE-2024-57908', 'CVE-2024-57910', 'CVE-2024-57911', 'CVE-2024-57912', 'CVE-2024-57913', 'CVE-2024-57922', 'CVE-2024-57929', 'CVE-2024-57931', 'CVE-2024-57938', 'CVE-2024-57946', 'CVE-2024-57948', 'CVE-2024-57951', 'CVE-2025-0927', 'CVE-2025-21638', 'CVE-2025-21639', 'CVE-2025-21640', 'CVE-2025-21653', 'CVE-2025-21664', 'CVE-2025-21678', 'CVE-2025-21687', 'CVE-2025-21689', 'CVE-2025-21694', 'CVE-2025-21697', 'CVE-2025-21699');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7393-1');
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
