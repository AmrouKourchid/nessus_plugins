#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7019-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207384);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id(
    "CVE-2022-38096",
    "CVE-2022-48772",
    "CVE-2022-48808",
    "CVE-2023-52488",
    "CVE-2023-52585",
    "CVE-2023-52629",
    "CVE-2023-52699",
    "CVE-2023-52752",
    "CVE-2023-52760",
    "CVE-2023-52880",
    "CVE-2023-52882",
    "CVE-2023-52884",
    "CVE-2023-52887",
    "CVE-2024-23307",
    "CVE-2024-23848",
    "CVE-2024-24857",
    "CVE-2024-24858",
    "CVE-2024-24859",
    "CVE-2024-24861",
    "CVE-2024-25739",
    "CVE-2024-25741",
    "CVE-2024-25742",
    "CVE-2024-26629",
    "CVE-2024-26642",
    "CVE-2024-26654",
    "CVE-2024-26680",
    "CVE-2024-26687",
    "CVE-2024-26810",
    "CVE-2024-26811",
    "CVE-2024-26812",
    "CVE-2024-26813",
    "CVE-2024-26814",
    "CVE-2024-26817",
    "CVE-2024-26828",
    "CVE-2024-26830",
    "CVE-2024-26886",
    "CVE-2024-26900",
    "CVE-2024-26921",
    "CVE-2024-26922",
    "CVE-2024-26923",
    "CVE-2024-26925",
    "CVE-2024-26926",
    "CVE-2024-26929",
    "CVE-2024-26931",
    "CVE-2024-26934",
    "CVE-2024-26935",
    "CVE-2024-26936",
    "CVE-2024-26937",
    "CVE-2024-26950",
    "CVE-2024-26951",
    "CVE-2024-26952",
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
    "CVE-2024-26980",
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
    "CVE-2024-27017",
    "CVE-2024-27018",
    "CVE-2024-27019",
    "CVE-2024-27020",
    "CVE-2024-27059",
    "CVE-2024-27393",
    "CVE-2024-27395",
    "CVE-2024-27396",
    "CVE-2024-27398",
    "CVE-2024-27399",
    "CVE-2024-27401",
    "CVE-2024-27437",
    "CVE-2024-31076",
    "CVE-2024-33621",
    "CVE-2024-33847",
    "CVE-2024-34027",
    "CVE-2024-34777",
    "CVE-2024-35247",
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
    "CVE-2024-35815",
    "CVE-2024-35817",
    "CVE-2024-35819",
    "CVE-2024-35821",
    "CVE-2024-35822",
    "CVE-2024-35823",
    "CVE-2024-35825",
    "CVE-2024-35847",
    "CVE-2024-35848",
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
    "CVE-2024-35902",
    "CVE-2024-35905",
    "CVE-2024-35907",
    "CVE-2024-35910",
    "CVE-2024-35912",
    "CVE-2024-35915",
    "CVE-2024-35922",
    "CVE-2024-35925",
    "CVE-2024-35927",
    "CVE-2024-35930",
    "CVE-2024-35933",
    "CVE-2024-35934",
    "CVE-2024-35935",
    "CVE-2024-35936",
    "CVE-2024-35938",
    "CVE-2024-35940",
    "CVE-2024-35944",
    "CVE-2024-35947",
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
    "CVE-2024-36014",
    "CVE-2024-36015",
    "CVE-2024-36016",
    "CVE-2024-36017",
    "CVE-2024-36020",
    "CVE-2024-36025",
    "CVE-2024-36029",
    "CVE-2024-36031",
    "CVE-2024-36032",
    "CVE-2024-36270",
    "CVE-2024-36286",
    "CVE-2024-36489",
    "CVE-2024-36880",
    "CVE-2024-36883",
    "CVE-2024-36886",
    "CVE-2024-36889",
    "CVE-2024-36894",
    "CVE-2024-36901",
    "CVE-2024-36902",
    "CVE-2024-36904",
    "CVE-2024-36905",
    "CVE-2024-36906",
    "CVE-2024-36916",
    "CVE-2024-36919",
    "CVE-2024-36928",
    "CVE-2024-36929",
    "CVE-2024-36931",
    "CVE-2024-36933",
    "CVE-2024-36934",
    "CVE-2024-36937",
    "CVE-2024-36938",
    "CVE-2024-36939",
    "CVE-2024-36940",
    "CVE-2024-36941",
    "CVE-2024-36946",
    "CVE-2024-36947",
    "CVE-2024-36950",
    "CVE-2024-36952",
    "CVE-2024-36953",
    "CVE-2024-36954",
    "CVE-2024-36955",
    "CVE-2024-36957",
    "CVE-2024-36959",
    "CVE-2024-36960",
    "CVE-2024-36964",
    "CVE-2024-36965",
    "CVE-2024-36967",
    "CVE-2024-36969",
    "CVE-2024-36971",
    "CVE-2024-36972",
    "CVE-2024-36974",
    "CVE-2024-36975",
    "CVE-2024-36978",
    "CVE-2024-37078",
    "CVE-2024-37356",
    "CVE-2024-38546",
    "CVE-2024-38547",
    "CVE-2024-38548",
    "CVE-2024-38549",
    "CVE-2024-38550",
    "CVE-2024-38552",
    "CVE-2024-38555",
    "CVE-2024-38558",
    "CVE-2024-38559",
    "CVE-2024-38560",
    "CVE-2024-38565",
    "CVE-2024-38567",
    "CVE-2024-38571",
    "CVE-2024-38573",
    "CVE-2024-38578",
    "CVE-2024-38579",
    "CVE-2024-38580",
    "CVE-2024-38582",
    "CVE-2024-38583",
    "CVE-2024-38586",
    "CVE-2024-38588",
    "CVE-2024-38589",
    "CVE-2024-38590",
    "CVE-2024-38591",
    "CVE-2024-38596",
    "CVE-2024-38597",
    "CVE-2024-38598",
    "CVE-2024-38599",
    "CVE-2024-38600",
    "CVE-2024-38601",
    "CVE-2024-38605",
    "CVE-2024-38607",
    "CVE-2024-38610",
    "CVE-2024-38612",
    "CVE-2024-38613",
    "CVE-2024-38615",
    "CVE-2024-38618",
    "CVE-2024-38619",
    "CVE-2024-38621",
    "CVE-2024-38623",
    "CVE-2024-38624",
    "CVE-2024-38627",
    "CVE-2024-38633",
    "CVE-2024-38634",
    "CVE-2024-38635",
    "CVE-2024-38637",
    "CVE-2024-38659",
    "CVE-2024-38661",
    "CVE-2024-38780",
    "CVE-2024-39276",
    "CVE-2024-39277",
    "CVE-2024-39292",
    "CVE-2024-39301",
    "CVE-2024-39466",
    "CVE-2024-39467",
    "CVE-2024-39468",
    "CVE-2024-39469",
    "CVE-2024-39471",
    "CVE-2024-39475",
    "CVE-2024-39480",
    "CVE-2024-39482",
    "CVE-2024-39484",
    "CVE-2024-39487",
    "CVE-2024-39488",
    "CVE-2024-39489",
    "CVE-2024-39490",
    "CVE-2024-39495",
    "CVE-2024-39499",
    "CVE-2024-39500",
    "CVE-2024-39501",
    "CVE-2024-39502",
    "CVE-2024-39503",
    "CVE-2024-39505",
    "CVE-2024-39506",
    "CVE-2024-39507",
    "CVE-2024-39509",
    "CVE-2024-40901",
    "CVE-2024-40902",
    "CVE-2024-40904",
    "CVE-2024-40905",
    "CVE-2024-40908",
    "CVE-2024-40911",
    "CVE-2024-40912",
    "CVE-2024-40914",
    "CVE-2024-40916",
    "CVE-2024-40927",
    "CVE-2024-40929",
    "CVE-2024-40931",
    "CVE-2024-40932",
    "CVE-2024-40934",
    "CVE-2024-40937",
    "CVE-2024-40941",
    "CVE-2024-40942",
    "CVE-2024-40943",
    "CVE-2024-40945",
    "CVE-2024-40954",
    "CVE-2024-40956",
    "CVE-2024-40957",
    "CVE-2024-40958",
    "CVE-2024-40959",
    "CVE-2024-40960",
    "CVE-2024-40961",
    "CVE-2024-40963",
    "CVE-2024-40967",
    "CVE-2024-40968",
    "CVE-2024-40970",
    "CVE-2024-40971",
    "CVE-2024-40974",
    "CVE-2024-40976",
    "CVE-2024-40978",
    "CVE-2024-40980",
    "CVE-2024-40981",
    "CVE-2024-40983",
    "CVE-2024-40984",
    "CVE-2024-40987",
    "CVE-2024-40988",
    "CVE-2024-40990",
    "CVE-2024-40994",
    "CVE-2024-40995",
    "CVE-2024-41000",
    "CVE-2024-41002",
    "CVE-2024-41004",
    "CVE-2024-41005",
    "CVE-2024-41006",
    "CVE-2024-41007",
    "CVE-2024-41027",
    "CVE-2024-41034",
    "CVE-2024-41035",
    "CVE-2024-41040",
    "CVE-2024-41041",
    "CVE-2024-41044",
    "CVE-2024-41046",
    "CVE-2024-41047",
    "CVE-2024-41048",
    "CVE-2024-41049",
    "CVE-2024-41055",
    "CVE-2024-41087",
    "CVE-2024-41089",
    "CVE-2024-41092",
    "CVE-2024-41093",
    "CVE-2024-41095",
    "CVE-2024-41097",
    "CVE-2024-42068",
    "CVE-2024-42070",
    "CVE-2024-42076",
    "CVE-2024-42077",
    "CVE-2024-42080",
    "CVE-2024-42082",
    "CVE-2024-42084",
    "CVE-2024-42085",
    "CVE-2024-42086",
    "CVE-2024-42087",
    "CVE-2024-42089",
    "CVE-2024-42090",
    "CVE-2024-42092",
    "CVE-2024-42093",
    "CVE-2024-42094",
    "CVE-2024-42095",
    "CVE-2024-42096",
    "CVE-2024-42097",
    "CVE-2024-42098",
    "CVE-2024-42101",
    "CVE-2024-42102",
    "CVE-2024-42104",
    "CVE-2024-42105",
    "CVE-2024-42106",
    "CVE-2024-42109",
    "CVE-2024-42115",
    "CVE-2024-42119",
    "CVE-2024-42120",
    "CVE-2024-42121",
    "CVE-2024-42124",
    "CVE-2024-42127",
    "CVE-2024-42130",
    "CVE-2024-42131",
    "CVE-2024-42137",
    "CVE-2024-42140",
    "CVE-2024-42145",
    "CVE-2024-42148",
    "CVE-2024-42152",
    "CVE-2024-42153",
    "CVE-2024-42154",
    "CVE-2024-42157",
    "CVE-2024-42161",
    "CVE-2024-42223",
    "CVE-2024-42224",
    "CVE-2024-42225",
    "CVE-2024-42229",
    "CVE-2024-42232",
    "CVE-2024-42236",
    "CVE-2024-42240",
    "CVE-2024-42244",
    "CVE-2024-42247"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/08/28");
  script_xref(name:"USN", value:"7019-1");

  script_name(english:"Ubuntu 22.04 LTS : Linux kernel vulnerabilities (USN-7019-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-7019-1 advisory.

    Ziming Zhang discovered that the DRM driver for VMware Virtual GPU did not properly handle certain error
    conditions, leading to a NULL pointer dereference. A local attacker could possibly trigger this
    vulnerability to cause a denial of service. (CVE-2022-38096)

    Gui-Dong Han discovered that the software RAID driver in the Linux kernel contained a race condition,
    leading to an integer overflow vulnerability. A privileged attacker could possibly use this to cause a
    denial of service (system crash). (CVE-2024-23307)

    Chenyuan Yang discovered that the CEC driver driver in the Linux kernel contained a use-after-free
    vulnerability. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2024-23848)

    It was discovered that a race condition existed in the Bluetooth subsystem in the Linux kernel when
    modifying certain settings values through debugfs. A privileged local attacker could use this to cause a
    denial of service. (CVE-2024-24857, CVE-2024-24858, CVE-2024-24859)

    Bai Jiaju discovered that the Xceive XC4000 silicon tuner device driver in the Linux kernel contained a
    race condition, leading to an integer overflow vulnerability. An attacker could possibly use this to cause
    a denial of service (system crash). (CVE-2024-24861)

    Chenyuan Yang discovered that the Unsorted Block Images (UBI) flash device volume management subsystem did
    not properly validate logical eraseblock sizes in certain situations. An attacker could possibly use this
    to cause a denial of service (system crash). (CVE-2024-25739)

    Chenyuan Yang discovered that the USB Gadget subsystem in the Linux kernel did not properly check for the
    device to be enabled before writing. A local attacker could possibly use this to cause a denial of
    service. (CVE-2024-25741)

    Benedict Schlter, Supraja Sridhara, Andrin Bertschi, and Shweta Shinde discovered that an untrusted
    hypervisor could inject malicious #VC interrupts and compromise the security guarantees of AMD SEV-SNP.
    This flaw is known as WeSee. A local attacker in control of the hypervisor could use this to expose
    sensitive information or possibly execute arbitrary code in the trusted execution environment.
    (CVE-2024-25742)

    It was discovered that the JFS file system contained an out-of-bounds read vulnerability when printing
    xattr debug information. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2024-40902)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM32 architecture;

    - ARM64 architecture;

    - M68K architecture;

    - MIPS architecture;

    - PowerPC architecture;

    - RISC-V architecture;

    - SuperH RISC architecture;

    - User-Mode Linux (UML);

    - x86 architecture;

    - Block layer subsystem;

    - Cryptographic API;

    - Accessibility subsystem;

    - ACPI drivers;

    - Android drivers;

    - Serial ATA and Parallel ATA drivers;

    - Drivers core;

    - Bluetooth drivers;

    - Character device driver;

    - Clock framework and drivers;

    - Data acquisition framework and drivers;

    - CPU frequency scaling framework;

    - Hardware crypto device drivers;

    - Buffer Sharing and Synchronization framework;

    - DMA engine subsystem;

    - FireWire subsystem;

    - FPGA Framework;

    - GPIO subsystem;

    - GPU drivers;

    - Greybus drivers;

    - HID subsystem;

    - HW tracing;

    - I2C subsystem;

    - IIO subsystem;

    - InfiniBand drivers;

    - Input Device (Mouse) drivers;

    - IRQ chip drivers;

    - Macintosh device drivers;

    - Multiple devices driver;

    - Media drivers;

    - EEPROM drivers;

    - VMware VMCI Driver;

    - MMC subsystem;

    - Network drivers;

    - Near Field Communication (NFC) drivers;

    - NVME drivers;

    - Device tree and open firmware driver;

    - PCI subsystem;

    - Pin controllers subsystem;

    - PTP clock framework;

    - Remote Processor subsystem;

    - S/390 drivers;

    - SCSI drivers;

    - Freescale SoC drivers;

    - SoundWire subsystem;

    - Greybus lights staging drivers;

    - Media staging drivers;

    - Trusted Execution Environment drivers;

    - Thermal drivers;

    - TTY drivers;

    - USB subsystem;

    - DesignWare USB3 driver;

    - VFIO drivers;

    - Framebuffer layer;

    - ACRN Hypervisor Service Module driver;

    - Xen hypervisor drivers;

    - 9P distributed file system;

    - File systems infrastructure;

    - BTRFS file system;

    - eCrypt file system;

    - Ext4 file system;

    - F2FS file system;

    - FAT file system;

    - GFS2 file system;

    - JFFS2 file system;

    - JFS file system;

    - Network file system client;

    - Network file system server daemon;

    - NILFS2 file system;

    - NTFS3 file system;

    - Pstore file system;

    - SMB network file system;

    - UBI file system;

    - IOMMU subsystem;

    - Memory management;

    - Socket messages infrastructure;

    - Netfilter;

    - BPF subsystem;

    - Kernel debugger infrastructure;

    - DMA mapping infrastructure;

    - IRQ subsystem;

    - Core kernel;

    - Tracing infrastructure;

    - Dynamic debug library;

    - PCI iomap interfaces;

    - 9P file system network protocol;

    - B.A.T.M.A.N. meshing protocol;

    - Bluetooth subsystem;

    - Ethernet bridge;

    - CAN network layer;

    - Ceph Core library;

    - Networking core;

    - Distributed Switch Architecture;

    - IPv4 networking;

    - IPv6 networking;

    - IUCV driver;

    - MAC80211 subsystem;

    - IEEE 802.15.4 subsystem;

    - Multipath TCP;

    - NET/ROM layer;

    - NFC subsystem;

    - NSH protocol;

    - Open vSwitch;

    - Phonet protocol;

    - RDS protocol;

    - Network traffic control;

    - SMC sockets;

    - TIPC protocol;

    - TLS protocol;

    - Unix domain sockets;

    - Wireless networking;

    - eXpress Data Path;

    - XFRM subsystem;

    - Key management;

    - ALSA framework;

    - HD-audio driver;

    - ALSA SH drivers;

    - SoC Audio for Freescale CPUs drivers;

    - Kirkwood ASoC drivers;

    - KVM core; (CVE-2024-42085, CVE-2024-42154, CVE-2024-42229, CVE-2024-38548, CVE-2024-42120,
    CVE-2024-38555, CVE-2024-38598, CVE-2024-40954, CVE-2024-38571, CVE-2024-36020, CVE-2024-36270,
    CVE-2024-39482, CVE-2024-39468, CVE-2024-38607, CVE-2024-26923, CVE-2024-42145, CVE-2024-41040,
    CVE-2024-35852, CVE-2024-35805, CVE-2024-35890, CVE-2024-36965, CVE-2024-42077, CVE-2024-26958,
    CVE-2024-35823, CVE-2024-42124, CVE-2024-26680, CVE-2024-38549, CVE-2024-36286, CVE-2024-27398,
    CVE-2024-35990, CVE-2024-36975, CVE-2024-27437, CVE-2024-35848, CVE-2024-26900, CVE-2024-26654,
    CVE-2024-40971, CVE-2024-35847, CVE-2024-35982, CVE-2024-42232, CVE-2022-48808, CVE-2024-35822,
    CVE-2024-36950, CVE-2024-33621, CVE-2024-39276, CVE-2024-40968, CVE-2024-35857, CVE-2024-40905,
    CVE-2023-52880, CVE-2024-35819, CVE-2024-35791, CVE-2024-42076, CVE-2024-40904, CVE-2024-35976,
    CVE-2024-35854, CVE-2024-26642, CVE-2024-27393, CVE-2024-26934, CVE-2024-26960, CVE-2024-42137,
    CVE-2024-38588, CVE-2024-40970, CVE-2024-36972, CVE-2024-26977, CVE-2024-38546, CVE-2024-41095,
    CVE-2024-39292, CVE-2024-41087, CVE-2024-33847, CVE-2024-40978, CVE-2024-41049, CVE-2024-35895,
    CVE-2024-35804, CVE-2024-42093, CVE-2024-36017, CVE-2024-38591, CVE-2024-42080, CVE-2024-41089,
    CVE-2024-38613, CVE-2024-39466, CVE-2024-40931, CVE-2024-35907, CVE-2024-36919, CVE-2024-36934,
    CVE-2024-42240, CVE-2024-35940, CVE-2024-36938, CVE-2024-42121, CVE-2024-39490, CVE-2024-40961,
    CVE-2024-42223, CVE-2024-41041, CVE-2024-41093, CVE-2024-42068, CVE-2024-41044, CVE-2024-42086,
    CVE-2024-42105, CVE-2024-36954, CVE-2024-35796, CVE-2024-38610, CVE-2024-36929, CVE-2024-35893,
    CVE-2024-38601, CVE-2024-40981, CVE-2024-36889, CVE-2024-27015, CVE-2024-35897, CVE-2024-39469,
    CVE-2024-35825, CVE-2024-26922, CVE-2024-38573, CVE-2024-42130, CVE-2024-38580, CVE-2024-26814,
    CVE-2024-36955, CVE-2024-26813, CVE-2024-27396, CVE-2024-36937, CVE-2024-36928, CVE-2024-42224,
    CVE-2024-27004, CVE-2024-42104, CVE-2024-42225, CVE-2024-38659, CVE-2024-35955, CVE-2024-42106,
    CVE-2024-39489, CVE-2024-31076, CVE-2024-26817, CVE-2024-35884, CVE-2024-42095, CVE-2024-42131,
    CVE-2024-40956, CVE-2024-40941, CVE-2024-36007, CVE-2024-27009, CVE-2024-40959, CVE-2024-42089,
    CVE-2024-37078, CVE-2024-35960, CVE-2024-41002, CVE-2024-39301, CVE-2024-35988, CVE-2023-52887,
    CVE-2024-35885, CVE-2024-39484, CVE-2024-35872, CVE-2024-40974, CVE-2024-35851, CVE-2024-26957,
    CVE-2024-38623, CVE-2024-35944, CVE-2024-41005, CVE-2024-42152, CVE-2024-35888, CVE-2024-38621,
    CVE-2024-26989, CVE-2024-42148, CVE-2024-27401, CVE-2024-36883, CVE-2024-35855, CVE-2024-26936,
    CVE-2024-26935, CVE-2022-48772, CVE-2024-35853, CVE-2024-35997, CVE-2024-27059, CVE-2024-36953,
    CVE-2024-35969, CVE-2024-42094, CVE-2024-38661, CVE-2024-35925, CVE-2024-40914, CVE-2024-36940,
    CVE-2024-27016, CVE-2024-26828, CVE-2024-40911, CVE-2024-38634, CVE-2024-38558, CVE-2024-38582,
    CVE-2023-52629, CVE-2024-27020, CVE-2024-35247, CVE-2024-26999, CVE-2024-26687, CVE-2024-38565,
    CVE-2024-38612, CVE-2024-39495, CVE-2024-26974, CVE-2024-42101, CVE-2024-38597, CVE-2024-26929,
    CVE-2024-40927, CVE-2024-26830, CVE-2024-26973, CVE-2024-40980, CVE-2024-38560, CVE-2024-41047,
    CVE-2024-42098, CVE-2024-39507, CVE-2024-38599, CVE-2024-35789, CVE-2024-27395, CVE-2024-41092,
    CVE-2024-42161, CVE-2024-41006, CVE-2024-36931, CVE-2024-38619, CVE-2024-35813, CVE-2024-35898,
    CVE-2024-41027, CVE-2024-40932, CVE-2024-40960, CVE-2024-26925, CVE-2024-41048, CVE-2024-36886,
    CVE-2024-35877, CVE-2024-40963, CVE-2024-36960, CVE-2024-38590, CVE-2024-40902, CVE-2024-35871,
    CVE-2024-38579, CVE-2024-40987, CVE-2024-36025, CVE-2024-35806, CVE-2024-35899, CVE-2024-26993,
    CVE-2024-41097, CVE-2024-39488, CVE-2024-42115, CVE-2024-42127, CVE-2024-37356, CVE-2024-26812,
    CVE-2024-36939, CVE-2024-35807, CVE-2024-26886, CVE-2024-35809, CVE-2024-40937, CVE-2024-35970,
    CVE-2024-35817, CVE-2024-35973, CVE-2024-40945, CVE-2024-42153, CVE-2024-36964, CVE-2024-42090,
    CVE-2024-38552, CVE-2024-39467, CVE-2024-26961, CVE-2024-38615, CVE-2024-38618, CVE-2024-40988,
    CVE-2024-38605, CVE-2024-41004, CVE-2024-26966, CVE-2024-42096, CVE-2024-26996, CVE-2024-36969,
    CVE-2024-36489, CVE-2024-40957, CVE-2024-36974, CVE-2024-39502, CVE-2024-26976, CVE-2024-27399,
    CVE-2024-36905, CVE-2024-35958, CVE-2024-35927, CVE-2024-27001, CVE-2024-39487, CVE-2024-41034,
    CVE-2024-36904, CVE-2024-41055, CVE-2024-38550, CVE-2024-38567, CVE-2024-38586, CVE-2024-40916,
    CVE-2024-38589, CVE-2023-52884, CVE-2024-26810, CVE-2024-35989, CVE-2024-36894, CVE-2024-39471,
    CVE-2024-35900, CVE-2024-42097, CVE-2024-36959, CVE-2024-26931, CVE-2024-40934, CVE-2024-36947,
    CVE-2024-34777, CVE-2024-27018, CVE-2024-39499, CVE-2024-36906, CVE-2024-35984, CVE-2024-39500,
    CVE-2024-26965, CVE-2024-26921, CVE-2024-27013, CVE-2024-39509, CVE-2024-27008, CVE-2024-36916,
    CVE-2024-40942, CVE-2024-35978, CVE-2024-26969, CVE-2024-26964, CVE-2024-35879, CVE-2024-36016,
    CVE-2024-26629, CVE-2024-42236, CVE-2024-40943, CVE-2024-36902, CVE-2024-42247, CVE-2024-36006,
    CVE-2024-36014, CVE-2024-26955, CVE-2024-39277, CVE-2024-39506, CVE-2024-35936, CVE-2024-26950,
    CVE-2024-35938, CVE-2024-41035, CVE-2024-42140, CVE-2024-36971, CVE-2024-35910, CVE-2024-34027,
    CVE-2024-35933, CVE-2024-35886, CVE-2024-39501, CVE-2024-42109, CVE-2024-42157, CVE-2024-35905,
    CVE-2024-41007, CVE-2024-40912, CVE-2024-26984, CVE-2024-35915, CVE-2024-35934, CVE-2024-38633,
    CVE-2024-26952, CVE-2024-27017, CVE-2024-38627, CVE-2024-42070, CVE-2024-41046, CVE-2024-35821,
    CVE-2024-35815, CVE-2024-36978, CVE-2024-36967, CVE-2023-52752, CVE-2024-38583, CVE-2024-38578,
    CVE-2024-26926, CVE-2023-52699, CVE-2024-36952, CVE-2024-38600, CVE-2024-42102, CVE-2024-38559,
    CVE-2024-38637, CVE-2024-42082, CVE-2023-52488, CVE-2024-36032, CVE-2024-35950, CVE-2024-35930,
    CVE-2024-38780, CVE-2024-40995, CVE-2024-36004, CVE-2024-26956, CVE-2024-35896, CVE-2024-26994,
    CVE-2024-38624, CVE-2024-39480, CVE-2023-52882, CVE-2024-35912, CVE-2024-36015, CVE-2024-27019,
    CVE-2024-40983, CVE-2023-52760, CVE-2024-39503, CVE-2024-36957, CVE-2024-26980, CVE-2024-40908,
    CVE-2024-40958, CVE-2024-35902, CVE-2024-42087, CVE-2024-36933, CVE-2024-38635, CVE-2024-26988,
    CVE-2024-36941, CVE-2024-26970, CVE-2024-36005, CVE-2024-36029, CVE-2024-36008, CVE-2024-42244,
    CVE-2024-40967, CVE-2023-52585, CVE-2024-26951, CVE-2024-39475, CVE-2024-35922, CVE-2024-36901,
    CVE-2024-40901, CVE-2024-36031, CVE-2024-41000, CVE-2024-40929, CVE-2024-40994, CVE-2024-42084,
    CVE-2024-38547, CVE-2024-26937, CVE-2024-40984, CVE-2024-27000, CVE-2024-35785, CVE-2024-35849,
    CVE-2024-42119, CVE-2024-35947, CVE-2024-39505, CVE-2024-42092, CVE-2024-26811, CVE-2024-35935,
    CVE-2024-36946, CVE-2024-40990, CVE-2024-26981, CVE-2024-38596, CVE-2024-40976, CVE-2024-36880)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7019-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42154");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1035-xilinx-zynqmp");
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
      'xilinx-zynqmp': '5.15.0-1035'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7019-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-38096', 'CVE-2022-48772', 'CVE-2022-48808', 'CVE-2023-52488', 'CVE-2023-52585', 'CVE-2023-52629', 'CVE-2023-52699', 'CVE-2023-52752', 'CVE-2023-52760', 'CVE-2023-52880', 'CVE-2023-52882', 'CVE-2023-52884', 'CVE-2023-52887', 'CVE-2024-23307', 'CVE-2024-23848', 'CVE-2024-24857', 'CVE-2024-24858', 'CVE-2024-24859', 'CVE-2024-24861', 'CVE-2024-25739', 'CVE-2024-25741', 'CVE-2024-25742', 'CVE-2024-26629', 'CVE-2024-26642', 'CVE-2024-26654', 'CVE-2024-26680', 'CVE-2024-26687', 'CVE-2024-26810', 'CVE-2024-26811', 'CVE-2024-26812', 'CVE-2024-26813', 'CVE-2024-26814', 'CVE-2024-26817', 'CVE-2024-26828', 'CVE-2024-26830', 'CVE-2024-26886', 'CVE-2024-26900', 'CVE-2024-26921', 'CVE-2024-26922', 'CVE-2024-26923', 'CVE-2024-26925', 'CVE-2024-26926', 'CVE-2024-26929', 'CVE-2024-26931', 'CVE-2024-26934', 'CVE-2024-26935', 'CVE-2024-26936', 'CVE-2024-26937', 'CVE-2024-26950', 'CVE-2024-26951', 'CVE-2024-26952', 'CVE-2024-26955', 'CVE-2024-26956', 'CVE-2024-26957', 'CVE-2024-26958', 'CVE-2024-26960', 'CVE-2024-26961', 'CVE-2024-26964', 'CVE-2024-26965', 'CVE-2024-26966', 'CVE-2024-26969', 'CVE-2024-26970', 'CVE-2024-26973', 'CVE-2024-26974', 'CVE-2024-26976', 'CVE-2024-26977', 'CVE-2024-26980', 'CVE-2024-26981', 'CVE-2024-26984', 'CVE-2024-26988', 'CVE-2024-26989', 'CVE-2024-26993', 'CVE-2024-26994', 'CVE-2024-26996', 'CVE-2024-26999', 'CVE-2024-27000', 'CVE-2024-27001', 'CVE-2024-27004', 'CVE-2024-27008', 'CVE-2024-27009', 'CVE-2024-27013', 'CVE-2024-27015', 'CVE-2024-27016', 'CVE-2024-27017', 'CVE-2024-27018', 'CVE-2024-27019', 'CVE-2024-27020', 'CVE-2024-27059', 'CVE-2024-27393', 'CVE-2024-27395', 'CVE-2024-27396', 'CVE-2024-27398', 'CVE-2024-27399', 'CVE-2024-27401', 'CVE-2024-27437', 'CVE-2024-31076', 'CVE-2024-33621', 'CVE-2024-33847', 'CVE-2024-34027', 'CVE-2024-34777', 'CVE-2024-35247', 'CVE-2024-35785', 'CVE-2024-35789', 'CVE-2024-35791', 'CVE-2024-35796', 'CVE-2024-35804', 'CVE-2024-35805', 'CVE-2024-35806', 'CVE-2024-35807', 'CVE-2024-35809', 'CVE-2024-35813', 'CVE-2024-35815', 'CVE-2024-35817', 'CVE-2024-35819', 'CVE-2024-35821', 'CVE-2024-35822', 'CVE-2024-35823', 'CVE-2024-35825', 'CVE-2024-35847', 'CVE-2024-35848', 'CVE-2024-35849', 'CVE-2024-35851', 'CVE-2024-35852', 'CVE-2024-35853', 'CVE-2024-35854', 'CVE-2024-35855', 'CVE-2024-35857', 'CVE-2024-35871', 'CVE-2024-35872', 'CVE-2024-35877', 'CVE-2024-35879', 'CVE-2024-35884', 'CVE-2024-35885', 'CVE-2024-35886', 'CVE-2024-35888', 'CVE-2024-35890', 'CVE-2024-35893', 'CVE-2024-35895', 'CVE-2024-35896', 'CVE-2024-35897', 'CVE-2024-35898', 'CVE-2024-35899', 'CVE-2024-35900', 'CVE-2024-35902', 'CVE-2024-35905', 'CVE-2024-35907', 'CVE-2024-35910', 'CVE-2024-35912', 'CVE-2024-35915', 'CVE-2024-35922', 'CVE-2024-35925', 'CVE-2024-35927', 'CVE-2024-35930', 'CVE-2024-35933', 'CVE-2024-35934', 'CVE-2024-35935', 'CVE-2024-35936', 'CVE-2024-35938', 'CVE-2024-35940', 'CVE-2024-35944', 'CVE-2024-35947', 'CVE-2024-35950', 'CVE-2024-35955', 'CVE-2024-35958', 'CVE-2024-35960', 'CVE-2024-35969', 'CVE-2024-35970', 'CVE-2024-35973', 'CVE-2024-35976', 'CVE-2024-35978', 'CVE-2024-35982', 'CVE-2024-35984', 'CVE-2024-35988', 'CVE-2024-35989', 'CVE-2024-35990', 'CVE-2024-35997', 'CVE-2024-36004', 'CVE-2024-36005', 'CVE-2024-36006', 'CVE-2024-36007', 'CVE-2024-36008', 'CVE-2024-36014', 'CVE-2024-36015', 'CVE-2024-36016', 'CVE-2024-36017', 'CVE-2024-36020', 'CVE-2024-36025', 'CVE-2024-36029', 'CVE-2024-36031', 'CVE-2024-36032', 'CVE-2024-36270', 'CVE-2024-36286', 'CVE-2024-36489', 'CVE-2024-36880', 'CVE-2024-36883', 'CVE-2024-36886', 'CVE-2024-36889', 'CVE-2024-36894', 'CVE-2024-36901', 'CVE-2024-36902', 'CVE-2024-36904', 'CVE-2024-36905', 'CVE-2024-36906', 'CVE-2024-36916', 'CVE-2024-36919', 'CVE-2024-36928', 'CVE-2024-36929', 'CVE-2024-36931', 'CVE-2024-36933', 'CVE-2024-36934', 'CVE-2024-36937', 'CVE-2024-36938', 'CVE-2024-36939', 'CVE-2024-36940', 'CVE-2024-36941', 'CVE-2024-36946', 'CVE-2024-36947', 'CVE-2024-36950', 'CVE-2024-36952', 'CVE-2024-36953', 'CVE-2024-36954', 'CVE-2024-36955', 'CVE-2024-36957', 'CVE-2024-36959', 'CVE-2024-36960', 'CVE-2024-36964', 'CVE-2024-36965', 'CVE-2024-36967', 'CVE-2024-36969', 'CVE-2024-36971', 'CVE-2024-36972', 'CVE-2024-36974', 'CVE-2024-36975', 'CVE-2024-36978', 'CVE-2024-37078', 'CVE-2024-37356', 'CVE-2024-38546', 'CVE-2024-38547', 'CVE-2024-38548', 'CVE-2024-38549', 'CVE-2024-38550', 'CVE-2024-38552', 'CVE-2024-38555', 'CVE-2024-38558', 'CVE-2024-38559', 'CVE-2024-38560', 'CVE-2024-38565', 'CVE-2024-38567', 'CVE-2024-38571', 'CVE-2024-38573', 'CVE-2024-38578', 'CVE-2024-38579', 'CVE-2024-38580', 'CVE-2024-38582', 'CVE-2024-38583', 'CVE-2024-38586', 'CVE-2024-38588', 'CVE-2024-38589', 'CVE-2024-38590', 'CVE-2024-38591', 'CVE-2024-38596', 'CVE-2024-38597', 'CVE-2024-38598', 'CVE-2024-38599', 'CVE-2024-38600', 'CVE-2024-38601', 'CVE-2024-38605', 'CVE-2024-38607', 'CVE-2024-38610', 'CVE-2024-38612', 'CVE-2024-38613', 'CVE-2024-38615', 'CVE-2024-38618', 'CVE-2024-38619', 'CVE-2024-38621', 'CVE-2024-38623', 'CVE-2024-38624', 'CVE-2024-38627', 'CVE-2024-38633', 'CVE-2024-38634', 'CVE-2024-38635', 'CVE-2024-38637', 'CVE-2024-38659', 'CVE-2024-38661', 'CVE-2024-38780', 'CVE-2024-39276', 'CVE-2024-39277', 'CVE-2024-39292', 'CVE-2024-39301', 'CVE-2024-39466', 'CVE-2024-39467', 'CVE-2024-39468', 'CVE-2024-39469', 'CVE-2024-39471', 'CVE-2024-39475', 'CVE-2024-39480', 'CVE-2024-39482', 'CVE-2024-39484', 'CVE-2024-39487', 'CVE-2024-39488', 'CVE-2024-39489', 'CVE-2024-39490', 'CVE-2024-39495', 'CVE-2024-39499', 'CVE-2024-39500', 'CVE-2024-39501', 'CVE-2024-39502', 'CVE-2024-39503', 'CVE-2024-39505', 'CVE-2024-39506', 'CVE-2024-39507', 'CVE-2024-39509', 'CVE-2024-40901', 'CVE-2024-40902', 'CVE-2024-40904', 'CVE-2024-40905', 'CVE-2024-40908', 'CVE-2024-40911', 'CVE-2024-40912', 'CVE-2024-40914', 'CVE-2024-40916', 'CVE-2024-40927', 'CVE-2024-40929', 'CVE-2024-40931', 'CVE-2024-40932', 'CVE-2024-40934', 'CVE-2024-40937', 'CVE-2024-40941', 'CVE-2024-40942', 'CVE-2024-40943', 'CVE-2024-40945', 'CVE-2024-40954', 'CVE-2024-40956', 'CVE-2024-40957', 'CVE-2024-40958', 'CVE-2024-40959', 'CVE-2024-40960', 'CVE-2024-40961', 'CVE-2024-40963', 'CVE-2024-40967', 'CVE-2024-40968', 'CVE-2024-40970', 'CVE-2024-40971', 'CVE-2024-40974', 'CVE-2024-40976', 'CVE-2024-40978', 'CVE-2024-40980', 'CVE-2024-40981', 'CVE-2024-40983', 'CVE-2024-40984', 'CVE-2024-40987', 'CVE-2024-40988', 'CVE-2024-40990', 'CVE-2024-40994', 'CVE-2024-40995', 'CVE-2024-41000', 'CVE-2024-41002', 'CVE-2024-41004', 'CVE-2024-41005', 'CVE-2024-41006', 'CVE-2024-41007', 'CVE-2024-41027', 'CVE-2024-41034', 'CVE-2024-41035', 'CVE-2024-41040', 'CVE-2024-41041', 'CVE-2024-41044', 'CVE-2024-41046', 'CVE-2024-41047', 'CVE-2024-41048', 'CVE-2024-41049', 'CVE-2024-41055', 'CVE-2024-41087', 'CVE-2024-41089', 'CVE-2024-41092', 'CVE-2024-41093', 'CVE-2024-41095', 'CVE-2024-41097', 'CVE-2024-42068', 'CVE-2024-42070', 'CVE-2024-42076', 'CVE-2024-42077', 'CVE-2024-42080', 'CVE-2024-42082', 'CVE-2024-42084', 'CVE-2024-42085', 'CVE-2024-42086', 'CVE-2024-42087', 'CVE-2024-42089', 'CVE-2024-42090', 'CVE-2024-42092', 'CVE-2024-42093', 'CVE-2024-42094', 'CVE-2024-42095', 'CVE-2024-42096', 'CVE-2024-42097', 'CVE-2024-42098', 'CVE-2024-42101', 'CVE-2024-42102', 'CVE-2024-42104', 'CVE-2024-42105', 'CVE-2024-42106', 'CVE-2024-42109', 'CVE-2024-42115', 'CVE-2024-42119', 'CVE-2024-42120', 'CVE-2024-42121', 'CVE-2024-42124', 'CVE-2024-42127', 'CVE-2024-42130', 'CVE-2024-42131', 'CVE-2024-42137', 'CVE-2024-42140', 'CVE-2024-42145', 'CVE-2024-42148', 'CVE-2024-42152', 'CVE-2024-42153', 'CVE-2024-42154', 'CVE-2024-42157', 'CVE-2024-42161', 'CVE-2024-42223', 'CVE-2024-42224', 'CVE-2024-42225', 'CVE-2024-42229', 'CVE-2024-42232', 'CVE-2024-42236', 'CVE-2024-42240', 'CVE-2024-42244', 'CVE-2024-42247');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7019-1');
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
