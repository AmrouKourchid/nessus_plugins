#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7421-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233966);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id(
    "CVE-2022-49034",
    "CVE-2024-26928",
    "CVE-2024-35864",
    "CVE-2024-36476",
    "CVE-2024-36899",
    "CVE-2024-42069",
    "CVE-2024-42315",
    "CVE-2024-43098",
    "CVE-2024-43900",
    "CVE-2024-44938",
    "CVE-2024-45828",
    "CVE-2024-46784",
    "CVE-2024-46809",
    "CVE-2024-46841",
    "CVE-2024-46871",
    "CVE-2024-47143",
    "CVE-2024-47408",
    "CVE-2024-47707",
    "CVE-2024-47730",
    "CVE-2024-48881",
    "CVE-2024-49571",
    "CVE-2024-49925",
    "CVE-2024-49950",
    "CVE-2024-49974",
    "CVE-2024-49996",
    "CVE-2024-49998",
    "CVE-2024-50051",
    "CVE-2024-50055",
    "CVE-2024-50121",
    "CVE-2024-50242",
    "CVE-2024-50275",
    "CVE-2024-50283",
    "CVE-2024-50304",
    "CVE-2024-52332",
    "CVE-2024-53096",
    "CVE-2024-53099",
    "CVE-2024-53112",
    "CVE-2024-53113",
    "CVE-2024-53119",
    "CVE-2024-53120",
    "CVE-2024-53121",
    "CVE-2024-53122",
    "CVE-2024-53124",
    "CVE-2024-53125",
    "CVE-2024-53127",
    "CVE-2024-53129",
    "CVE-2024-53130",
    "CVE-2024-53131",
    "CVE-2024-53135",
    "CVE-2024-53136",
    "CVE-2024-53138",
    "CVE-2024-53140",
    "CVE-2024-53142",
    "CVE-2024-53145",
    "CVE-2024-53146",
    "CVE-2024-53148",
    "CVE-2024-53150",
    "CVE-2024-53151",
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
    "CVE-2024-53180",
    "CVE-2024-53181",
    "CVE-2024-53183",
    "CVE-2024-53184",
    "CVE-2024-53194",
    "CVE-2024-53197",
    "CVE-2024-53198",
    "CVE-2024-53206",
    "CVE-2024-53214",
    "CVE-2024-53215",
    "CVE-2024-53217",
    "CVE-2024-53226",
    "CVE-2024-53227",
    "CVE-2024-53237",
    "CVE-2024-53239",
    "CVE-2024-53680",
    "CVE-2024-53685",
    "CVE-2024-53690",
    "CVE-2024-55881",
    "CVE-2024-55916",
    "CVE-2024-56369",
    "CVE-2024-56531",
    "CVE-2024-56532",
    "CVE-2024-56533",
    "CVE-2024-56539",
    "CVE-2024-56548",
    "CVE-2024-56558",
    "CVE-2024-56562",
    "CVE-2024-56567",
    "CVE-2024-56568",
    "CVE-2024-56569",
    "CVE-2024-56570",
    "CVE-2024-56572",
    "CVE-2024-56574",
    "CVE-2024-56575",
    "CVE-2024-56576",
    "CVE-2024-56578",
    "CVE-2024-56581",
    "CVE-2024-56586",
    "CVE-2024-56587",
    "CVE-2024-56589",
    "CVE-2024-56590",
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
    "CVE-2024-56610",
    "CVE-2024-56614",
    "CVE-2024-56615",
    "CVE-2024-56616",
    "CVE-2024-56619",
    "CVE-2024-56622",
    "CVE-2024-56623",
    "CVE-2024-56625",
    "CVE-2024-56626",
    "CVE-2024-56627",
    "CVE-2024-56629",
    "CVE-2024-56630",
    "CVE-2024-56631",
    "CVE-2024-56633",
    "CVE-2024-56634",
    "CVE-2024-56636",
    "CVE-2024-56637",
    "CVE-2024-56640",
    "CVE-2024-56642",
    "CVE-2024-56643",
    "CVE-2024-56644",
    "CVE-2024-56645",
    "CVE-2024-56648",
    "CVE-2024-56650",
    "CVE-2024-56658",
    "CVE-2024-56659",
    "CVE-2024-56662",
    "CVE-2024-56670",
    "CVE-2024-56678",
    "CVE-2024-56679",
    "CVE-2024-56681",
    "CVE-2024-56688",
    "CVE-2024-56690",
    "CVE-2024-56691",
    "CVE-2024-56693",
    "CVE-2024-56694",
    "CVE-2024-56698",
    "CVE-2024-56700",
    "CVE-2024-56701",
    "CVE-2024-56704",
    "CVE-2024-56705",
    "CVE-2024-56708",
    "CVE-2024-56715",
    "CVE-2024-56716",
    "CVE-2024-56720",
    "CVE-2024-56723",
    "CVE-2024-56724",
    "CVE-2024-56726",
    "CVE-2024-56728",
    "CVE-2024-56739",
    "CVE-2024-56745",
    "CVE-2024-56746",
    "CVE-2024-56747",
    "CVE-2024-56748",
    "CVE-2024-56754",
    "CVE-2024-56756",
    "CVE-2024-56759",
    "CVE-2024-56763",
    "CVE-2024-56767",
    "CVE-2024-56769",
    "CVE-2024-56770",
    "CVE-2024-56774",
    "CVE-2024-56776",
    "CVE-2024-56777",
    "CVE-2024-56778",
    "CVE-2024-56779",
    "CVE-2024-56780",
    "CVE-2024-56781",
    "CVE-2024-56785",
    "CVE-2024-56787",
    "CVE-2024-57791",
    "CVE-2024-57792",
    "CVE-2024-57798",
    "CVE-2024-57802",
    "CVE-2024-57807",
    "CVE-2024-57838",
    "CVE-2024-57841",
    "CVE-2024-57849",
    "CVE-2024-57850",
    "CVE-2024-57874",
    "CVE-2024-57882",
    "CVE-2024-57884",
    "CVE-2024-57889",
    "CVE-2024-57890",
    "CVE-2024-57892",
    "CVE-2024-57896",
    "CVE-2024-57897",
    "CVE-2024-57900",
    "CVE-2024-57901",
    "CVE-2024-57902",
    "CVE-2024-57903",
    "CVE-2024-57904",
    "CVE-2024-57906",
    "CVE-2024-57907",
    "CVE-2024-57908",
    "CVE-2024-57910",
    "CVE-2024-57911",
    "CVE-2024-57912",
    "CVE-2024-57913",
    "CVE-2024-57917",
    "CVE-2024-57922",
    "CVE-2024-57925",
    "CVE-2024-57929",
    "CVE-2024-57931",
    "CVE-2024-57938",
    "CVE-2024-57939",
    "CVE-2024-57940",
    "CVE-2024-57946",
    "CVE-2024-57948",
    "CVE-2024-57951",
    "CVE-2024-58087",
    "CVE-2025-21631",
    "CVE-2025-21636",
    "CVE-2025-21637",
    "CVE-2025-21638",
    "CVE-2025-21639",
    "CVE-2025-21640",
    "CVE-2025-21646",
    "CVE-2025-21648",
    "CVE-2025-21653",
    "CVE-2025-21664",
    "CVE-2025-21665",
    "CVE-2025-21666",
    "CVE-2025-21669",
    "CVE-2025-21678",
    "CVE-2025-21680",
    "CVE-2025-21683",
    "CVE-2025-21687",
    "CVE-2025-21689",
    "CVE-2025-21690",
    "CVE-2025-21692",
    "CVE-2025-21694",
    "CVE-2025-21697",
    "CVE-2025-21699"
  );
  script_xref(name:"USN", value:"7421-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/30");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (Azure) vulnerabilities (USN-7421-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-7421-1 advisory.

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

    - ACPI drivers;

    - Drivers core;

    - RAM backed block device driver;

    - Virtio block driver;

    - Data acquisition framework and drivers;

    - Hardware crypto device drivers;

    - DMA engine subsystem;

    - EDAC drivers;

    - ARM SCPI message protocol;

    - GPIO subsystem;

    - GPU drivers;

    - HID subsystem;

    - Microsoft Hyper-V drivers;

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

    - Microsoft Azure Network Adapter (MANA) driver;

    - NVME drivers;

    - PCI subsystem;

    - Pin controllers subsystem;

    - x86 platform drivers;

    - Power supply drivers;

    - Real Time Clock drivers;

    - SCSI subsystem;

    - SuperH / SH-Mobile drivers;

    - i.MX SoC drivers;

    - QCOM SoC drivers;

    - SPI subsystem;

    - Media staging drivers;

    - UFS subsystem;

    - DesignWare USB3 driver;

    - USB Gadget drivers;

    - USB Serial drivers;

    - USB Type-C Port Controller Manager driver;

    - VFIO drivers;

    - Framebuffer layer;

    - Xen hypervisor drivers;

    - AFS file system;

    - BTRFS file system;

    - Ceph distributed file system;

    - File systems infrastructure;

    - F2FS file system;

    - GFS2 file system;

    - JFFS2 file system;

    - JFS file system;

    - Network file system (NFS) client;

    - Network file system (NFS) server daemon;

    - NILFS2 file system;

    - NTFS3 file system;

    - Overlay file system;

    - Proc file system;

    - Diskquota system;

    - SMB network file system;

    - UBI file system;

    - Timer subsystem;

    - VLANs driver;

    - LAPB network protocol;

    - Network namespace;

    - Kernel init infrastructure;

    - BPF subsystem;

    - Kernel CPU control infrastructure;

    - DMA mapping infrastructure;

    - KCSAN framework;

    - Tracing infrastructure;

    - Memory management;

    - 9P file system network protocol;

    - Bluetooth subsystem;

    - CAN network layer;

    - Networking core;

    - DCCP (Datagram Congestion Control Protocol);

    - Distributed Switch Architecture;

    - HSR network protocol;

    - IEEE802154.4 network protocol;

    - IPv4 networking;

    - IPv6 networking;

    - IEEE 802.15.4 subsystem;

    - Multipath TCP;

    - Netfilter;

    - Netlink;

    - NET/ROM layer;

    - Packet sockets;

    - Network traffic control;

    - SCTP protocol;

    - SMC sockets;

    - Sun RPC protocol;

    - TIPC protocol;

    - VMware vSockets driver;

    - eXpress Data Path;

    - SELinux security module;

    - ALSA framework;

    - USB sound devices; (CVE-2024-53680, CVE-2024-53148, CVE-2024-47408, CVE-2024-53122, CVE-2024-56691,
    CVE-2024-56763, CVE-2024-53227, CVE-2024-56369, CVE-2024-50275, CVE-2024-57892, CVE-2024-53142,
    CVE-2024-56693, CVE-2024-56658, CVE-2024-57882, CVE-2024-56606, CVE-2024-46871, CVE-2024-57907,
    CVE-2024-56642, CVE-2025-21631, CVE-2024-57908, CVE-2024-57890, CVE-2024-53194, CVE-2024-57913,
    CVE-2024-56659, CVE-2024-56643, CVE-2024-56590, CVE-2024-56754, CVE-2025-21678, CVE-2024-56678,
    CVE-2024-49974, CVE-2024-56614, CVE-2024-53124, CVE-2022-49034, CVE-2024-49996, CVE-2024-47143,
    CVE-2024-50055, CVE-2024-53184, CVE-2024-56681, CVE-2025-21683, CVE-2024-57922, CVE-2024-56532,
    CVE-2024-53161, CVE-2024-57791, CVE-2025-21664, CVE-2024-53206, CVE-2024-56589, CVE-2024-57902,
    CVE-2024-56633, CVE-2024-53140, CVE-2024-56627, CVE-2024-57912, CVE-2024-55916, CVE-2024-56594,
    CVE-2025-21690, CVE-2024-56602, CVE-2024-49998, CVE-2024-53171, CVE-2024-53174, CVE-2024-53172,
    CVE-2024-56701, CVE-2024-52332, CVE-2024-57948, CVE-2024-57802, CVE-2024-53237, CVE-2024-50304,
    CVE-2024-56568, CVE-2024-49571, CVE-2025-21636, CVE-2024-57906, CVE-2024-57939, CVE-2024-57931,
    CVE-2024-56698, CVE-2024-56781, CVE-2024-50051, CVE-2024-57904, CVE-2024-43900, CVE-2024-53146,
    CVE-2024-53217, CVE-2024-56548, CVE-2024-56616, CVE-2024-53155, CVE-2024-57889, CVE-2025-21666,
    CVE-2024-53165, CVE-2024-56615, CVE-2024-56629, CVE-2024-53197, CVE-2024-47707, CVE-2024-53690,
    CVE-2024-56572, CVE-2024-56748, CVE-2024-45828, CVE-2024-53156, CVE-2024-53150, CVE-2024-53181,
    CVE-2024-56625, CVE-2024-57938, CVE-2024-56708, CVE-2024-57925, CVE-2024-56644, CVE-2024-50121,
    CVE-2024-53125, CVE-2025-21697, CVE-2024-53180, CVE-2024-53129, CVE-2024-57910, CVE-2024-57951,
    CVE-2024-46841, CVE-2024-56670, CVE-2024-56759, CVE-2024-56662, CVE-2024-56769, CVE-2024-56623,
    CVE-2024-26928, CVE-2024-56777, CVE-2024-53183, CVE-2024-53135, CVE-2024-57884, CVE-2024-56778,
    CVE-2024-56774, CVE-2024-53145, CVE-2024-56574, CVE-2025-21687, CVE-2024-53215, CVE-2024-57807,
    CVE-2024-56704, CVE-2025-21665, CVE-2024-56637, CVE-2024-56601, CVE-2024-56650, CVE-2024-57911,
    CVE-2024-57900, CVE-2024-56716, CVE-2025-21689, CVE-2024-56597, CVE-2024-56570, CVE-2024-56779,
    CVE-2025-21653, CVE-2024-56747, CVE-2024-56622, CVE-2024-44938, CVE-2025-21639, CVE-2024-56578,
    CVE-2024-56728, CVE-2024-53151, CVE-2024-56723, CVE-2024-53158, CVE-2024-56645, CVE-2024-56586,
    CVE-2024-50242, CVE-2024-53099, CVE-2024-56726, CVE-2024-35864, CVE-2024-56739, CVE-2024-56785,
    CVE-2024-46784, CVE-2024-56539, CVE-2024-57838, CVE-2024-57850, CVE-2024-56593, CVE-2024-53239,
    CVE-2024-53173, CVE-2024-57901, CVE-2024-56595, CVE-2024-53138, CVE-2024-56724, CVE-2025-21699,
    CVE-2025-21694, CVE-2024-49925, CVE-2024-53113, CVE-2024-56603, CVE-2024-53119, CVE-2024-53121,
    CVE-2024-48881, CVE-2024-56745, CVE-2025-21637, CVE-2025-21640, CVE-2024-50283, CVE-2024-42069,
    CVE-2024-53214, CVE-2024-56605, CVE-2024-53226, CVE-2024-56640, CVE-2024-57929, CVE-2024-56575,
    CVE-2024-56700, CVE-2024-57903, CVE-2024-56776, CVE-2024-56679, CVE-2024-56648, CVE-2025-21692,
    CVE-2024-56558, CVE-2024-53198, CVE-2024-56787, CVE-2024-56600, CVE-2024-56576, CVE-2024-53120,
    CVE-2024-56531, CVE-2024-56567, CVE-2025-21680, CVE-2024-56780, CVE-2024-56631, CVE-2024-56694,
    CVE-2024-43098, CVE-2024-53127, CVE-2024-56626, CVE-2024-56598, CVE-2024-47730, CVE-2024-53130,
    CVE-2024-56619, CVE-2024-56569, CVE-2024-57917, CVE-2024-56767, CVE-2024-56587, CVE-2024-56690,
    CVE-2024-53112, CVE-2024-57946, CVE-2025-21638, CVE-2024-56770, CVE-2024-56596, CVE-2024-56720,
    CVE-2024-36476, CVE-2024-56533, CVE-2025-21648, CVE-2024-56705, CVE-2025-21646, CVE-2024-57897,
    CVE-2024-57798, CVE-2024-56636, CVE-2024-53096, CVE-2024-56715, CVE-2024-58087, CVE-2024-57841,
    CVE-2024-46809, CVE-2024-56634, CVE-2024-53685, CVE-2024-56756, CVE-2024-56562, CVE-2024-57874,
    CVE-2024-56581, CVE-2024-56630, CVE-2025-21669, CVE-2024-57896, CVE-2024-55881, CVE-2024-53157,
    CVE-2024-56688, CVE-2024-57849, CVE-2024-53131, CVE-2024-56610, CVE-2024-57940, CVE-2024-57792,
    CVE-2024-36899, CVE-2024-53136, CVE-2024-42315, CVE-2024-56746, CVE-2024-49950)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7421-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-58087");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1086-azure-fde");
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
if (! ('20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '20.04': {
    '5.15.0': {
      'azure-fde': '5.15.0-1086'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7421-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-49034', 'CVE-2024-26928', 'CVE-2024-35864', 'CVE-2024-36476', 'CVE-2024-36899', 'CVE-2024-42069', 'CVE-2024-42315', 'CVE-2024-43098', 'CVE-2024-43900', 'CVE-2024-44938', 'CVE-2024-45828', 'CVE-2024-46784', 'CVE-2024-46809', 'CVE-2024-46841', 'CVE-2024-46871', 'CVE-2024-47143', 'CVE-2024-47408', 'CVE-2024-47707', 'CVE-2024-47730', 'CVE-2024-48881', 'CVE-2024-49571', 'CVE-2024-49925', 'CVE-2024-49950', 'CVE-2024-49974', 'CVE-2024-49996', 'CVE-2024-49998', 'CVE-2024-50051', 'CVE-2024-50055', 'CVE-2024-50121', 'CVE-2024-50242', 'CVE-2024-50275', 'CVE-2024-50283', 'CVE-2024-50304', 'CVE-2024-52332', 'CVE-2024-53096', 'CVE-2024-53099', 'CVE-2024-53112', 'CVE-2024-53113', 'CVE-2024-53119', 'CVE-2024-53120', 'CVE-2024-53121', 'CVE-2024-53122', 'CVE-2024-53124', 'CVE-2024-53125', 'CVE-2024-53127', 'CVE-2024-53129', 'CVE-2024-53130', 'CVE-2024-53131', 'CVE-2024-53135', 'CVE-2024-53136', 'CVE-2024-53138', 'CVE-2024-53140', 'CVE-2024-53142', 'CVE-2024-53145', 'CVE-2024-53146', 'CVE-2024-53148', 'CVE-2024-53150', 'CVE-2024-53151', 'CVE-2024-53155', 'CVE-2024-53156', 'CVE-2024-53157', 'CVE-2024-53158', 'CVE-2024-53161', 'CVE-2024-53165', 'CVE-2024-53171', 'CVE-2024-53172', 'CVE-2024-53173', 'CVE-2024-53174', 'CVE-2024-53180', 'CVE-2024-53181', 'CVE-2024-53183', 'CVE-2024-53184', 'CVE-2024-53194', 'CVE-2024-53197', 'CVE-2024-53198', 'CVE-2024-53206', 'CVE-2024-53214', 'CVE-2024-53215', 'CVE-2024-53217', 'CVE-2024-53226', 'CVE-2024-53227', 'CVE-2024-53237', 'CVE-2024-53239', 'CVE-2024-53680', 'CVE-2024-53685', 'CVE-2024-53690', 'CVE-2024-55881', 'CVE-2024-55916', 'CVE-2024-56369', 'CVE-2024-56531', 'CVE-2024-56532', 'CVE-2024-56533', 'CVE-2024-56539', 'CVE-2024-56548', 'CVE-2024-56558', 'CVE-2024-56562', 'CVE-2024-56567', 'CVE-2024-56568', 'CVE-2024-56569', 'CVE-2024-56570', 'CVE-2024-56572', 'CVE-2024-56574', 'CVE-2024-56575', 'CVE-2024-56576', 'CVE-2024-56578', 'CVE-2024-56581', 'CVE-2024-56586', 'CVE-2024-56587', 'CVE-2024-56589', 'CVE-2024-56590', 'CVE-2024-56593', 'CVE-2024-56594', 'CVE-2024-56595', 'CVE-2024-56596', 'CVE-2024-56597', 'CVE-2024-56598', 'CVE-2024-56600', 'CVE-2024-56601', 'CVE-2024-56602', 'CVE-2024-56603', 'CVE-2024-56605', 'CVE-2024-56606', 'CVE-2024-56610', 'CVE-2024-56614', 'CVE-2024-56615', 'CVE-2024-56616', 'CVE-2024-56619', 'CVE-2024-56622', 'CVE-2024-56623', 'CVE-2024-56625', 'CVE-2024-56626', 'CVE-2024-56627', 'CVE-2024-56629', 'CVE-2024-56630', 'CVE-2024-56631', 'CVE-2024-56633', 'CVE-2024-56634', 'CVE-2024-56636', 'CVE-2024-56637', 'CVE-2024-56640', 'CVE-2024-56642', 'CVE-2024-56643', 'CVE-2024-56644', 'CVE-2024-56645', 'CVE-2024-56648', 'CVE-2024-56650', 'CVE-2024-56658', 'CVE-2024-56659', 'CVE-2024-56662', 'CVE-2024-56670', 'CVE-2024-56678', 'CVE-2024-56679', 'CVE-2024-56681', 'CVE-2024-56688', 'CVE-2024-56690', 'CVE-2024-56691', 'CVE-2024-56693', 'CVE-2024-56694', 'CVE-2024-56698', 'CVE-2024-56700', 'CVE-2024-56701', 'CVE-2024-56704', 'CVE-2024-56705', 'CVE-2024-56708', 'CVE-2024-56715', 'CVE-2024-56716', 'CVE-2024-56720', 'CVE-2024-56723', 'CVE-2024-56724', 'CVE-2024-56726', 'CVE-2024-56728', 'CVE-2024-56739', 'CVE-2024-56745', 'CVE-2024-56746', 'CVE-2024-56747', 'CVE-2024-56748', 'CVE-2024-56754', 'CVE-2024-56756', 'CVE-2024-56759', 'CVE-2024-56763', 'CVE-2024-56767', 'CVE-2024-56769', 'CVE-2024-56770', 'CVE-2024-56774', 'CVE-2024-56776', 'CVE-2024-56777', 'CVE-2024-56778', 'CVE-2024-56779', 'CVE-2024-56780', 'CVE-2024-56781', 'CVE-2024-56785', 'CVE-2024-56787', 'CVE-2024-57791', 'CVE-2024-57792', 'CVE-2024-57798', 'CVE-2024-57802', 'CVE-2024-57807', 'CVE-2024-57838', 'CVE-2024-57841', 'CVE-2024-57849', 'CVE-2024-57850', 'CVE-2024-57874', 'CVE-2024-57882', 'CVE-2024-57884', 'CVE-2024-57889', 'CVE-2024-57890', 'CVE-2024-57892', 'CVE-2024-57896', 'CVE-2024-57897', 'CVE-2024-57900', 'CVE-2024-57901', 'CVE-2024-57902', 'CVE-2024-57903', 'CVE-2024-57904', 'CVE-2024-57906', 'CVE-2024-57907', 'CVE-2024-57908', 'CVE-2024-57910', 'CVE-2024-57911', 'CVE-2024-57912', 'CVE-2024-57913', 'CVE-2024-57917', 'CVE-2024-57922', 'CVE-2024-57925', 'CVE-2024-57929', 'CVE-2024-57931', 'CVE-2024-57938', 'CVE-2024-57939', 'CVE-2024-57940', 'CVE-2024-57946', 'CVE-2024-57948', 'CVE-2024-57951', 'CVE-2024-58087', 'CVE-2025-21631', 'CVE-2025-21636', 'CVE-2025-21637', 'CVE-2025-21638', 'CVE-2025-21639', 'CVE-2025-21640', 'CVE-2025-21646', 'CVE-2025-21648', 'CVE-2025-21653', 'CVE-2025-21664', 'CVE-2025-21665', 'CVE-2025-21666', 'CVE-2025-21669', 'CVE-2025-21678', 'CVE-2025-21680', 'CVE-2025-21683', 'CVE-2025-21687', 'CVE-2025-21689', 'CVE-2025-21690', 'CVE-2025-21692', 'CVE-2025-21694', 'CVE-2025-21697', 'CVE-2025-21699');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7421-1');
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
