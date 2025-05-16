#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7166-4. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214397);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/20");

  script_cve_id(
    "CVE-2023-52532",
    "CVE-2023-52621",
    "CVE-2023-52639",
    "CVE-2023-52904",
    "CVE-2023-52917",
    "CVE-2024-26947",
    "CVE-2024-27072",
    "CVE-2024-35904",
    "CVE-2024-35951",
    "CVE-2024-36893",
    "CVE-2024-36968",
    "CVE-2024-38538",
    "CVE-2024-38544",
    "CVE-2024-38545",
    "CVE-2024-38632",
    "CVE-2024-38667",
    "CVE-2024-39463",
    "CVE-2024-41016",
    "CVE-2024-42079",
    "CVE-2024-42156",
    "CVE-2024-42158",
    "CVE-2024-44931",
    "CVE-2024-44940",
    "CVE-2024-44942",
    "CVE-2024-46695",
    "CVE-2024-46849",
    "CVE-2024-46852",
    "CVE-2024-46853",
    "CVE-2024-46854",
    "CVE-2024-46855",
    "CVE-2024-46858",
    "CVE-2024-46859",
    "CVE-2024-46865",
    "CVE-2024-47670",
    "CVE-2024-47671",
    "CVE-2024-47672",
    "CVE-2024-47673",
    "CVE-2024-47674",
    "CVE-2024-47679",
    "CVE-2024-47684",
    "CVE-2024-47685",
    "CVE-2024-47690",
    "CVE-2024-47692",
    "CVE-2024-47693",
    "CVE-2024-47695",
    "CVE-2024-47696",
    "CVE-2024-47697",
    "CVE-2024-47698",
    "CVE-2024-47699",
    "CVE-2024-47701",
    "CVE-2024-47705",
    "CVE-2024-47706",
    "CVE-2024-47709",
    "CVE-2024-47710",
    "CVE-2024-47712",
    "CVE-2024-47713",
    "CVE-2024-47718",
    "CVE-2024-47720",
    "CVE-2024-47723",
    "CVE-2024-47734",
    "CVE-2024-47735",
    "CVE-2024-47737",
    "CVE-2024-47739",
    "CVE-2024-47740",
    "CVE-2024-47742",
    "CVE-2024-47747",
    "CVE-2024-47748",
    "CVE-2024-47749",
    "CVE-2024-47756",
    "CVE-2024-47757",
    "CVE-2024-49851",
    "CVE-2024-49852",
    "CVE-2024-49856",
    "CVE-2024-49858",
    "CVE-2024-49860",
    "CVE-2024-49863",
    "CVE-2024-49866",
    "CVE-2024-49867",
    "CVE-2024-49868",
    "CVE-2024-49871",
    "CVE-2024-49875",
    "CVE-2024-49877",
    "CVE-2024-49878",
    "CVE-2024-49879",
    "CVE-2024-49881",
    "CVE-2024-49882",
    "CVE-2024-49883",
    "CVE-2024-49884",
    "CVE-2024-49886",
    "CVE-2024-49889",
    "CVE-2024-49890",
    "CVE-2024-49892",
    "CVE-2024-49894",
    "CVE-2024-49895",
    "CVE-2024-49896",
    "CVE-2024-49900",
    "CVE-2024-49902",
    "CVE-2024-49903",
    "CVE-2024-49907",
    "CVE-2024-49913",
    "CVE-2024-49924",
    "CVE-2024-49927",
    "CVE-2024-49930",
    "CVE-2024-49933",
    "CVE-2024-49935",
    "CVE-2024-49936",
    "CVE-2024-49938",
    "CVE-2024-49944",
    "CVE-2024-49946",
    "CVE-2024-49948",
    "CVE-2024-49949",
    "CVE-2024-49952",
    "CVE-2024-49954",
    "CVE-2024-49955",
    "CVE-2024-49957",
    "CVE-2024-49958",
    "CVE-2024-49959",
    "CVE-2024-49962",
    "CVE-2024-49963",
    "CVE-2024-49965",
    "CVE-2024-49966",
    "CVE-2024-49967",
    "CVE-2024-49969",
    "CVE-2024-49973",
    "CVE-2024-49975",
    "CVE-2024-49977",
    "CVE-2024-49981",
    "CVE-2024-49982",
    "CVE-2024-49983",
    "CVE-2024-49985",
    "CVE-2024-49995",
    "CVE-2024-49997",
    "CVE-2024-50000",
    "CVE-2024-50001",
    "CVE-2024-50002",
    "CVE-2024-50003",
    "CVE-2024-50006",
    "CVE-2024-50007",
    "CVE-2024-50008",
    "CVE-2024-50013",
    "CVE-2024-50015",
    "CVE-2024-50019",
    "CVE-2024-50024",
    "CVE-2024-50031",
    "CVE-2024-50033",
    "CVE-2024-50035",
    "CVE-2024-50038",
    "CVE-2024-50039",
    "CVE-2024-50040",
    "CVE-2024-50041",
    "CVE-2024-50044",
    "CVE-2024-50045",
    "CVE-2024-50046",
    "CVE-2024-50049",
    "CVE-2024-50059",
    "CVE-2024-50062",
    "CVE-2024-50093",
    "CVE-2024-50095",
    "CVE-2024-50096",
    "CVE-2024-50179",
    "CVE-2024-50180",
    "CVE-2024-50181",
    "CVE-2024-50184",
    "CVE-2024-50186",
    "CVE-2024-50188",
    "CVE-2024-50189",
    "CVE-2024-50191"
  );
  script_xref(name:"USN", value:"7166-4");

  script_name(english:"Ubuntu 22.04 LTS : Linux kernel (Xilinx ZynqMP) vulnerabilities (USN-7166-4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-7166-4 advisory.

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM32 architecture;

    - RISC-V architecture;

    - S390 architecture;

    - x86 architecture;

    - Block layer subsystem;

    - ACPI drivers;

    - Drivers core;

    - ATA over ethernet (AOE) driver;

    - TPM device driver;

    - Clock framework and drivers;

    - Buffer Sharing and Synchronization framework;

    - EFI core;

    - GPIO subsystem;

    - GPU drivers;

    - HID subsystem;

    - I2C subsystem;

    - InfiniBand drivers;

    - Input Device core drivers;

    - Mailbox framework;

    - Media drivers;

    - Ethernet bonding driver;

    - Network drivers;

    - Mellanox network drivers;

    - Microsoft Azure Network Adapter (MANA) driver;

    - STMicroelectronics network drivers;

    - NTB driver;

    - Virtio pmem driver;

    - PCI subsystem;

    - x86 platform drivers;

    - S/390 drivers;

    - SCSI subsystem;

    - SPI subsystem;

    - Thermal drivers;

    - USB Device Class drivers;

    - USB Type-C Port Controller Manager driver;

    - VFIO drivers;

    - Virtio Host (VHOST) subsystem;

    - Framebuffer layer;

    - 9P distributed file system;

    - BTRFS file system;

    - Ceph distributed file system;

    - File systems infrastructure;

    - Ext4 file system;

    - F2FS file system;

    - GFS2 file system;

    - JFS file system;

    - Network file system (NFS) client;

    - Network file system (NFS) server daemon;

    - NILFS2 file system;

    - Network file system (NFS) superblock;

    - Bluetooth subsystem;

    - Network traffic control;

    - Network sockets;

    - TCP network protocol;

    - BPF subsystem;

    - Perf events;

    - Kernel thread helper (kthread);

    - Padata parallel execution mechanism;

    - Arbitrary resource management;

    - Static call mechanism;

    - Tracing infrastructure;

    - Memory management;

    - Ethernet bridge;

    - CAN network layer;

    - Networking core;

    - IPv4 networking;

    - IPv6 networking;

    - MAC80211 subsystem;

    - Multipath TCP;

    - Netfilter;

    - Netlink;

    - SCTP protocol;

    - TIPC protocol;

    - SELinux security module;

    - Simplified Mandatory Access Control Kernel framework;

    - AudioScience HPI driver;

    - Amlogic Meson SoC drivers;

    - USB sound devices; (CVE-2024-49944, CVE-2024-49907, CVE-2024-50062, CVE-2024-36893, CVE-2024-49985,
    CVE-2024-49903, CVE-2024-49886, CVE-2024-50180, CVE-2024-47757, CVE-2024-49938, CVE-2024-49902,
    CVE-2024-47709, CVE-2024-49884, CVE-2024-49967, CVE-2024-49977, CVE-2024-47734, CVE-2024-49954,
    CVE-2024-49963, CVE-2024-47747, CVE-2024-50008, CVE-2024-47696, CVE-2024-50038, CVE-2024-46695,
    CVE-2024-47705, CVE-2024-49957, CVE-2024-38538, CVE-2024-50019, CVE-2024-38544, CVE-2024-50003,
    CVE-2024-50095, CVE-2024-50000, CVE-2024-49981, CVE-2024-49863, CVE-2024-47710, CVE-2024-49983,
    CVE-2024-26947, CVE-2024-46852, CVE-2024-49871, CVE-2024-49936, CVE-2024-47720, CVE-2024-49881,
    CVE-2024-47672, CVE-2024-50040, CVE-2024-49997, CVE-2024-50044, CVE-2023-52532, CVE-2024-47740,
    CVE-2024-44942, CVE-2024-49948, CVE-2023-52621, CVE-2024-49959, CVE-2024-47718, CVE-2024-50188,
    CVE-2024-47699, CVE-2024-47756, CVE-2024-47723, CVE-2024-46849, CVE-2024-50035, CVE-2024-50189,
    CVE-2024-47684, CVE-2024-49900, CVE-2024-50024, CVE-2024-49851, CVE-2024-49860, CVE-2024-49924,
    CVE-2024-49946, CVE-2024-44940, CVE-2023-52904, CVE-2024-47679, CVE-2024-47748, CVE-2023-52917,
    CVE-2024-47735, CVE-2024-46858, CVE-2024-35904, CVE-2024-47673, CVE-2024-49878, CVE-2024-47739,
    CVE-2024-49973, CVE-2024-49935, CVE-2024-49875, CVE-2024-49896, CVE-2024-47690, CVE-2024-50007,
    CVE-2024-49933, CVE-2024-49958, CVE-2024-49913, CVE-2024-49883, CVE-2024-47742, CVE-2024-41016,
    CVE-2024-50002, CVE-2024-49969, CVE-2024-46853, CVE-2024-50031, CVE-2024-47698, CVE-2024-47749,
    CVE-2024-50059, CVE-2024-49966, CVE-2024-50093, CVE-2024-27072, CVE-2024-50186, CVE-2024-49895,
    CVE-2024-38632, CVE-2024-49995, CVE-2024-38545, CVE-2024-38667, CVE-2024-36968, CVE-2024-49952,
    CVE-2024-50001, CVE-2024-47697, CVE-2024-50045, CVE-2024-49856, CVE-2024-49852, CVE-2024-47712,
    CVE-2023-52639, CVE-2024-49975, CVE-2024-42158, CVE-2024-49962, CVE-2024-50181, CVE-2024-42156,
    CVE-2024-46855, CVE-2024-47693, CVE-2024-47670, CVE-2024-47706, CVE-2024-50184, CVE-2024-49965,
    CVE-2024-39463, CVE-2024-50191, CVE-2024-49866, CVE-2024-49890, CVE-2024-49877, CVE-2024-49879,
    CVE-2024-49927, CVE-2024-50039, CVE-2024-46859, CVE-2024-47674, CVE-2024-50096, CVE-2024-50013,
    CVE-2024-46854, CVE-2024-49868, CVE-2024-49882, CVE-2024-47671, CVE-2024-50179, CVE-2024-44931,
    CVE-2024-50046, CVE-2024-50006, CVE-2024-49892, CVE-2024-49949, CVE-2024-42079, CVE-2024-46865,
    CVE-2024-47692, CVE-2024-47713, CVE-2024-47701, CVE-2024-49889, CVE-2024-49894, CVE-2024-50015,
    CVE-2024-49858, CVE-2024-49955, CVE-2024-49867, CVE-2024-35951, CVE-2024-50033, CVE-2024-49982,
    CVE-2024-47695, CVE-2024-50049, CVE-2024-49930, CVE-2024-50041, CVE-2024-47737, CVE-2024-47685)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7166-4");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1039-xilinx-zynqmp");
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
if (! ('22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '22.04': {
    '5.15.0': {
      'xilinx-zynqmp': '5.15.0-1039'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7166-4');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-52532', 'CVE-2023-52621', 'CVE-2023-52639', 'CVE-2023-52904', 'CVE-2023-52917', 'CVE-2024-26947', 'CVE-2024-27072', 'CVE-2024-35904', 'CVE-2024-35951', 'CVE-2024-36893', 'CVE-2024-36968', 'CVE-2024-38538', 'CVE-2024-38544', 'CVE-2024-38545', 'CVE-2024-38632', 'CVE-2024-38667', 'CVE-2024-39463', 'CVE-2024-41016', 'CVE-2024-42079', 'CVE-2024-42156', 'CVE-2024-42158', 'CVE-2024-44931', 'CVE-2024-44940', 'CVE-2024-44942', 'CVE-2024-46695', 'CVE-2024-46849', 'CVE-2024-46852', 'CVE-2024-46853', 'CVE-2024-46854', 'CVE-2024-46855', 'CVE-2024-46858', 'CVE-2024-46859', 'CVE-2024-46865', 'CVE-2024-47670', 'CVE-2024-47671', 'CVE-2024-47672', 'CVE-2024-47673', 'CVE-2024-47674', 'CVE-2024-47679', 'CVE-2024-47684', 'CVE-2024-47685', 'CVE-2024-47690', 'CVE-2024-47692', 'CVE-2024-47693', 'CVE-2024-47695', 'CVE-2024-47696', 'CVE-2024-47697', 'CVE-2024-47698', 'CVE-2024-47699', 'CVE-2024-47701', 'CVE-2024-47705', 'CVE-2024-47706', 'CVE-2024-47709', 'CVE-2024-47710', 'CVE-2024-47712', 'CVE-2024-47713', 'CVE-2024-47718', 'CVE-2024-47720', 'CVE-2024-47723', 'CVE-2024-47734', 'CVE-2024-47735', 'CVE-2024-47737', 'CVE-2024-47739', 'CVE-2024-47740', 'CVE-2024-47742', 'CVE-2024-47747', 'CVE-2024-47748', 'CVE-2024-47749', 'CVE-2024-47756', 'CVE-2024-47757', 'CVE-2024-49851', 'CVE-2024-49852', 'CVE-2024-49856', 'CVE-2024-49858', 'CVE-2024-49860', 'CVE-2024-49863', 'CVE-2024-49866', 'CVE-2024-49867', 'CVE-2024-49868', 'CVE-2024-49871', 'CVE-2024-49875', 'CVE-2024-49877', 'CVE-2024-49878', 'CVE-2024-49879', 'CVE-2024-49881', 'CVE-2024-49882', 'CVE-2024-49883', 'CVE-2024-49884', 'CVE-2024-49886', 'CVE-2024-49889', 'CVE-2024-49890', 'CVE-2024-49892', 'CVE-2024-49894', 'CVE-2024-49895', 'CVE-2024-49896', 'CVE-2024-49900', 'CVE-2024-49902', 'CVE-2024-49903', 'CVE-2024-49907', 'CVE-2024-49913', 'CVE-2024-49924', 'CVE-2024-49927', 'CVE-2024-49930', 'CVE-2024-49933', 'CVE-2024-49935', 'CVE-2024-49936', 'CVE-2024-49938', 'CVE-2024-49944', 'CVE-2024-49946', 'CVE-2024-49948', 'CVE-2024-49949', 'CVE-2024-49952', 'CVE-2024-49954', 'CVE-2024-49955', 'CVE-2024-49957', 'CVE-2024-49958', 'CVE-2024-49959', 'CVE-2024-49962', 'CVE-2024-49963', 'CVE-2024-49965', 'CVE-2024-49966', 'CVE-2024-49967', 'CVE-2024-49969', 'CVE-2024-49973', 'CVE-2024-49975', 'CVE-2024-49977', 'CVE-2024-49981', 'CVE-2024-49982', 'CVE-2024-49983', 'CVE-2024-49985', 'CVE-2024-49995', 'CVE-2024-49997', 'CVE-2024-50000', 'CVE-2024-50001', 'CVE-2024-50002', 'CVE-2024-50003', 'CVE-2024-50006', 'CVE-2024-50007', 'CVE-2024-50008', 'CVE-2024-50013', 'CVE-2024-50015', 'CVE-2024-50019', 'CVE-2024-50024', 'CVE-2024-50031', 'CVE-2024-50033', 'CVE-2024-50035', 'CVE-2024-50038', 'CVE-2024-50039', 'CVE-2024-50040', 'CVE-2024-50041', 'CVE-2024-50044', 'CVE-2024-50045', 'CVE-2024-50046', 'CVE-2024-50049', 'CVE-2024-50059', 'CVE-2024-50062', 'CVE-2024-50093', 'CVE-2024-50095', 'CVE-2024-50096', 'CVE-2024-50179', 'CVE-2024-50180', 'CVE-2024-50181', 'CVE-2024-50184', 'CVE-2024-50186', 'CVE-2024-50188', 'CVE-2024-50189', 'CVE-2024-50191');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7166-4');
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
