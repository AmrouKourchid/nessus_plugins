#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7294-3. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216933);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2021-47469",
    "CVE-2023-52458",
    "CVE-2023-52917",
    "CVE-2024-35887",
    "CVE-2024-35896",
    "CVE-2024-38544",
    "CVE-2024-40911",
    "CVE-2024-40953",
    "CVE-2024-40965",
    "CVE-2024-41016",
    "CVE-2024-41066",
    "CVE-2024-42252",
    "CVE-2024-43863",
    "CVE-2024-44931",
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
    "CVE-2024-49851",
    "CVE-2024-49860",
    "CVE-2024-49867",
    "CVE-2024-49868",
    "CVE-2024-49877",
    "CVE-2024-49878",
    "CVE-2024-49879",
    "CVE-2024-49882",
    "CVE-2024-49883",
    "CVE-2024-49892",
    "CVE-2024-49894",
    "CVE-2024-49896",
    "CVE-2024-49900",
    "CVE-2024-49902",
    "CVE-2024-49903",
    "CVE-2024-49924",
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
    "CVE-2024-53059",
    "CVE-2024-53061",
    "CVE-2024-53063",
    "CVE-2024-53066",
    "CVE-2024-53101",
    "CVE-2024-53104"
  );
  script_xref(name:"USN", value:"7294-3");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/26");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel vulnerabilities (USN-7294-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-7294-3 advisory.

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM64 architecture;

    - Block layer subsystem;

    - ACPI drivers;

    - Drivers core;

    - ATA over ethernet (AOE) driver;

    - TPM device driver;

    - GPIO subsystem;

    - GPU drivers;

    - HID subsystem;

    - I2C subsystem;

    - InfiniBand drivers;

    - Mailbox framework;

    - Multiple devices driver;

    - Media drivers;

    - Network drivers;

    - NTB driver;

    - Virtio pmem driver;

    - Parport drivers;

    - PCI subsystem;

    - SPI subsystem;

    - Direct Digital Synthesis drivers;

    - USB Device Class drivers;

    - USB Dual Role (OTG-ready) Controller drivers;

    - USB Serial drivers;

    - USB Type-C support driver;

    - Framebuffer layer;

    - BTRFS file system;

    - Ceph distributed file system;

    - Ext4 file system;

    - F2FS file system;

    - File systems infrastructure;

    - JFS file system;

    - Network file system (NFS) client;

    - Network file system (NFS) server daemon;

    - NILFS2 file system;

    - SMB network file system;

    - Network traffic control;

    - Network sockets;

    - TCP network protocol;

    - BPF subsystem;

    - Perf events;

    - Arbitrary resource management;

    - Timer substystem drivers;

    - Tracing infrastructure;

    - Closures library;

    - Memory management;

    - Amateur Radio drivers;

    - Bluetooth subsystem;

    - Ethernet bridge;

    - CAN network layer;

    - Networking core;

    - IPv4 networking;

    - IPv6 networking;

    - MAC80211 subsystem;

    - Netfilter;

    - Netlink;

    - SCTP protocol;

    - TIPC protocol;

    - Wireless networking;

    - XFRM subsystem;

    - Key management;

    - FireWire sound drivers;

    - AudioScience HPI driver;

    - Amlogic Meson SoC drivers;

    - KVM core; (CVE-2024-47698, CVE-2024-49868, CVE-2024-50006, CVE-2024-40965, CVE-2024-50233,
    CVE-2024-47671, CVE-2024-49944, CVE-2024-47684, CVE-2024-50134, CVE-2024-50279, CVE-2024-50302,
    CVE-2024-40953, CVE-2024-50234, CVE-2024-41066, CVE-2024-50040, CVE-2024-47701, CVE-2024-50033,
    CVE-2024-50007, CVE-2024-50143, CVE-2024-41016, CVE-2024-53059, CVE-2024-50195, CVE-2024-50202,
    CVE-2024-47749, CVE-2024-47685, CVE-2024-50267, CVE-2024-49965, CVE-2024-49903, CVE-2024-49883,
    CVE-2024-50035, CVE-2024-46849, CVE-2024-53061, CVE-2024-50151, CVE-2024-49995, CVE-2024-49867,
    CVE-2024-49962, CVE-2024-50218, CVE-2024-50039, CVE-2024-50148, CVE-2024-49900, CVE-2024-50287,
    CVE-2024-50150, CVE-2024-49879, CVE-2024-47757, CVE-2024-49997, CVE-2024-50045, CVE-2024-47742,
    CVE-2024-47679, CVE-2024-53063, CVE-2024-49878, CVE-2024-49860, CVE-2024-35896, CVE-2024-40911,
    CVE-2024-42252, CVE-2024-47723, CVE-2024-47674, CVE-2024-47737, CVE-2024-50282, CVE-2024-44931,
    CVE-2024-49938, CVE-2024-49963, CVE-2024-50290, CVE-2024-49958, CVE-2021-47469, CVE-2024-47670,
    CVE-2024-50116, CVE-2024-50262, CVE-2024-50082, CVE-2023-52917, CVE-2024-50117, CVE-2024-50131,
    CVE-2024-47699, CVE-2024-49896, CVE-2024-49957, CVE-2024-49952, CVE-2024-50273, CVE-2024-50171,
    CVE-2024-50237, CVE-2024-49955, CVE-2024-50230, CVE-2024-50194, CVE-2024-50278, CVE-2024-50127,
    CVE-2024-53066, CVE-2024-38544, CVE-2024-49902, CVE-2024-49892, CVE-2024-46854, CVE-2024-49966,
    CVE-2024-50167, CVE-2024-47697, CVE-2024-49985, CVE-2024-47696, CVE-2024-50024, CVE-2024-50251,
    CVE-2024-47740, CVE-2024-49882, CVE-2024-49851, CVE-2024-50059, CVE-2024-49973, CVE-2024-35887,
    CVE-2024-50296, CVE-2024-47706, CVE-2024-50044, CVE-2024-47712, CVE-2024-50301, CVE-2024-47709,
    CVE-2024-49975, CVE-2024-49877, CVE-2024-47710, CVE-2024-50269, CVE-2024-46731, CVE-2024-50099,
    CVE-2024-50184, CVE-2024-50299, CVE-2024-50008, CVE-2024-50265, CVE-2024-49948, CVE-2024-50229,
    CVE-2024-50168, CVE-2024-49894, CVE-2024-47692, CVE-2024-50074, CVE-2024-47713, CVE-2024-49924,
    CVE-2024-53104, CVE-2024-50205, CVE-2024-47672, CVE-2024-50096, CVE-2024-47747, CVE-2024-50199,
    CVE-2023-52458, CVE-2024-49959, CVE-2024-50236, CVE-2024-53101, CVE-2024-43863, CVE-2024-46853,
    CVE-2024-50179, CVE-2024-49981, CVE-2024-47756, CVE-2024-49949, CVE-2024-50142, CVE-2024-49982,
    CVE-2024-50180)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7294-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47685");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1086-ibm");
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
    '5.4.0': {
      'ibm': '5.4.0-1086'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7294-3');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-47469', 'CVE-2023-52458', 'CVE-2023-52917', 'CVE-2024-35887', 'CVE-2024-35896', 'CVE-2024-38544', 'CVE-2024-40911', 'CVE-2024-40953', 'CVE-2024-40965', 'CVE-2024-41016', 'CVE-2024-41066', 'CVE-2024-42252', 'CVE-2024-43863', 'CVE-2024-44931', 'CVE-2024-46731', 'CVE-2024-46849', 'CVE-2024-46853', 'CVE-2024-46854', 'CVE-2024-47670', 'CVE-2024-47671', 'CVE-2024-47672', 'CVE-2024-47674', 'CVE-2024-47679', 'CVE-2024-47684', 'CVE-2024-47685', 'CVE-2024-47692', 'CVE-2024-47696', 'CVE-2024-47697', 'CVE-2024-47698', 'CVE-2024-47699', 'CVE-2024-47701', 'CVE-2024-47706', 'CVE-2024-47709', 'CVE-2024-47710', 'CVE-2024-47712', 'CVE-2024-47713', 'CVE-2024-47723', 'CVE-2024-47737', 'CVE-2024-47740', 'CVE-2024-47742', 'CVE-2024-47747', 'CVE-2024-47749', 'CVE-2024-47756', 'CVE-2024-47757', 'CVE-2024-49851', 'CVE-2024-49860', 'CVE-2024-49867', 'CVE-2024-49868', 'CVE-2024-49877', 'CVE-2024-49878', 'CVE-2024-49879', 'CVE-2024-49882', 'CVE-2024-49883', 'CVE-2024-49892', 'CVE-2024-49894', 'CVE-2024-49896', 'CVE-2024-49900', 'CVE-2024-49902', 'CVE-2024-49903', 'CVE-2024-49924', 'CVE-2024-49938', 'CVE-2024-49944', 'CVE-2024-49948', 'CVE-2024-49949', 'CVE-2024-49952', 'CVE-2024-49955', 'CVE-2024-49957', 'CVE-2024-49958', 'CVE-2024-49959', 'CVE-2024-49962', 'CVE-2024-49963', 'CVE-2024-49965', 'CVE-2024-49966', 'CVE-2024-49973', 'CVE-2024-49975', 'CVE-2024-49981', 'CVE-2024-49982', 'CVE-2024-49985', 'CVE-2024-49995', 'CVE-2024-49997', 'CVE-2024-50006', 'CVE-2024-50007', 'CVE-2024-50008', 'CVE-2024-50024', 'CVE-2024-50033', 'CVE-2024-50035', 'CVE-2024-50039', 'CVE-2024-50040', 'CVE-2024-50044', 'CVE-2024-50045', 'CVE-2024-50059', 'CVE-2024-50074', 'CVE-2024-50082', 'CVE-2024-50096', 'CVE-2024-50099', 'CVE-2024-50116', 'CVE-2024-50117', 'CVE-2024-50127', 'CVE-2024-50131', 'CVE-2024-50134', 'CVE-2024-50142', 'CVE-2024-50143', 'CVE-2024-50148', 'CVE-2024-50150', 'CVE-2024-50151', 'CVE-2024-50167', 'CVE-2024-50168', 'CVE-2024-50171', 'CVE-2024-50179', 'CVE-2024-50180', 'CVE-2024-50184', 'CVE-2024-50194', 'CVE-2024-50195', 'CVE-2024-50199', 'CVE-2024-50202', 'CVE-2024-50205', 'CVE-2024-50218', 'CVE-2024-50229', 'CVE-2024-50230', 'CVE-2024-50233', 'CVE-2024-50234', 'CVE-2024-50236', 'CVE-2024-50237', 'CVE-2024-50251', 'CVE-2024-50262', 'CVE-2024-50265', 'CVE-2024-50267', 'CVE-2024-50269', 'CVE-2024-50273', 'CVE-2024-50278', 'CVE-2024-50279', 'CVE-2024-50282', 'CVE-2024-50287', 'CVE-2024-50290', 'CVE-2024-50296', 'CVE-2024-50299', 'CVE-2024-50301', 'CVE-2024-50302', 'CVE-2024-53059', 'CVE-2024-53061', 'CVE-2024-53063', 'CVE-2024-53066', 'CVE-2024-53101', 'CVE-2024-53104');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7294-3');
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
