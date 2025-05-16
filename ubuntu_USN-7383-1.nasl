#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7383-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233469);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id(
    "CVE-2024-47711",
    "CVE-2024-47726",
    "CVE-2024-49865",
    "CVE-2024-49893",
    "CVE-2024-49914",
    "CVE-2024-49920",
    "CVE-2024-49921",
    "CVE-2024-49968",
    "CVE-2024-49972",
    "CVE-2024-50009",
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
    "CVE-2024-50032",
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
    "CVE-2024-53156",
    "CVE-2024-53165",
    "CVE-2024-53170",
    "CVE-2024-56582",
    "CVE-2024-56614",
    "CVE-2024-56663"
  );
  script_xref(name:"USN", value:"7383-1");

  script_name(english:"Ubuntu 22.04 LTS / 24.04 LTS : Linux kernel vulnerabilities (USN-7383-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS / 24.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-7383-1 advisory.

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM64 architecture;

    - x86 architecture;

    - Block layer subsystem;

    - Drivers core;

    - Ublk userspace block driver;

    - Compressed RAM block device driver;

    - CPU frequency scaling framework;

    - DAX dirext access to differentiated memory framework;

    - GPU drivers;

    - HID subsystem;

    - I3C subsystem;

    - IIO subsystem;

    - InfiniBand drivers;

    - IOMMU subsystem;

    - IRQ chip drivers;

    - Network drivers;

    - NTB driver;

    - Virtio pmem driver;

    - Parport drivers;

    - Pin controllers subsystem;

    - SCSI subsystem;

    - SuperH / SH-Mobile drivers;

    - Direct Digital Synthesis drivers;

    - Thermal drivers;

    - TTY drivers;

    - UFS subsystem;

    - USB Gadget drivers;

    - USB Host Controller drivers;

    - TI TPS6598x USB Power Delivery controller driver;

    - Framebuffer layer;

    - BTRFS file system;

    - Ext4 file system;

    - F2FS file system;

    - Network file system (NFS) client;

    - NILFS2 file system;

    - NTFS3 file system;

    - SMB network file system;

    - BPF subsystem;

    - Network file system (NFS) superblock;

    - Network traffic control;

    - Network sockets;

    - User-space API (UAPI);

    - io_uring subsystem;

    - Kernel thread helper (kthread);

    - RCU subsystem;

    - Timer subsystem;

    - Maple Tree data structure library;

    - Memory management;

    - Bluetooth subsystem;

    - Ethernet bridge;

    - Networking core;

    - IPv4 networking;

    - Multipath TCP;

    - Netfilter;

    - Netlink;

    - Unix domain sockets;

    - Wireless networking;

    - eXpress Data Path; (CVE-2024-50182, CVE-2024-50020, CVE-2024-50060, CVE-2024-50074, CVE-2024-50193,
    CVE-2024-50117, CVE-2024-50201, CVE-2024-50033, CVE-2024-50056, CVE-2024-50026, CVE-2024-50059,
    CVE-2024-50041, CVE-2024-50083, CVE-2024-50038, CVE-2024-50229, CVE-2024-50028, CVE-2024-50183,
    CVE-2024-50196, CVE-2024-50029, CVE-2024-50093, CVE-2024-50188, CVE-2024-50025, CVE-2024-50200,
    CVE-2024-50068, CVE-2024-49920, CVE-2024-50198, CVE-2024-50035, CVE-2024-50042, CVE-2024-50023,
    CVE-2024-50047, CVE-2024-56582, CVE-2024-50090, CVE-2024-50062, CVE-2024-50073, CVE-2024-50063,
    CVE-2024-50098, CVE-2024-50197, CVE-2024-50040, CVE-2024-50180, CVE-2024-53170, CVE-2024-50087,
    CVE-2024-50031, CVE-2024-50202, CVE-2024-50058, CVE-2024-50186, CVE-2024-50134, CVE-2024-50194,
    CVE-2024-50075, CVE-2024-50046, CVE-2024-50078, CVE-2024-50066, CVE-2024-53156, CVE-2024-49893,
    CVE-2024-50021, CVE-2024-47711, CVE-2024-47726, CVE-2024-50024, CVE-2024-49865, CVE-2024-50064,
    CVE-2024-50049, CVE-2024-50171, CVE-2024-50019, CVE-2024-50077, CVE-2024-50199, CVE-2024-50072,
    CVE-2024-50069, CVE-2024-50048, CVE-2024-49972, CVE-2024-53165, CVE-2024-50022, CVE-2024-50084,
    CVE-2024-50185, CVE-2024-50055, CVE-2024-50187, CVE-2024-50009, CVE-2024-50082, CVE-2024-50085,
    CVE-2024-50095, CVE-2024-50195, CVE-2024-50080, CVE-2024-50076, CVE-2024-50088, CVE-2024-50039,
    CVE-2024-50044, CVE-2024-50030, CVE-2024-49968, CVE-2024-50148, CVE-2024-50192, CVE-2024-50032,
    CVE-2024-50061, CVE-2024-50233, CVE-2024-50099, CVE-2024-49921, CVE-2024-50184, CVE-2024-50065,
    CVE-2024-49914, CVE-2024-50027, CVE-2024-50070, CVE-2024-50086, CVE-2024-50189, CVE-2024-56614,
    CVE-2024-50057, CVE-2024-50096, CVE-2024-50045, CVE-2024-50036, CVE-2024-56663, CVE-2024-50191,
    CVE-2024-50101)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7383-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-56614");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1008-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1021-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1022-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1022-oracle-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1024-nvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1024-nvidia-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1024-nvidia-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1024-nvidia-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1025-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1026-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-1026-gcp-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-56-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.8.0-56-lowlatency-64k");
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
      'lowlatency': '6.8.0-56',
      'lowlatency-64k': '6.8.0-56',
      'oracle': '6.8.0-1022',
      'oracle-64k': '6.8.0-1022',
      'nvidia': '6.8.0-1024',
      'nvidia-64k': '6.8.0-1024',
      'gcp': '6.8.0-1026',
      'gcp-64k': '6.8.0-1026'
    }
  },
  '24.04': {
    '6.8.0': {
      'lowlatency': '6.8.0-56',
      'lowlatency-64k': '6.8.0-56',
      'gkeop': '6.8.0-1008',
      'gke': '6.8.0-1021',
      'oracle': '6.8.0-1022',
      'oracle-64k': '6.8.0-1022',
      'nvidia-lowlatency': '6.8.0-1024',
      'nvidia-lowlatency-64k': '6.8.0-1024',
      'aws': '6.8.0-1025',
      'gcp': '6.8.0-1026',
      'gcp-64k': '6.8.0-1026'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7383-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2024-47711', 'CVE-2024-47726', 'CVE-2024-49865', 'CVE-2024-49893', 'CVE-2024-49914', 'CVE-2024-49920', 'CVE-2024-49921', 'CVE-2024-49968', 'CVE-2024-49972', 'CVE-2024-50009', 'CVE-2024-50019', 'CVE-2024-50020', 'CVE-2024-50021', 'CVE-2024-50022', 'CVE-2024-50023', 'CVE-2024-50024', 'CVE-2024-50025', 'CVE-2024-50026', 'CVE-2024-50027', 'CVE-2024-50028', 'CVE-2024-50029', 'CVE-2024-50030', 'CVE-2024-50031', 'CVE-2024-50032', 'CVE-2024-50033', 'CVE-2024-50035', 'CVE-2024-50036', 'CVE-2024-50038', 'CVE-2024-50039', 'CVE-2024-50040', 'CVE-2024-50041', 'CVE-2024-50042', 'CVE-2024-50044', 'CVE-2024-50045', 'CVE-2024-50046', 'CVE-2024-50047', 'CVE-2024-50048', 'CVE-2024-50049', 'CVE-2024-50055', 'CVE-2024-50056', 'CVE-2024-50057', 'CVE-2024-50058', 'CVE-2024-50059', 'CVE-2024-50060', 'CVE-2024-50061', 'CVE-2024-50062', 'CVE-2024-50063', 'CVE-2024-50064', 'CVE-2024-50065', 'CVE-2024-50066', 'CVE-2024-50068', 'CVE-2024-50069', 'CVE-2024-50070', 'CVE-2024-50072', 'CVE-2024-50073', 'CVE-2024-50074', 'CVE-2024-50075', 'CVE-2024-50076', 'CVE-2024-50077', 'CVE-2024-50078', 'CVE-2024-50080', 'CVE-2024-50082', 'CVE-2024-50083', 'CVE-2024-50084', 'CVE-2024-50085', 'CVE-2024-50086', 'CVE-2024-50087', 'CVE-2024-50088', 'CVE-2024-50090', 'CVE-2024-50093', 'CVE-2024-50095', 'CVE-2024-50096', 'CVE-2024-50098', 'CVE-2024-50099', 'CVE-2024-50101', 'CVE-2024-50117', 'CVE-2024-50134', 'CVE-2024-50148', 'CVE-2024-50171', 'CVE-2024-50180', 'CVE-2024-50182', 'CVE-2024-50183', 'CVE-2024-50184', 'CVE-2024-50185', 'CVE-2024-50186', 'CVE-2024-50187', 'CVE-2024-50188', 'CVE-2024-50189', 'CVE-2024-50191', 'CVE-2024-50192', 'CVE-2024-50193', 'CVE-2024-50194', 'CVE-2024-50195', 'CVE-2024-50196', 'CVE-2024-50197', 'CVE-2024-50198', 'CVE-2024-50199', 'CVE-2024-50200', 'CVE-2024-50201', 'CVE-2024-50202', 'CVE-2024-50229', 'CVE-2024-50233', 'CVE-2024-53156', 'CVE-2024-53165', 'CVE-2024-53170', 'CVE-2024-56582', 'CVE-2024-56614', 'CVE-2024-56663');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7383-1');
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
