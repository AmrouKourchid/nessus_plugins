#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7288-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216710);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id(
    "CVE-2023-52913",
    "CVE-2024-26718",
    "CVE-2024-35887",
    "CVE-2024-39497",
    "CVE-2024-40953",
    "CVE-2024-40965",
    "CVE-2024-41066",
    "CVE-2024-41080",
    "CVE-2024-42252",
    "CVE-2024-42291",
    "CVE-2024-50010",
    "CVE-2024-50036",
    "CVE-2024-50058",
    "CVE-2024-50072",
    "CVE-2024-50074",
    "CVE-2024-50082",
    "CVE-2024-50083",
    "CVE-2024-50085",
    "CVE-2024-50086",
    "CVE-2024-50099",
    "CVE-2024-50101",
    "CVE-2024-50103",
    "CVE-2024-50110",
    "CVE-2024-50115",
    "CVE-2024-50116",
    "CVE-2024-50117",
    "CVE-2024-50127",
    "CVE-2024-50128",
    "CVE-2024-50131",
    "CVE-2024-50134",
    "CVE-2024-50141",
    "CVE-2024-50142",
    "CVE-2024-50143",
    "CVE-2024-50148",
    "CVE-2024-50150",
    "CVE-2024-50151",
    "CVE-2024-50153",
    "CVE-2024-50154",
    "CVE-2024-50156",
    "CVE-2024-50160",
    "CVE-2024-50162",
    "CVE-2024-50163",
    "CVE-2024-50167",
    "CVE-2024-50168",
    "CVE-2024-50171",
    "CVE-2024-50182",
    "CVE-2024-50185",
    "CVE-2024-50192",
    "CVE-2024-50193",
    "CVE-2024-50194",
    "CVE-2024-50195",
    "CVE-2024-50196",
    "CVE-2024-50198",
    "CVE-2024-50199",
    "CVE-2024-50201",
    "CVE-2024-50202",
    "CVE-2024-50205",
    "CVE-2024-50208",
    "CVE-2024-50209",
    "CVE-2024-50218",
    "CVE-2024-50229",
    "CVE-2024-50230",
    "CVE-2024-50232",
    "CVE-2024-50233",
    "CVE-2024-50234",
    "CVE-2024-50236",
    "CVE-2024-50237",
    "CVE-2024-50244",
    "CVE-2024-50245",
    "CVE-2024-50247",
    "CVE-2024-50249",
    "CVE-2024-50251",
    "CVE-2024-50257",
    "CVE-2024-50259",
    "CVE-2024-50262",
    "CVE-2024-50265",
    "CVE-2024-50267",
    "CVE-2024-50268",
    "CVE-2024-50269",
    "CVE-2024-50273",
    "CVE-2024-50278",
    "CVE-2024-50279",
    "CVE-2024-50282",
    "CVE-2024-50287",
    "CVE-2024-50290",
    "CVE-2024-50292",
    "CVE-2024-50295",
    "CVE-2024-50296",
    "CVE-2024-50299",
    "CVE-2024-50301",
    "CVE-2024-50302",
    "CVE-2024-53042",
    "CVE-2024-53052",
    "CVE-2024-53055",
    "CVE-2024-53058",
    "CVE-2024-53059",
    "CVE-2024-53061",
    "CVE-2024-53063",
    "CVE-2024-53066",
    "CVE-2024-53088",
    "CVE-2024-53097",
    "CVE-2024-53101",
    "CVE-2024-53104",
    "CVE-2025-0927"
  );
  script_xref(name:"USN", value:"7288-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/03/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/26");

  script_name(english:"Ubuntu 22.04 LTS : Linux kernel vulnerabilities (USN-7288-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-7288-1 advisory.

    Attila Szsz discovered that the HFS+ file system implementation in the Linux Kernel contained a heap
    overflow vulnerability. An attacker could use a specially crafted file system image that, when mounted,
    could cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2025-0927)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM64 architecture;

    - x86 architecture;

    - Block layer subsystem;

    - ACPI drivers;

    - GPU drivers;

    - HID subsystem;

    - I2C subsystem;

    - IIO ADC drivers;

    - IIO subsystem;

    - InfiniBand drivers;

    - IOMMU subsystem;

    - IRQ chip drivers;

    - Multiple devices driver;

    - Media drivers;

    - Network drivers;

    - STMicroelectronics network drivers;

    - Parport drivers;

    - Pin controllers subsystem;

    - Direct Digital Synthesis drivers;

    - TCM subsystem;

    - TTY drivers;

    - USB Dual Role (OTG-ready) Controller drivers;

    - USB Serial drivers;

    - USB Type-C support driver;

    - USB Type-C Connector System Software Interface driver;

    - BTRFS file system;

    - File systems infrastructure;

    - Network file system (NFS) client;

    - NILFS2 file system;

    - NTFS3 file system;

    - SMB network file system;

    - User-space API (UAPI);

    - io_uring subsystem;

    - BPF subsystem;

    - Timer substystem drivers;

    - Tracing infrastructure;

    - Closures library;

    - Memory management;

    - Amateur Radio drivers;

    - Bluetooth subsystem;

    - Networking core;

    - IPv4 networking;

    - MAC80211 subsystem;

    - Multipath TCP;

    - Netfilter;

    - Network traffic control;

    - SCTP protocol;

    - XFRM subsystem;

    - Key management;

    - FireWire sound drivers;

    - HD-audio driver;

    - QCOM ASoC drivers;

    - STMicroelectronics SoC drivers;

    - KVM core; (CVE-2024-50202, CVE-2024-50208, CVE-2024-50265, CVE-2024-41080, CVE-2024-50101,
    CVE-2024-39497, CVE-2024-50153, CVE-2024-50162, CVE-2024-50150, CVE-2024-50115, CVE-2024-53066,
    CVE-2024-50279, CVE-2024-50116, CVE-2024-50218, CVE-2024-53104, CVE-2024-50086, CVE-2024-50154,
    CVE-2024-50244, CVE-2024-50074, CVE-2024-50278, CVE-2024-50262, CVE-2024-50168, CVE-2024-50134,
    CVE-2024-53063, CVE-2024-50236, CVE-2024-50082, CVE-2024-50234, CVE-2024-50247, CVE-2024-50282,
    CVE-2024-50267, CVE-2024-40965, CVE-2024-50229, CVE-2024-50110, CVE-2024-35887, CVE-2024-50302,
    CVE-2024-50036, CVE-2024-50209, CVE-2024-50287, CVE-2024-50245, CVE-2024-50072, CVE-2024-50301,
    CVE-2024-50201, CVE-2024-53097, CVE-2024-40953, CVE-2024-50085, CVE-2024-50299, CVE-2024-50292,
    CVE-2024-50269, CVE-2024-50182, CVE-2024-50233, CVE-2024-53088, CVE-2024-50259, CVE-2024-50232,
    CVE-2024-53055, CVE-2024-50195, CVE-2024-50273, CVE-2024-42291, CVE-2024-50192, CVE-2024-50251,
    CVE-2024-50193, CVE-2024-50142, CVE-2024-53101, CVE-2024-50205, CVE-2024-26718, CVE-2024-50167,
    CVE-2024-50010, CVE-2024-50230, CVE-2024-41066, CVE-2024-50194, CVE-2024-50148, CVE-2024-50151,
    CVE-2024-50127, CVE-2024-50160, CVE-2023-52913, CVE-2024-53052, CVE-2024-50156, CVE-2024-50141,
    CVE-2024-50103, CVE-2024-50296, CVE-2024-50257, CVE-2024-50199, CVE-2024-50128, CVE-2024-50058,
    CVE-2024-50099, CVE-2024-50290, CVE-2024-53042, CVE-2024-50295, CVE-2024-50268, CVE-2024-50163,
    CVE-2024-53058, CVE-2024-50185, CVE-2024-50117, CVE-2024-50237, CVE-2024-50083, CVE-2024-50131,
    CVE-2024-50196, CVE-2024-42252, CVE-2024-50143, CVE-2024-50171, CVE-2024-50249, CVE-2024-53059,
    CVE-2024-50198, CVE-2024-53061)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7288-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53104");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-133-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-133-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-133-generic-lpae");
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
      'generic': '5.15.0-133',
      'generic-64k': '5.15.0-133',
      'generic-lpae': '5.15.0-133'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7288-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-52913', 'CVE-2024-26718', 'CVE-2024-35887', 'CVE-2024-39497', 'CVE-2024-40953', 'CVE-2024-40965', 'CVE-2024-41066', 'CVE-2024-41080', 'CVE-2024-42252', 'CVE-2024-42291', 'CVE-2024-50010', 'CVE-2024-50036', 'CVE-2024-50058', 'CVE-2024-50072', 'CVE-2024-50074', 'CVE-2024-50082', 'CVE-2024-50083', 'CVE-2024-50085', 'CVE-2024-50086', 'CVE-2024-50099', 'CVE-2024-50101', 'CVE-2024-50103', 'CVE-2024-50110', 'CVE-2024-50115', 'CVE-2024-50116', 'CVE-2024-50117', 'CVE-2024-50127', 'CVE-2024-50128', 'CVE-2024-50131', 'CVE-2024-50134', 'CVE-2024-50141', 'CVE-2024-50142', 'CVE-2024-50143', 'CVE-2024-50148', 'CVE-2024-50150', 'CVE-2024-50151', 'CVE-2024-50153', 'CVE-2024-50154', 'CVE-2024-50156', 'CVE-2024-50160', 'CVE-2024-50162', 'CVE-2024-50163', 'CVE-2024-50167', 'CVE-2024-50168', 'CVE-2024-50171', 'CVE-2024-50182', 'CVE-2024-50185', 'CVE-2024-50192', 'CVE-2024-50193', 'CVE-2024-50194', 'CVE-2024-50195', 'CVE-2024-50196', 'CVE-2024-50198', 'CVE-2024-50199', 'CVE-2024-50201', 'CVE-2024-50202', 'CVE-2024-50205', 'CVE-2024-50208', 'CVE-2024-50209', 'CVE-2024-50218', 'CVE-2024-50229', 'CVE-2024-50230', 'CVE-2024-50232', 'CVE-2024-50233', 'CVE-2024-50234', 'CVE-2024-50236', 'CVE-2024-50237', 'CVE-2024-50244', 'CVE-2024-50245', 'CVE-2024-50247', 'CVE-2024-50249', 'CVE-2024-50251', 'CVE-2024-50257', 'CVE-2024-50259', 'CVE-2024-50262', 'CVE-2024-50265', 'CVE-2024-50267', 'CVE-2024-50268', 'CVE-2024-50269', 'CVE-2024-50273', 'CVE-2024-50278', 'CVE-2024-50279', 'CVE-2024-50282', 'CVE-2024-50287', 'CVE-2024-50290', 'CVE-2024-50292', 'CVE-2024-50295', 'CVE-2024-50296', 'CVE-2024-50299', 'CVE-2024-50301', 'CVE-2024-50302', 'CVE-2024-53042', 'CVE-2024-53052', 'CVE-2024-53055', 'CVE-2024-53058', 'CVE-2024-53059', 'CVE-2024-53061', 'CVE-2024-53063', 'CVE-2024-53066', 'CVE-2024-53088', 'CVE-2024-53097', 'CVE-2024-53101', 'CVE-2024-53104', 'CVE-2025-0927');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7288-1');
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
