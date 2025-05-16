#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7195-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213656);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/09");

  script_cve_id(
    "CVE-2021-47001",
    "CVE-2021-47076",
    "CVE-2021-47101",
    "CVE-2021-47501",
    "CVE-2022-38096",
    "CVE-2022-48733",
    "CVE-2022-48938",
    "CVE-2022-48943",
    "CVE-2023-52488",
    "CVE-2023-52497",
    "CVE-2023-52498",
    "CVE-2023-52639",
    "CVE-2023-52821",
    "CVE-2024-26947",
    "CVE-2024-35904",
    "CVE-2024-35951",
    "CVE-2024-35963",
    "CVE-2024-35965",
    "CVE-2024-35966",
    "CVE-2024-35967",
    "CVE-2024-36938",
    "CVE-2024-36952",
    "CVE-2024-36953",
    "CVE-2024-36968",
    "CVE-2024-38538",
    "CVE-2024-38553",
    "CVE-2024-38597",
    "CVE-2024-40910",
    "CVE-2024-42068",
    "CVE-2024-42077",
    "CVE-2024-42156",
    "CVE-2024-42240",
    "CVE-2024-43892",
    "CVE-2024-44940",
    "CVE-2024-44942",
    "CVE-2024-46724",
    "CVE-2024-49967",
    "CVE-2024-50264",
    "CVE-2024-53057"
  );
  script_xref(name:"USN", value:"7195-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (Azure) vulnerabilities (USN-7195-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-7195-1 advisory.

    Ziming Zhang discovered that the DRM driver for VMware Virtual GPU did not properly handle certain error
    conditions, leading to a NULL pointer dereference. A local attacker could possibly trigger this
    vulnerability to cause a denial of service. (CVE-2022-38096)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - ARM32 architecture;

    - ARM64 architecture;

    - S390 architecture;

    - x86 architecture;

    - Power management core;

    - GPU drivers;

    - InfiniBand drivers;

    - Network drivers;

    - S/390 drivers;

    - SCSI subsystem;

    - TTY drivers;

    - BTRFS file system;

    - Ext4 file system;

    - EROFS file system;

    - F2FS file system;

    - File systems infrastructure;

    - BPF subsystem;

    - Socket messages infrastructure;

    - Bluetooth subsystem;

    - Memory management;

    - Amateur Radio drivers;

    - Ethernet bridge;

    - Networking core;

    - IPv4 networking;

    - Network traffic control;

    - Sun RPC protocol;

    - VMware vSockets driver;

    - SELinux security module; (CVE-2024-42240, CVE-2024-36938, CVE-2024-35967, CVE-2024-36953,
    CVE-2022-48938, CVE-2024-38553, CVE-2024-35904, CVE-2024-35965, CVE-2024-26947, CVE-2024-36968,
    CVE-2024-43892, CVE-2024-38597, CVE-2023-52498, CVE-2021-47501, CVE-2024-44942, CVE-2024-42077,
    CVE-2024-53057, CVE-2024-46724, CVE-2024-35963, CVE-2022-48943, CVE-2024-42068, CVE-2024-42156,
    CVE-2022-48733, CVE-2023-52639, CVE-2021-47101, CVE-2023-52821, CVE-2024-44940, CVE-2024-36952,
    CVE-2021-47001, CVE-2024-38538, CVE-2024-40910, CVE-2021-47076, CVE-2024-35966, CVE-2024-50264,
    CVE-2024-35951, CVE-2023-52488, CVE-2023-52497, CVE-2024-49967)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7195-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53057");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1142-azure");
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
      'azure': '5.4.0-1142'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7195-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-47001', 'CVE-2021-47076', 'CVE-2021-47101', 'CVE-2021-47501', 'CVE-2022-38096', 'CVE-2022-48733', 'CVE-2022-48938', 'CVE-2022-48943', 'CVE-2023-52488', 'CVE-2023-52497', 'CVE-2023-52498', 'CVE-2023-52639', 'CVE-2023-52821', 'CVE-2024-26947', 'CVE-2024-35904', 'CVE-2024-35951', 'CVE-2024-35963', 'CVE-2024-35965', 'CVE-2024-35966', 'CVE-2024-35967', 'CVE-2024-36938', 'CVE-2024-36952', 'CVE-2024-36953', 'CVE-2024-36968', 'CVE-2024-38538', 'CVE-2024-38553', 'CVE-2024-38597', 'CVE-2024-40910', 'CVE-2024-42068', 'CVE-2024-42077', 'CVE-2024-42156', 'CVE-2024-42240', 'CVE-2024-43892', 'CVE-2024-44940', 'CVE-2024-44942', 'CVE-2024-46724', 'CVE-2024-49967', 'CVE-2024-50264', 'CVE-2024-53057');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7195-1');
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
