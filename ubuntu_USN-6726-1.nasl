#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6726-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193081);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/17");

  script_cve_id(
    "CVE-2023-46838",
    "CVE-2023-52340",
    "CVE-2023-52429",
    "CVE-2023-52436",
    "CVE-2023-52438",
    "CVE-2023-52439",
    "CVE-2023-52443",
    "CVE-2023-52444",
    "CVE-2023-52445",
    "CVE-2023-52448",
    "CVE-2023-52449",
    "CVE-2023-52451",
    "CVE-2023-52454",
    "CVE-2023-52457",
    "CVE-2023-52464",
    "CVE-2023-52469",
    "CVE-2023-52470",
    "CVE-2023-52609",
    "CVE-2023-52612",
    "CVE-2024-0607",
    "CVE-2024-23851",
    "CVE-2024-26597",
    "CVE-2024-26633"
  );
  script_xref(name:"USN", value:"6726-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-6726-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6726-1 advisory.

    Pratyush Yadav discovered that the Xen network backend implementation in the Linux kernel did not properly
    handle zero length data request, leading to a null pointer dereference vulnerability. An attacker in a
    guest VM could possibly use this to cause a denial of service (host domain crash). (CVE-2023-46838)

    It was discovered that the IPv6 implementation of the Linux kernel did not properly manage route cache
    memory usage. A remote attacker could use this to cause a denial of service (memory exhaustion).
    (CVE-2023-52340)

    It was discovered that the device mapper driver in the Linux kernel did not properly validate target size
    during certain memory allocations. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2023-52429, CVE-2024-23851)

    Dan Carpenter discovered that the netfilter subsystem in the Linux kernel did not store data in properly
    sized memory locations. A local user could use this to cause a denial of service (system crash).
    (CVE-2024-0607)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - Architecture specifics;

    - Cryptographic API;

    - Android drivers;

    - EDAC drivers;

    - GPU drivers;

    - Media drivers;

    - MTD block device drivers;

    - Network drivers;

    - NVME drivers;

    - TTY drivers;

    - Userspace I/O drivers;

    - F2FS file system;

    - GFS2 file system;

    - IPv6 Networking;

    - AppArmor security module; (CVE-2023-52464, CVE-2023-52448, CVE-2023-52457, CVE-2023-52443,
    CVE-2023-52439, CVE-2023-52612, CVE-2024-26633, CVE-2024-26597, CVE-2023-52449, CVE-2023-52444,
    CVE-2023-52609, CVE-2023-52469, CVE-2023-52445, CVE-2023-52451, CVE-2023-52470, CVE-2023-52454,
    CVE-2023-52436, CVE-2023-52438)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6726-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52612");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1069-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1082-bluefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1089-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1106-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1110-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1121-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1122-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1126-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1127-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-175-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-175-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-176-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-176-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-176-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024-2025 Canonical, Inc. / NASL script (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var kernel_mappings = {
  '18.04': {
    '5.4.0': {
      'generic': '5.4.0-175',
      'lowlatency': '5.4.0-175',
      'ibm': '5.4.0-1069',
      'raspi': '5.4.0-1106',
      'oracle': '5.4.0-1121',
      'aws': '5.4.0-1122',
      'gcp': '5.4.0-1126',
      'azure': '5.4.0-1127'
    }
  },
  '20.04': {
    '5.4.0': {
      'generic': '5.4.0-176',
      'generic-lpae': '5.4.0-176',
      'lowlatency': '5.4.0-176',
      'ibm': '5.4.0-1069',
      'bluefield': '5.4.0-1082',
      'gkeop': '5.4.0-1089',
      'raspi': '5.4.0-1106',
      'kvm': '5.4.0-1110',
      'oracle': '5.4.0-1121',
      'aws': '5.4.0-1122',
      'gcp': '5.4.0-1126',
      'azure': '5.4.0-1127'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6726-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-46838', 'CVE-2023-52340', 'CVE-2023-52429', 'CVE-2023-52436', 'CVE-2023-52438', 'CVE-2023-52439', 'CVE-2023-52443', 'CVE-2023-52444', 'CVE-2023-52445', 'CVE-2023-52448', 'CVE-2023-52449', 'CVE-2023-52451', 'CVE-2023-52454', 'CVE-2023-52457', 'CVE-2023-52464', 'CVE-2023-52469', 'CVE-2023-52470', 'CVE-2023-52609', 'CVE-2023-52612', 'CVE-2024-0607', 'CVE-2024-23851', 'CVE-2024-26597', 'CVE-2024-26633');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6726-1');
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
