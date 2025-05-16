#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7184-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213506);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/07");

  script_cve_id(
    "CVE-2021-47086",
    "CVE-2021-47118",
    "CVE-2021-47501",
    "CVE-2022-36402",
    "CVE-2023-35827",
    "CVE-2023-52507",
    "CVE-2023-52509",
    "CVE-2023-52594",
    "CVE-2024-26625",
    "CVE-2024-26777",
    "CVE-2024-35886",
    "CVE-2024-36270",
    "CVE-2024-36941",
    "CVE-2024-36946",
    "CVE-2024-36968",
    "CVE-2024-38619",
    "CVE-2024-38633",
    "CVE-2024-39301",
    "CVE-2024-40912",
    "CVE-2024-40959",
    "CVE-2024-42090",
    "CVE-2024-42101",
    "CVE-2024-42153",
    "CVE-2024-43856",
    "CVE-2024-43884",
    "CVE-2024-44944",
    "CVE-2024-44947",
    "CVE-2024-45021",
    "CVE-2024-49967",
    "CVE-2024-53057"
  );
  script_xref(name:"USN", value:"7184-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : Linux kernel vulnerabilities (USN-7184-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-7184-1 advisory.

    Ziming Zhang discovered that the VMware Virtual GPU DRM driver in the Linux kernel contained an integer
    overflow vulnerability. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2022-36402)

    Zheng Wang discovered a use-after-free in the Renesas Ethernet AVB driver in the Linux kernel during
    device removal. A privileged attacker could use this to cause a denial of service (system crash).
    (CVE-2023-35827)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - GPU drivers;

    - I2C subsystem;

    - Network drivers;

    - Pin controllers subsystem;

    - TTY drivers;

    - USB Mass Storage drivers;

    - Framebuffer layer;

    - Ext4 file system;

    - File systems infrastructure;

    - Bluetooth subsystem;

    - Kernel init infrastructure;

    - DMA mapping infrastructure;

    - Memory management;

    - 9P file system network protocol;

    - IPv4 networking;

    - IPv6 networking;

    - Logical Link layer;

    - MAC80211 subsystem;

    - Netfilter;

    - NFC subsystem;

    - Phonet protocol;

    - Network traffic control;

    - Wireless networking; (CVE-2024-44944, CVE-2023-52507, CVE-2024-42101, CVE-2021-47118, CVE-2024-36941,
    CVE-2024-38633, CVE-2021-47086, CVE-2024-26625, CVE-2024-39301, CVE-2024-42090, CVE-2024-53057,
    CVE-2024-26777, CVE-2024-36946, CVE-2024-42153, CVE-2024-40912, CVE-2024-36968, CVE-2024-43856,
    CVE-2024-49967, CVE-2024-43884, CVE-2023-52509, CVE-2023-52594, CVE-2024-36270, CVE-2024-44947,
    CVE-2024-45021, CVE-2024-35886, CVE-2024-40959, CVE-2021-47501, CVE-2024-38619)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7184-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53057");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1139-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1140-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1177-aws");
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
if (! ('14.04' >< os_release || '16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var kernel_mappings = {
  '14.04': {
    '4.4.0': {
      'aws': '4.4.0-1139'
    }
  },
  '16.04': {
    '4.4.0': {
      'kvm': '4.4.0-1140',
      'aws': '4.4.0-1177'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7184-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-47086', 'CVE-2021-47118', 'CVE-2021-47501', 'CVE-2022-36402', 'CVE-2023-35827', 'CVE-2023-52507', 'CVE-2023-52509', 'CVE-2023-52594', 'CVE-2024-26625', 'CVE-2024-26777', 'CVE-2024-35886', 'CVE-2024-36270', 'CVE-2024-36941', 'CVE-2024-36946', 'CVE-2024-36968', 'CVE-2024-38619', 'CVE-2024-38633', 'CVE-2024-39301', 'CVE-2024-40912', 'CVE-2024-40959', 'CVE-2024-42090', 'CVE-2024-42101', 'CVE-2024-42153', 'CVE-2024-43856', 'CVE-2024-43884', 'CVE-2024-44944', 'CVE-2024-44947', 'CVE-2024-45021', 'CVE-2024-49967', 'CVE-2024-53057');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7184-1');
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
