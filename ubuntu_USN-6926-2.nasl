#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6926-2. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204956);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/09");

  script_cve_id(
    "CVE-2023-46343",
    "CVE-2023-52435",
    "CVE-2023-52436",
    "CVE-2023-52443",
    "CVE-2023-52444",
    "CVE-2023-52449",
    "CVE-2023-52469",
    "CVE-2023-52620",
    "CVE-2023-52752",
    "CVE-2024-24857",
    "CVE-2024-24858",
    "CVE-2024-24859",
    "CVE-2024-25739",
    "CVE-2024-25744",
    "CVE-2024-26840",
    "CVE-2024-26857",
    "CVE-2024-26882",
    "CVE-2024-26884",
    "CVE-2024-26886",
    "CVE-2024-26901",
    "CVE-2024-26923",
    "CVE-2024-26934",
    "CVE-2024-27013",
    "CVE-2024-27020",
    "CVE-2024-35978",
    "CVE-2024-35982",
    "CVE-2024-35984",
    "CVE-2024-35997",
    "CVE-2024-36016",
    "CVE-2024-36902"
  );
  script_xref(name:"USN", value:"6926-2");

  script_name(english:"Ubuntu 14.04 LTS / 18.04 LTS : Linux kernel vulnerabilities (USN-6926-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6926-2 advisory.

     discovered that the NFC Controller Interface (NCI) implementation in the Linux kernel did not
    properly handle certain memory allocation failure conditions, leading to a null pointer dereference
    vulnerability. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2023-46343)

    It was discovered that a race condition existed in the Bluetooth subsystem in the Linux kernel when
    modifying certain settings values through debugfs. A privileged local attacker could use this to cause a
    denial of service. (CVE-2024-24857, CVE-2024-24858, CVE-2024-24859)

    Chenyuan Yang discovered that the Unsorted Block Images (UBI) flash device volume management subsystem did
    not properly validate logical eraseblock sizes in certain situations. An attacker could possibly use this
    to cause a denial of service (system crash). (CVE-2024-25739)

    Supraja Sridhara, Benedict Schlter, Mark Kuhne, Andrin Bertschi, and Shweta Shinde discovered that the
    Confidential Computing framework in the Linux kernel for x86 platforms did not properly handle 32-bit
    emulation on TDX and SEV. An attacker with access to the VMM could use this to cause a denial of service
    (guest crash) or possibly execute arbitrary code. (CVE-2024-25744)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - GPU drivers;

    - HID subsystem;

    - I2C subsystem;

    - MTD block device drivers;

    - Network drivers;

    - TTY drivers;

    - USB subsystem;

    - File systems infrastructure;

    - F2FS file system;

    - SMB network file system;

    - BPF subsystem;

    - B.A.T.M.A.N. meshing protocol;

    - Bluetooth subsystem;

    - Networking core;

    - IPv4 networking;

    - IPv6 networking;

    - Netfilter;

    - Unix domain sockets;

    - AppArmor security module; (CVE-2024-26884, CVE-2024-26882, CVE-2024-26923, CVE-2024-26840,
    CVE-2023-52435, CVE-2024-35984, CVE-2024-26886, CVE-2023-52752, CVE-2023-52436, CVE-2024-36016,
    CVE-2024-26857, CVE-2024-36902, CVE-2023-52443, CVE-2024-35997, CVE-2024-35982, CVE-2023-52469,
    CVE-2024-27020, CVE-2024-35978, CVE-2024-26934, CVE-2024-27013, CVE-2023-52449, CVE-2024-26901,
    CVE-2023-52444, CVE-2023-52620)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6926-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26934");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-25744");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1179-azure");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('14.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var kernel_mappings = {
  '14.04': {
    '4.15.0': {
      'azure': '4.15.0-1179'
    }
  },
  '18.04': {
    '4.15.0': {
      'azure': '4.15.0-1179'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6926-2');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2023-46343', 'CVE-2023-52435', 'CVE-2023-52436', 'CVE-2023-52443', 'CVE-2023-52444', 'CVE-2023-52449', 'CVE-2023-52469', 'CVE-2023-52620', 'CVE-2023-52752', 'CVE-2024-24857', 'CVE-2024-24858', 'CVE-2024-24859', 'CVE-2024-25739', 'CVE-2024-25744', 'CVE-2024-26840', 'CVE-2024-26857', 'CVE-2024-26882', 'CVE-2024-26884', 'CVE-2024-26886', 'CVE-2024-26901', 'CVE-2024-26923', 'CVE-2024-26934', 'CVE-2024-27013', 'CVE-2024-27020', 'CVE-2024-35978', 'CVE-2024-35982', 'CVE-2024-35984', 'CVE-2024-35997', 'CVE-2024-36016', 'CVE-2024-36902');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6926-2');
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
