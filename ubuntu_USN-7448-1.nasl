#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7448-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234778);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id(
    "CVE-2024-57948",
    "CVE-2024-57949",
    "CVE-2024-57950",
    "CVE-2024-57951",
    "CVE-2024-57952",
    "CVE-2025-2312",
    "CVE-2025-21665",
    "CVE-2025-21666",
    "CVE-2025-21667",
    "CVE-2025-21668",
    "CVE-2025-21669",
    "CVE-2025-21670",
    "CVE-2025-21672",
    "CVE-2025-21673",
    "CVE-2025-21674",
    "CVE-2025-21675",
    "CVE-2025-21676",
    "CVE-2025-21677",
    "CVE-2025-21678",
    "CVE-2025-21680",
    "CVE-2025-21681",
    "CVE-2025-21682",
    "CVE-2025-21683",
    "CVE-2025-21684",
    "CVE-2025-21685",
    "CVE-2025-21689",
    "CVE-2025-21690",
    "CVE-2025-21691",
    "CVE-2025-21692",
    "CVE-2025-21693",
    "CVE-2025-21694",
    "CVE-2025-21695",
    "CVE-2025-21696",
    "CVE-2025-21697",
    "CVE-2025-21699",
    "CVE-2025-21700",
    "CVE-2025-21701",
    "CVE-2025-21702",
    "CVE-2025-21703",
    "CVE-2025-21756",
    "CVE-2025-21993"
  );
  script_xref(name:"USN", value:"7448-1");
  script_xref(name:"IAVB", value:"2025-B-0066");

  script_name(english:"Ubuntu 24.04 LTS / 24.10 : Linux kernel vulnerabilities (USN-7448-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 24.04 LTS / 24.10 host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-7448-1 advisory.

    It was discovered that the CIFS network file system implementation in the Linux kernel did not properly
    verify the target namespace when handling upcalls. An attacker could use this to expose sensitive
    information. (CVE-2025-2312)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - GPIO subsystem;

    - GPU drivers;

    - IRQ chip drivers;

    - Network drivers;

    - Mellanox network drivers;

    - x86 platform drivers;

    - i.MX PM domains;

    - SCSI subsystem;

    - USB Serial drivers;

    - AFS file system;

    - GFS2 file system;

    - File systems infrastructure;

    - Proc file system;

    - SMB network file system;

    - Timer subsystem;

    - Kernel CPU control infrastructure;

    - Memory management;

    - Networking core;

    - Ethtool driver;

    - IEEE 802.15.4 subsystem;

    - Open vSwitch;

    - Network traffic control;

    - VMware vSockets driver; (CVE-2025-21694, CVE-2025-21993, CVE-2025-21684, CVE-2025-21681, CVE-2025-21675,
    CVE-2025-21672, CVE-2025-21696, CVE-2025-21691, CVE-2025-21683, CVE-2025-21666, CVE-2025-21682,
    CVE-2025-21697, CVE-2025-21668, CVE-2025-21701, CVE-2025-21670, CVE-2025-21676, CVE-2025-21695,
    CVE-2025-21692, CVE-2025-21674, CVE-2025-21699, CVE-2024-57948, CVE-2025-21677, CVE-2024-57951,
    CVE-2025-21702, CVE-2025-21700, CVE-2024-57949, CVE-2025-21669, CVE-2025-21703, CVE-2025-21756,
    CVE-2025-21667, CVE-2024-57952, CVE-2024-57950, CVE-2025-21685, CVE-2025-21693, CVE-2025-21678,
    CVE-2025-21665, CVE-2025-21680, CVE-2025-21689, CVE-2025-21690, CVE-2025-21673)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7448-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21692");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.11.0-1013-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-6.11.0-1013-azure-fde");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (! ('24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '24.04': {
    '6.11.0': {
      'azure': '6.11.0-1013',
      'azure-fde': '6.11.0-1013'
    }
  },
  '24.10': {
    '6.11.0': {
      'azure': '6.11.0-1013',
      'azure-fde': '6.11.0-1013'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7448-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2024-57948', 'CVE-2024-57949', 'CVE-2024-57950', 'CVE-2024-57951', 'CVE-2024-57952', 'CVE-2025-2312', 'CVE-2025-21665', 'CVE-2025-21666', 'CVE-2025-21667', 'CVE-2025-21668', 'CVE-2025-21669', 'CVE-2025-21670', 'CVE-2025-21672', 'CVE-2025-21673', 'CVE-2025-21674', 'CVE-2025-21675', 'CVE-2025-21676', 'CVE-2025-21677', 'CVE-2025-21678', 'CVE-2025-21680', 'CVE-2025-21681', 'CVE-2025-21682', 'CVE-2025-21683', 'CVE-2025-21684', 'CVE-2025-21685', 'CVE-2025-21689', 'CVE-2025-21690', 'CVE-2025-21691', 'CVE-2025-21692', 'CVE-2025-21693', 'CVE-2025-21694', 'CVE-2025-21695', 'CVE-2025-21696', 'CVE-2025-21697', 'CVE-2025-21699', 'CVE-2025-21700', 'CVE-2025-21701', 'CVE-2025-21702', 'CVE-2025-21703', 'CVE-2025-21756', 'CVE-2025-21993');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7448-1');
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
