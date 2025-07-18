#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7148-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212266);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/10");

  script_cve_id(
    "CVE-2021-47055",
    "CVE-2022-24448",
    "CVE-2022-48733",
    "CVE-2022-48938",
    "CVE-2022-48943",
    "CVE-2023-52502",
    "CVE-2023-52531",
    "CVE-2023-52578",
    "CVE-2023-52599",
    "CVE-2023-52614",
    "CVE-2024-26633",
    "CVE-2024-26636",
    "CVE-2024-26668",
    "CVE-2024-26675",
    "CVE-2024-27397",
    "CVE-2024-35877",
    "CVE-2024-38538",
    "CVE-2024-38560",
    "CVE-2024-41059",
    "CVE-2024-41071",
    "CVE-2024-41089",
    "CVE-2024-41095",
    "CVE-2024-42104",
    "CVE-2024-42240",
    "CVE-2024-42244",
    "CVE-2024-42309",
    "CVE-2024-42310",
    "CVE-2024-43882",
    "CVE-2024-44942",
    "CVE-2024-44987",
    "CVE-2024-44998",
    "CVE-2024-46722",
    "CVE-2024-46723",
    "CVE-2024-46738",
    "CVE-2024-46743",
    "CVE-2024-46756",
    "CVE-2024-46757",
    "CVE-2024-46758",
    "CVE-2024-46759",
    "CVE-2024-46800"
  );
  script_xref(name:"USN", value:"7148-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : Linux kernel vulnerabilities (USN-7148-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-7148-1 advisory.

    Lyu Tao discovered that the NFS implementation in the Linux kernel did not properly handle requests to
    open a directory on a regular file. A local attacker could use this to expose sensitive information
    (kernel memory).

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - x86 architecture;

    - ATM drivers;

    - Device frequency scaling framework;

    - GPU drivers;

    - Hardware monitoring drivers;

    - VMware VMCI Driver;

    - MTD block device drivers;

    - Network drivers;

    - Device tree and open firmware driver;

    - SCSI subsystem;

    - USB Serial drivers;

    - BTRFS file system;

    - File systems infrastructure;

    - F2FS file system;

    - JFS file system;

    - NILFS2 file system;

    - Netfilter;

    - Memory management;

    - Ethernet bridge;

    - IPv6 networking;

    - Logical Link layer;

    - MAC80211 subsystem;

    - NFC subsystem;

    - Network traffic control; (CVE-2021-47055, CVE-2024-26675, CVE-2024-42244, CVE-2024-46743,
    CVE-2024-41095, CVE-2024-46756, CVE-2024-46723, CVE-2024-46759, CVE-2024-35877, CVE-2024-38538,
    CVE-2024-26668, CVE-2024-44998, CVE-2024-42309, CVE-2024-46758, CVE-2024-46800, CVE-2022-48733,
    CVE-2023-52531, CVE-2023-52599, CVE-2024-46722, CVE-2024-42240, CVE-2024-44987, CVE-2023-52502,
    CVE-2023-52578, CVE-2024-41059, CVE-2024-41071, CVE-2024-44942, CVE-2024-46738, CVE-2022-48943,
    CVE-2023-52614, CVE-2024-27397, CVE-2024-38560, CVE-2024-43882, CVE-2024-42104, CVE-2024-46757,
    CVE-2024-26636, CVE-2024-26633, CVE-2024-41089, CVE-2024-42310, CVE-2022-48938)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7148-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24448");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-46800");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1138-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1139-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1176-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-261-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-261-lowlatency");
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
      'generic': '4.4.0-261',
      'lowlatency': '4.4.0-261',
      'aws': '4.4.0-1138'
    }
  },
  '16.04': {
    '4.4.0': {
      'generic': '4.4.0-261',
      'lowlatency': '4.4.0-261',
      'kvm': '4.4.0-1139',
      'aws': '4.4.0-1176'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7148-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-47055', 'CVE-2022-24448', 'CVE-2022-48733', 'CVE-2022-48938', 'CVE-2022-48943', 'CVE-2023-52502', 'CVE-2023-52531', 'CVE-2023-52578', 'CVE-2023-52599', 'CVE-2023-52614', 'CVE-2024-26633', 'CVE-2024-26636', 'CVE-2024-26668', 'CVE-2024-26675', 'CVE-2024-27397', 'CVE-2024-35877', 'CVE-2024-38538', 'CVE-2024-38560', 'CVE-2024-41059', 'CVE-2024-41071', 'CVE-2024-41089', 'CVE-2024-41095', 'CVE-2024-42104', 'CVE-2024-42240', 'CVE-2024-42244', 'CVE-2024-42309', 'CVE-2024-42310', 'CVE-2024-43882', 'CVE-2024-44942', 'CVE-2024-44987', 'CVE-2024-44998', 'CVE-2024-46722', 'CVE-2024-46723', 'CVE-2024-46738', 'CVE-2024-46743', 'CVE-2024-46756', 'CVE-2024-46757', 'CVE-2024-46758', 'CVE-2024-46759', 'CVE-2024-46800');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7148-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : extra
  );
  exit(0);
}
