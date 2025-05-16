#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7506-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235726);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/12");

  script_cve_id(
    "CVE-2021-46959",
    "CVE-2021-47150",
    "CVE-2021-47163",
    "CVE-2021-47191",
    "CVE-2021-47219",
    "CVE-2021-47245",
    "CVE-2021-47500",
    "CVE-2021-47506",
    "CVE-2021-47587",
    "CVE-2022-23041",
    "CVE-2023-52741",
    "CVE-2024-26689",
    "CVE-2024-26915",
    "CVE-2024-26974",
    "CVE-2024-26996",
    "CVE-2024-35864",
    "CVE-2024-36934",
    "CVE-2024-46771",
    "CVE-2024-46780",
    "CVE-2024-49944",
    "CVE-2024-50237",
    "CVE-2024-50256",
    "CVE-2024-53063",
    "CVE-2024-53066",
    "CVE-2024-53140",
    "CVE-2024-53173",
    "CVE-2024-56598",
    "CVE-2024-56631",
    "CVE-2024-56642",
    "CVE-2024-56650",
    "CVE-2024-56770",
    "CVE-2025-21971"
  );
  script_xref(name:"USN", value:"7506-1");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel vulnerabilities (USN-7506-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-7506-1 advisory.

    Demi Marie Obenour and Simon Gaiser discovered that several Xen para- virtualization device frontends did
    not properly restrict the access rights of device backends. An attacker could possibly use a malicious Xen
    backend to gain access to memory pages of a guest VM or cause a denial of service in the guest.
    (CVE-2022-23041)

    Several security issues were discovered in the Linux kernel. An attacker could possibly use these to
    compromise the system. This update corrects flaws in the following subsystems:

    - Hardware crypto device drivers;

    - GPU drivers;

    - IIO subsystem;

    - Media drivers;

    - Network drivers;

    - SCSI subsystem;

    - SPI subsystem;

    - USB Gadget drivers;

    - Ceph distributed file system;

    - File systems infrastructure;

    - JFS file system;

    - Network file system (NFS) client;

    - Network file system (NFS) server daemon;

    - NILFS2 file system;

    - SMB network file system;

    - CAN network layer;

    - IPv6 networking;

    - MAC80211 subsystem;

    - Netfilter;

    - Netlink;

    - Network traffic control;

    - SCTP protocol;

    - TIPC protocol; (CVE-2024-46780, CVE-2021-47163, CVE-2024-46771, CVE-2021-47506, CVE-2024-36934,
    CVE-2024-35864, CVE-2024-26915, CVE-2021-47150, CVE-2024-50256, CVE-2024-53173, CVE-2024-53066,
    CVE-2024-53063, CVE-2021-47245, CVE-2024-26996, CVE-2024-56642, CVE-2021-47219, CVE-2024-56631,
    CVE-2021-47587, CVE-2021-47191, CVE-2023-52741, CVE-2021-46959, CVE-2024-26689, CVE-2024-26974,
    CVE-2024-56770, CVE-2024-56598, CVE-2024-49944, CVE-2024-50237, CVE-2024-53140, CVE-2024-56650,
    CVE-2021-47500, CVE-2025-21971)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7506-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23041");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-56642");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1144-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1181-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-268-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-268-lowlatency");
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
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var kernel_mappings = {
  '16.04': {
    '4.4.0': {
      'generic': '4.4.0-268',
      'lowlatency': '4.4.0-268',
      'kvm': '4.4.0-1144',
      'aws': '4.4.0-1181'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-7506-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-46959', 'CVE-2021-47150', 'CVE-2021-47163', 'CVE-2021-47191', 'CVE-2021-47219', 'CVE-2021-47245', 'CVE-2021-47500', 'CVE-2021-47506', 'CVE-2021-47587', 'CVE-2022-23041', 'CVE-2023-52741', 'CVE-2024-26689', 'CVE-2024-26915', 'CVE-2024-26974', 'CVE-2024-26996', 'CVE-2024-35864', 'CVE-2024-36934', 'CVE-2024-46771', 'CVE-2024-46780', 'CVE-2024-49944', 'CVE-2024-50237', 'CVE-2024-50256', 'CVE-2024-53063', 'CVE-2024-53066', 'CVE-2024-53140', 'CVE-2024-53173', 'CVE-2024-56598', 'CVE-2024-56631', 'CVE-2024-56642', 'CVE-2024-56650', 'CVE-2024-56770', 'CVE-2025-21971');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-7506-1');
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
