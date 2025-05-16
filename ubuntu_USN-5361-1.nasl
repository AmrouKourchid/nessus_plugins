#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5361-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159387);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-3702",
    "CVE-2020-12888",
    "CVE-2020-26141",
    "CVE-2020-26145",
    "CVE-2021-0920",
    "CVE-2021-0935",
    "CVE-2021-4083",
    "CVE-2021-28964",
    "CVE-2021-31916",
    "CVE-2021-37159",
    "CVE-2021-39636",
    "CVE-2021-42739",
    "CVE-2021-43976",
    "CVE-2021-45486"
  );
  script_xref(name:"USN", value:"5361-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"Ubuntu 16.04 ESM : Linux kernel vulnerabilities (USN-5361-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-5361-1 advisory.

    It was discovered that the VFIO PCI driver in the Linux kernel did not properly handle attempts to access
    disabled memory spaces. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2020-12888)

    Mathy Vanhoef discovered that the Linux kernels WiFi implementation did not properly verify certain
    fragmented frames. A physically proximate attacker could possibly use this issue to inject or decrypt
    packets. (CVE-2020-26141)

    Mathy Vanhoef discovered that the Linux kernels WiFi implementation accepted plaintext fragments in
    certain situations. A physically proximate attacker could use this issue to inject packets.
    (CVE-2020-26145)

    It was discovered that a race condition existed in the Atheros Ath9k WiFi driver in the Linux kernel. An
    attacker could possibly use this to expose sensitive information (WiFi network traffic). (CVE-2020-3702)

    It was discovered a race condition existed in the Unix domain socket implementation in the Linux kernel,
    leading to a use-after-free vulnerability. A local attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2021-0920)

    It was discovered that the IPv6 implementation in the Linux kernel contained a use-after-free
    vulnerability. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2021-0935)

    Zygo Blaxell discovered that the btrfs file system implementation in the Linux kernel contained a race
    condition during certain cloning operations. A local attacker could possibly use this to cause a denial of
    service (system crash). (CVE-2021-28964)

    Dan Carpenter discovered that the block device manager (dm) implementation in the Linux kernel contained a
    buffer overflow in the ioctl for listing devices. A privileged local attacker could use this to cause a
    denial of service (system crash). (CVE-2021-31916)

    It was discovered that the Option USB High Speed Mobile device driver in the Linux kernel did not properly
    handle error conditions. A physically proximate attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2021-37159)

    It was discovered that the network packet filtering implementation in the Linux kernel did not properly
    initialize information in certain circumstances. A local attacker could use this to expose sensitive
    information (kernel memory). (CVE-2021-39636)

    Jann Horn discovered a race condition in the Unix domain socket implementation in the Linux kernel that
    could result in a read-after-free. A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2021-4083)

    Luo Likang discovered that the FireDTV Firewire driver in the Linux kernel did not properly perform bounds
    checking in some situations. A local attacker could use this to cause a denial of service (system crash)
    or possibly execute arbitrary code. (CVE-2021-42739)

    Brendan Dolan-Gavitt discovered that the Marvell WiFi-Ex USB device driver in the Linux kernel did not
    properly handle some error conditions. A physically proximate attacker could use this to cause a denial of
    service (system crash). (CVE-2021-43976)

    Amit Klein discovered that the IPv4 implementation in the Linux kernel could disclose internal state in
    some situations. An attacker could possibly use this to expose sensitive information. (CVE-2021-45486)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5361-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0935");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-4083");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1104-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1139-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-223-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-223-lowlatency");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2024 Canonical, Inc. / NASL script (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
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
      'generic': '4.4.0-223',
      'lowlatency': '4.4.0-223',
      'kvm': '4.4.0-1104',
      'aws': '4.4.0-1139'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5361-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2020-3702', 'CVE-2020-12888', 'CVE-2020-26141', 'CVE-2020-26145', 'CVE-2021-0920', 'CVE-2021-0935', 'CVE-2021-4083', 'CVE-2021-28964', 'CVE-2021-31916', 'CVE-2021-37159', 'CVE-2021-39636', 'CVE-2021-42739', 'CVE-2021-43976', 'CVE-2021-45486');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5361-1');
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
