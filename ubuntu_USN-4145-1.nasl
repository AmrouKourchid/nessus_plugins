#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4145-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129491);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2016-10905",
    "CVE-2017-18509",
    "CVE-2018-20961",
    "CVE-2018-20976",
    "CVE-2019-0136",
    "CVE-2019-10207",
    "CVE-2019-11487",
    "CVE-2019-13631",
    "CVE-2019-15211",
    "CVE-2019-15215",
    "CVE-2019-15926"
  );
  script_xref(name:"USN", value:"4145-1");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel vulnerabilities (USN-4145-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-4145-1 advisory.

    It was discovered that a race condition existed in the GFS2 file system in the Linux kernel. A local
    attacker could possibly use this to cause a denial of service (system crash). (CVE-2016-10905)

    It was discovered that the IPv6 implementation in the Linux kernel did not properly validate socket
    options in some situations. A local attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2017-18509)

    It was discovered that the USB gadget Midi driver in the Linux kernel contained a double-free
    vulnerability when handling certain error conditions. A local attacker could use this to cause a denial of
    service (system crash). (CVE-2018-20961)

    It was discovered that the XFS file system in the Linux kernel did not properly handle mount failures in
    some situations. A local attacker could possibly use this to cause a denial of service (system crash) or
    execute arbitrary code. (CVE-2018-20976)

    It was discovered that the Intel Wi-Fi device driver in the Linux kernel did not properly validate certain
    Tunneled Direct Link Setup (TDLS). A physically proximate attacker could use this to cause a denial of
    service (Wi-Fi disconnect). (CVE-2019-0136)

    It was discovered that the Bluetooth UART implementation in the Linux kernel did not properly check for
    missing tty operations. A local attacker could use this to cause a denial of service. (CVE-2019-10207)

    It was discovered that an integer overflow existed in the Linux kernel when reference counting pages,
    leading to potential use-after-free issues. A local attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2019-11487)

    It was discovered that the GTCO tablet input driver in the Linux kernel did not properly bounds check the
    initial HID report sent by the device. A physically proximate attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2019-13631)

    It was discovered that the Raremono AM/FM/SW radio device driver in the Linux kernel did not properly
    allocate memory, leading to a use-after-free. A physically proximate attacker could use this to cause a
    denial of service or possibly execute arbitrary code. (CVE-2019-15211)

    It was discovered that a race condition existed in the CPiA2 video4linux device driver for the Linux
    kernel, leading to a use-after-free. A physically proximate attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2019-15215)

    It was discovered that the Atheros mobile chipset driver in the Linux kernel did not properly validate
    data in some situations. An attacker could use this to cause a denial of service (system crash).
    (CVE-2019-15926)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4145-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20961");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1059-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1095-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1123-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1127-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-165-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-165-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-165-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-165-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-165-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-165-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-165-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2019-2024 Canonical, Inc. / NASL script (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '16.04': {
    '4.4.0': {
      'generic': '4.4.0-165',
      'generic-lpae': '4.4.0-165',
      'lowlatency': '4.4.0-165',
      'powerpc-e500mc': '4.4.0-165',
      'powerpc-smp': '4.4.0-165',
      'powerpc64-emb': '4.4.0-165',
      'powerpc64-smp': '4.4.0-165',
      'kvm': '4.4.0-1059',
      'aws': '4.4.0-1095',
      'raspi2': '4.4.0-1123',
      'snapdragon': '4.4.0-1127'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-4145-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2016-10905', 'CVE-2017-18509', 'CVE-2018-20961', 'CVE-2018-20976', 'CVE-2019-0136', 'CVE-2019-10207', 'CVE-2019-11487', 'CVE-2019-13631', 'CVE-2019-15211', 'CVE-2019-15215', 'CVE-2019-15926');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4145-1');
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
