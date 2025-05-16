#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4094-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(127889);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2018-13053",
    "CVE-2018-13093",
    "CVE-2018-13096",
    "CVE-2018-13097",
    "CVE-2018-13098",
    "CVE-2018-13099",
    "CVE-2018-13100",
    "CVE-2018-14609",
    "CVE-2018-14610",
    "CVE-2018-14611",
    "CVE-2018-14612",
    "CVE-2018-14613",
    "CVE-2018-14614",
    "CVE-2018-14615",
    "CVE-2018-14616",
    "CVE-2018-14617",
    "CVE-2018-16862",
    "CVE-2018-20169",
    "CVE-2018-20511",
    "CVE-2018-20856",
    "CVE-2018-5383",
    "CVE-2019-10126",
    "CVE-2019-1125",
    "CVE-2019-12614",
    "CVE-2019-12818",
    "CVE-2019-12819",
    "CVE-2019-12984",
    "CVE-2019-13233",
    "CVE-2019-13272",
    "CVE-2019-2024",
    "CVE-2019-2101",
    "CVE-2019-3846"
  );
  script_xref(name:"USN", value:"4094-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/10");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Linux kernel vulnerabilities (USN-4094-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-4094-1 advisory.

    It was discovered that the alarmtimer implementation in the Linux kernel contained an integer overflow
    vulnerability. A local attacker could use this to cause a denial of service. (CVE-2018-13053)

    Wen Xu discovered that the XFS filesystem implementation in the Linux kernel did not properly track inode
    validations. An attacker could use this to construct a malicious XFS image that, when mounted, could cause
    a denial of service (system crash). (CVE-2018-13093)

    Wen Xu discovered that the f2fs file system implementation in the Linux kernel did not properly validate
    metadata. An attacker could use this to construct a malicious f2fs image that, when mounted, could cause a
    denial of service (system crash). (CVE-2018-13097, CVE-2018-13099, CVE-2018-13100, CVE-2018-14614,
    CVE-2018-14616, CVE-2018-13096, CVE-2018-13098, CVE-2018-14615)

    Wen Xu and Po-Ning Tseng discovered that btrfs file system implementation in the Linux kernel did not
    properly validate metadata. An attacker could use this to construct a malicious btrfs image that, when
    mounted, could cause a denial of service (system crash). (CVE-2018-14610, CVE-2018-14611, CVE-2018-14612,
    CVE-2018-14613, CVE-2018-14609)

    Wen Xu discovered that the HFS+ filesystem implementation in the Linux kernel did not properly handle
    malformed catalog data in some situations. An attacker could use this to construct a malicious HFS+ image
    that, when mounted, could cause a denial of service (system crash). (CVE-2018-14617)

    Vasily Averin and Pavel Tikhomirov discovered that the cleancache subsystem of the Linux kernel did not
    properly initialize new files in some situations. A local attacker could use this to expose sensitive
    information. (CVE-2018-16862)

    Hui Peng and Mathias Payer discovered that the USB subsystem in the Linux kernel did not properly handle
    size checks when handling an extra USB descriptor. A physically proximate attacker could use this to cause
    a denial of service (system crash). (CVE-2018-20169)

    It was discovered that a use-after-free error existed in the block layer subsystem of the Linux kernel
    when certain failure conditions occurred. A local attacker could possibly use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2018-20856)

    Eli Biham and Lior Neumann discovered that the Bluetooth implementation in the Linux kernel did not
    properly validate elliptic curve parameters during Diffie-Hellman key exchange in some situations. An
    attacker could use this to expose sensitive information. (CVE-2018-5383)

    It was discovered that a heap buffer overflow existed in the Marvell Wireless LAN device driver for the
    Linux kernel. An attacker could use this to cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2019-10126)

    Andrei Vlad Lutas and Dan Lutas discovered that some x86 processors incorrectly handle SWAPGS instructions
    during speculative execution. A local attacker could use this to expose sensitive information (kernel
    memory). (CVE-2019-1125)

    It was discovered that the PowerPC dlpar implementation in the Linux kernel did not properly check for
    allocation errors in some situations. A local attacker could possibly use this to cause a denial of
    service (system crash). (CVE-2019-12614)

    It was discovered that a NULL pointer dereference vulnerabilty existed in the Near-field communication
    (NFC) implementation in the Linux kernel. An attacker could use this to cause a denial of service (system
    crash). (CVE-2019-12818)

    It was discovered that the MDIO bus devices subsystem in the Linux kernel improperly dropped a device
    reference in an error condition, leading to a use-after-free. An attacker could use this to cause a denial
    of service (system crash). (CVE-2019-12819)

    It was discovered that a NULL pointer dereference vulnerability existed in the Near-field communication
    (NFC) implementation in the Linux kernel. A local attacker could use this to cause a denial of service
    (system crash). (CVE-2019-12984)

    Jann Horn discovered a use-after-free vulnerability in the Linux kernel when accessing LDT entries in some
    situations. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2019-13233)

    Jann Horn discovered that the ptrace implementation in the Linux kernel did not properly record
    credentials in some situations. A local attacker could use this to cause a denial of service (system
    crash) or possibly gain administrative privileges. (CVE-2019-13272)

    It was discovered that the Empia EM28xx DVB USB device driver implementation in the Linux kernel contained
    a use-after-free vulnerability when disconnecting the device. An attacker could use this to cause a denial
    of service (system crash). (CVE-2019-2024)

    It was discovered that the USB video device class implementation in the Linux kernel did not properly
    validate control bits, resulting in an out of bounds buffer read. A local attacker could use this to
    possibly expose sensitive information (kernel memory). (CVE-2019-2101)

    It was discovered that the Marvell Wireless LAN device driver in the Linux kernel did not properly
    validate the BSS descriptor. A local attacker could possibly use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2019-3846)

    It was discovered that the Appletalk IP encapsulation driver in the Linux kernel did not properly prevent
    kernel addresses from being copied to user space. A local attacker with the CAP_NET_ADMIN capability could
    use this to expose sensitive information. (CVE-2018-20511)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4094-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3846");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-10126");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Polkit pkexec helper PTRACE_TRACEME local root exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1021-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1040-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1040-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1042-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1043-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1050-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1060-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-58-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-58-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-58-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
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
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '16.04': {
    '4.15.0': {
      'generic': '4.15.0-58',
      'generic-lpae': '4.15.0-58',
      'lowlatency': '4.15.0-58',
      'oracle': '4.15.0-1021',
      'gcp': '4.15.0-1040'
    }
  },
  '18.04': {
    '4.15.0': {
      'generic': '4.15.0-58',
      'generic-lpae': '4.15.0-58',
      'lowlatency': '4.15.0-58',
      'oracle': '4.15.0-1021',
      'gcp': '4.15.0-1040',
      'gke': '4.15.0-1040',
      'kvm': '4.15.0-1042',
      'raspi2': '4.15.0-1043',
      'oem': '4.15.0-1050',
      'snapdragon': '4.15.0-1060'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-4094-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2018-5383', 'CVE-2018-13053', 'CVE-2018-13093', 'CVE-2018-13096', 'CVE-2018-13097', 'CVE-2018-13098', 'CVE-2018-13099', 'CVE-2018-13100', 'CVE-2018-14609', 'CVE-2018-14610', 'CVE-2018-14611', 'CVE-2018-14612', 'CVE-2018-14613', 'CVE-2018-14614', 'CVE-2018-14615', 'CVE-2018-14616', 'CVE-2018-14617', 'CVE-2018-16862', 'CVE-2018-20169', 'CVE-2018-20511', 'CVE-2018-20856', 'CVE-2019-1125', 'CVE-2019-2024', 'CVE-2019-2101', 'CVE-2019-3846', 'CVE-2019-10126', 'CVE-2019-12614', 'CVE-2019-12818', 'CVE-2019-12819', 'CVE-2019-12984', 'CVE-2019-13233', 'CVE-2019-13272');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4094-1');
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
