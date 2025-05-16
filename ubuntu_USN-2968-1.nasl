#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2968-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(91088);
  script_version("2.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2015-7515",
    "CVE-2015-8830",
    "CVE-2016-0774",
    "CVE-2016-0821",
    "CVE-2016-2184",
    "CVE-2016-2185",
    "CVE-2016-2186",
    "CVE-2016-2188",
    "CVE-2016-3136",
    "CVE-2016-3137",
    "CVE-2016-3138",
    "CVE-2016-3140",
    "CVE-2016-3156",
    "CVE-2016-3157",
    "CVE-2016-3689"
  );
  script_xref(name:"USN", value:"2968-1");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel vulnerabilities (USN-2968-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-2968-1 advisory.

    Ralf Spenneberg discovered that the Aiptek Tablet USB device driver in the Linux kernel did not properly
    validate the endpoints reported by the device. An attacker with physical access could cause a denial of
    service (system crash). (CVE-2015-7515)

    Ben Hawkes discovered that the Linux kernel's AIO interface allowed single writes greater than 2GB, which
    could cause an integer overflow when writing to certain filesystems, socket or device types. A local
    attacker could this to cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2015-8830)

    It was discovered that the Linux kernel did not keep accurate track of pipe buffer details when error
    conditions occurred, due to an incomplete fix for CVE-2015-1805. A local attacker could use this to cause
    a denial of service (system crash) or possibly execute arbitrary code with administrative privileges.
    (CVE-2016-0774)

    Zach Riggle discovered that the Linux kernel's list poison feature did not take into account the
    mmap_min_addr value. A local attacker could use this to bypass the kernel's poison-pointer protection
    mechanism while attempting to exploit an existing kernel vulnerability. (CVE-2016-0821)

    Ralf Spenneberg discovered that the USB sound subsystem in the Linux kernel did not properly validate USB
    device descriptors. An attacker with physical access could use this to cause a denial of service (system
    crash). (CVE-2016-2184)

    Ralf Spenneberg discovered that the ATI Wonder Remote II USB driver in the Linux kernel did not properly
    validate USB device descriptors. An attacker with physical access could use this to cause a denial of
    service (system crash). (CVE-2016-2185)

    Ralf Spenneberg discovered that the PowerMate USB driver in the Linux kernel did not properly validate USB
    device descriptors. An attacker with physical access could use this to cause a denial of service (system
    crash). (CVE-2016-2186)

    Ralf Spenneberg discovered that the I/O-Warrior USB device driver in the Linux kernel did not properly
    validate USB device descriptors. An attacker with physical access could use this to cause a denial of
    service (system crash). (CVE-2016-2188)

    Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the MCT USB RS232 Converter device
    driver in the Linux kernel did not properly validate USB device descriptors. An attacker with physical
    access could use this to cause a denial of service (system crash). (CVE-2016-3136)

    Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the Cypress M8 USB device driver
    in the Linux kernel did not properly validate USB device descriptors. An attacker with physical access
    could use this to cause a denial of service (system crash). (CVE-2016-3137)

    Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the USB abstract device control
    driver for modems and ISDN adapters did not validate endpoint descriptors. An attacker with physical
    access could use this to cause a denial of service (system crash). (CVE-2016-3138)

    Sergej Schumilo, Hendrik Schwartke, and Ralf Spenneberg discovered that the Linux kernel's USB driver for
    Digi AccelePort serial converters did not properly validate USB device descriptors. An attacker with
    physical access could use this to cause a denial of service (system crash). (CVE-2016-3140)

    It was discovered that the IPv4 implementation in the Linux kernel did not perform the destruction of inet
    device objects properly. An attacker in a guest OS could use this to cause a denial of service (networking
    outage) in the host OS. (CVE-2016-3156)

    Andy Lutomirski discovered that the Linux kernel did not properly context- switch IOPL on 64-bit PV Xen
    guests. An attacker in a guest OS could use this to cause a denial of service (guest OS crash), gain
    privileges, or obtain sensitive information. (CVE-2016-3157)

    It was discovered that the Linux kernel's USB driver for IMS Passenger Control Unit devices did not
    properly validate the device's interfaces. An attacker with physical access could use this to cause a
    denial of service (system crash). (CVE-2016-3689)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2968-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3157");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-86-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-86-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-86-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-86-powerpc-e500");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-86-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-86-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-86-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-86-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2016-2024 Canonical, Inc. / NASL script (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('14.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '14.04': {
    '3.13.0': {
      'generic': '3.13.0-86',
      'generic-lpae': '3.13.0-86',
      'lowlatency': '3.13.0-86',
      'powerpc-e500': '3.13.0-86',
      'powerpc-e500mc': '3.13.0-86',
      'powerpc-smp': '3.13.0-86',
      'powerpc64-emb': '3.13.0-86',
      'powerpc64-smp': '3.13.0-86'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-2968-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2015-7515', 'CVE-2015-8830', 'CVE-2016-0774', 'CVE-2016-0821', 'CVE-2016-2184', 'CVE-2016-2185', 'CVE-2016-2186', 'CVE-2016-2188', 'CVE-2016-3136', 'CVE-2016-3137', 'CVE-2016-3138', 'CVE-2016-3140', 'CVE-2016-3156', 'CVE-2016-3157', 'CVE-2016-3689');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-2968-1');
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
