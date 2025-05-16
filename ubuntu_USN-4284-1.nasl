#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4284-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133797);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2019-14615",
    "CVE-2019-15099",
    "CVE-2019-15291",
    "CVE-2019-16229",
    "CVE-2019-16232",
    "CVE-2019-18683",
    "CVE-2019-18786",
    "CVE-2019-18811",
    "CVE-2019-19050",
    "CVE-2019-19057",
    "CVE-2019-19062",
    "CVE-2019-19063",
    "CVE-2019-19071",
    "CVE-2019-19077",
    "CVE-2019-19078",
    "CVE-2019-19082",
    "CVE-2019-19241",
    "CVE-2019-19252",
    "CVE-2019-19332",
    "CVE-2019-19602",
    "CVE-2019-19767",
    "CVE-2019-19947",
    "CVE-2019-19965"
  );
  script_xref(name:"USN", value:"4284-1");

  script_name(english:"Ubuntu 18.04 LTS : Linux kernel vulnerabilities (USN-4284-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-4284-1 advisory.

    It was discovered that the Linux kernel did not properly clear data structures on context switches for
    certain Intel graphics processors. A local attacker could use this to expose sensitive information.
    (CVE-2019-14615)

    It was discovered that the Atheros 802.11ac wireless USB device driver in the Linux kernel did not
    properly validate device metadata. A physically proximate attacker could use this to cause a denial of
    service (system crash). (CVE-2019-15099)

    It was discovered that the HSA Linux kernel driver for AMD GPU devices did not properly check for errors
    in certain situations, leading to a NULL pointer dereference. A local attacker could possibly use this to
    cause a denial of service. (CVE-2019-16229)

    It was discovered that the Marvell 8xxx Libertas WLAN device driver in the Linux kernel did not properly
    check for errors in certain situations, leading to a NULL pointer dereference. A local attacker could
    possibly use this to cause a denial of service. (CVE-2019-16232)

    It was discovered that a race condition existed in the Virtual Video Test Driver in the Linux kernel. An
    attacker with write access to /dev/video0 on a system with the vivid module loaded could possibly use this
    to gain administrative privileges. (CVE-2019-18683)

    It was discovered that the Renesas Digital Radio Interface (DRIF) driver in the Linux kernel did not
    properly initialize data. A local attacker could possibly use this to expose sensitive information (kernel
    memory). (CVE-2019-18786)

    It was discovered that the Sound Open Firmware (SOF) driver in the Linux kernel did not properly
    deallocate memory in certain error conditions. A local attacker could use this to cause a denial of
    service (kernel memory exhaustion). (CVE-2019-18811)

    It was discovered that the crypto subsystem in the Linux kernel did not properly deallocate memory in
    certain error conditions. A local attacker could use this to cause a denial of service (kernel memory
    exhaustion). (CVE-2019-19050, CVE-2019-19062)

    It was discovered that multiple memory leaks existed in the Marvell WiFi-Ex Driver for the Linux kernel. A
    local attacker could possibly use this to cause a denial of service (kernel memory exhaustion).
    (CVE-2019-19057)

    It was discovered that the Realtek rtlwifi USB device driver in the Linux kernel did not properly
    deallocate memory in certain error conditions. A local attacker could possibly use this to cause a denial
    of service (kernel memory exhaustion). (CVE-2019-19063)

    It was discovered that the RSI 91x WLAN device driver in the Linux kernel did not properly deallocate
    memory in certain error conditions. A local attacker could use this to cause a denial of service (kernel
    memory exhaustion). (CVE-2019-19071)

    It was discovered that the Broadcom Netxtreme HCA device driver in the Linux kernel did not properly
    deallocate memory in certain error conditions. A local attacker could possibly use this to cause a denial
    of service (kernel memory exhaustion). (CVE-2019-19077)

    It was discovered that the Atheros 802.11ac wireless USB device driver in the Linux kernel did not
    properly deallocate memory in certain error conditions. A local attacker could possibly use this to cause
    a denial of service (kernel memory exhaustion). (CVE-2019-19078)

    It was discovered that the AMD GPU device drivers in the Linux kernel did not properly deallocate memory
    in certain error conditions. A local attacker could use this to possibly cause a denial of service (kernel
    memory exhaustion). (CVE-2019-19082)

    It was discovered that the IO uring implementation in the Linux kernel did not properly perform
    credentials checks in certain situations. A local attacker could possibly use this to gain administrative
    privileges. (CVE-2019-19241)

    Or Cohen discovered that the virtual console subsystem in the Linux kernel did not properly restrict
    writes to unimplemented vcsu (unicode) devices. A local attacker could possibly use this to cause a denial
    of service (system crash) or have other unspecified impacts. (CVE-2019-19252)

    It was discovered that the KVM hypervisor implementation in the Linux kernel did not properly handle ioctl
    requests to get emulated CPUID features. An attacker with access to /dev/kvm could use this to cause a
    denial of service (system crash). (CVE-2019-19332)

    It was discovered that a race condition existed in the Linux kernel on x86 platforms when keeping track of
    which process was assigned control of the FPU. A local attacker could use this to cause a denial of
    service (memory corruption) or possibly gain administrative privileges. (CVE-2019-19602)

    It was discovered that the ext4 file system implementation in the Linux kernel did not properly handle
    certain conditions. An attacker could use this to specially craft an ext4 file system that, when mounted,
    could cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2019-19767)

    It was discovered that the Kvaser CAN/USB driver in the Linux kernel did not properly initialize memory in
    certain situations. A local attacker could possibly use this to expose sensitive information (kernel
    memory). (CVE-2019-19947)

    Gao Chuan discovered that the SAS Class driver in the Linux kernel contained a race condition that could
    lead to a NULL pointer dereference. A local attacker could possibly use this to cause a denial of service
    (system crash). (CVE-2019-19965)

    It was discovered that the B2C2 FlexCop USB device driver in the Linux kernel did not properly validate
    device metadata. A physically proximate attacker could use this to cause a denial of service (system
    crash). (CVE-2019-15291)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4284-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18683");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19252");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3.0-1012-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3.0-1013-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3.0-1018-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3.0-40-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3.0-40-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3.0-40-lowlatency");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2024 Canonical, Inc. / NASL script (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '18.04': {
    '5.3.0': {
      'generic': '5.3.0-40',
      'generic-lpae': '5.3.0-40',
      'lowlatency': '5.3.0-40',
      'gcp': '5.3.0-1012',
      'azure': '5.3.0-1013',
      'raspi2': '5.3.0-1018'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-4284-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2019-14615', 'CVE-2019-15099', 'CVE-2019-15291', 'CVE-2019-16229', 'CVE-2019-16232', 'CVE-2019-18683', 'CVE-2019-18786', 'CVE-2019-18811', 'CVE-2019-19050', 'CVE-2019-19057', 'CVE-2019-19062', 'CVE-2019-19063', 'CVE-2019-19071', 'CVE-2019-19077', 'CVE-2019-19078', 'CVE-2019-19082', 'CVE-2019-19241', 'CVE-2019-19252', 'CVE-2019-19332', 'CVE-2019-19602', 'CVE-2019-19767', 'CVE-2019-19947', 'CVE-2019-19965');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4284-1');
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
