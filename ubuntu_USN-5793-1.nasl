#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5793-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169691);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2022-2663",
    "CVE-2022-3303",
    "CVE-2022-3541",
    "CVE-2022-3543",
    "CVE-2022-3544",
    "CVE-2022-3586",
    "CVE-2022-3623",
    "CVE-2022-3646",
    "CVE-2022-3649",
    "CVE-2022-3910",
    "CVE-2022-3977",
    "CVE-2022-4095",
    "CVE-2022-20421",
    "CVE-2022-40307",
    "CVE-2022-41849",
    "CVE-2022-41850",
    "CVE-2022-43750"
  );
  script_xref(name:"USN", value:"5793-1");

  script_name(english:"Ubuntu 22.10 : Linux kernel vulnerabilities (USN-5793-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
USN-5793-1 advisory.

    It was discovered that the io_uring subsystem in the Linux kernel did not properly perform reference
    counting in some situations, leading to a use- after-free vulnerability. A local attacker could use this
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2022-3910)

    It was discovered that a race condition existed in the Android Binder IPC subsystem in the Linux kernel,
    leading to a use-after-free vulnerability. A local attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2022-20421)

    David Leadbeater discovered that the netfilter IRC protocol tracking implementation in the Linux Kernel
    incorrectly handled certain message payloads in some situations. A remote attacker could possibly use this
    to cause a denial of service or bypass firewall filtering. (CVE-2022-2663)

    It was discovered that the sound subsystem in the Linux kernel contained a race condition in some
    situations. A local attacker could use this to cause a denial of service (system crash). (CVE-2022-3303)

    It was discovered that the Sunplus Ethernet driver in the Linux kernel contained a read-after-free
    vulnerability. An attacker could possibly use this to expose sensitive information (kernel memory)
    (CVE-2022-3541)

    It was discovered that a memory leak existed in the Unix domain socket implementation of the Linux kernel.
    A local attacker could use this to cause a denial of service (memory exhaustion). (CVE-2022-3543)

    It was discovered that the NILFS2 file system implementation in the Linux kernel did not properly
    deallocate memory in certain error conditions. An attacker could use this to cause a denial of service
    (memory exhaustion). (CVE-2022-3544, CVE-2022-3646)

    Gwnaun Jung discovered that the SFB packet scheduling implementation in the Linux kernel contained a use-
    after-free vulnerability. A local attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2022-3586)

    It was discovered that the hugetlb implementation in the Linux kernel contained a race condition in some
    situations. A local attacker could use this to cause a denial of service (system crash) or expose
    sensitive information (kernel memory). (CVE-2022-3623)

    Khalid Masum discovered that the NILFS2 file system implementation in the Linux kernel did not properly
    handle certain error conditions, leading to a use-after-free vulnerability. A local attacker could use
    this to cause a denial of service or possibly execute arbitrary code. (CVE-2022-3649)

    It was discovered that a race condition existed in the MCTP implementation in the Linux kernel, leading to
    a use-after-free vulnerability. A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2022-3977)

    It was discovered that a race condition existed in the EFI capsule loader driver in the Linux kernel,
    leading to a use-after-free vulnerability. A local attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2022-40307)

    Zheng Wang and Zhuorao Yang discovered that the RealTek RTL8712U wireless driver in the Linux kernel
    contained a use-after-free vulnerability. A local attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2022-4095)

    It was discovered that a race condition existed in the SMSC UFX USB driver implementation in the Linux
    kernel, leading to a use-after-free vulnerability. A physically proximate attacker could use this to cause
    a denial of service (system crash) or possibly execute arbitrary code. (CVE-2022-41849)

    It was discovered that a race condition existed in the Roccat HID driver in the Linux kernel, leading to a
    use-after-free vulnerability. A local attacker could use this to cause a denial of service (system crash)
    or possibly execute arbitrary code. (CVE-2022-41850)

    It was discovered that the USB monitoring (usbmon) component in the Linux kernel did not properly set
    permissions on memory mapped in to user space processes. A local attacker could use this to cause a denial
    of service (system crash) or possibly execute arbitrary code. (CVE-2022-43750)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5793-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3623");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-4095");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1011-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1011-raspi-nolpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1014-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1014-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1015-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1016-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-28-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-28-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-28-generic-lpae");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! ('22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '22.10': {
    '5.19.0': {
      'generic': '5.19.0-28',
      'generic-64k': '5.19.0-28',
      'generic-lpae': '5.19.0-28',
      'raspi': '5.19.0-1011',
      'raspi-nolpae': '5.19.0-1011',
      'lowlatency': '5.19.0-1014',
      'lowlatency-64k': '5.19.0-1014',
      'kvm': '5.19.0-1015',
      'aws': '5.19.0-1016'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5793-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-2663', 'CVE-2022-3303', 'CVE-2022-3541', 'CVE-2022-3543', 'CVE-2022-3544', 'CVE-2022-3586', 'CVE-2022-3623', 'CVE-2022-3646', 'CVE-2022-3649', 'CVE-2022-3910', 'CVE-2022-3977', 'CVE-2022-4095', 'CVE-2022-20421', 'CVE-2022-40307', 'CVE-2022-41849', 'CVE-2022-41850', 'CVE-2022-43750');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5793-1');
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
