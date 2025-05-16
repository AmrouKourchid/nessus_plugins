#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3360-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(101928);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2014-9900",
    "CVE-2015-8944",
    "CVE-2015-8955",
    "CVE-2015-8962",
    "CVE-2015-8963",
    "CVE-2015-8964",
    "CVE-2015-8966",
    "CVE-2015-8967",
    "CVE-2016-10088",
    "CVE-2017-1000380",
    "CVE-2017-7346",
    "CVE-2017-7895",
    "CVE-2017-8924",
    "CVE-2017-8925",
    "CVE-2017-9605"
  );
  script_xref(name:"USN", value:"3360-1");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel vulnerabilities (USN-3360-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-3360-1 advisory.

    It was discovered that the Linux kernel did not properly initialize a Wake- on-Lan data structure. A local
    attacker could use this to expose sensitive information (kernel memory). (CVE-2014-9900)

    It was discovered that the Linux kernel did not properly restrict access to /proc/iomem. A local attacker
    could use this to expose sensitive information. (CVE-2015-8944)

    It was discovered that a use-after-free vulnerability existed in the performance events and counters
    subsystem of the Linux kernel for ARM64. A local attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2015-8955)

    It was discovered that the SCSI generic (sg) driver in the Linux kernel contained a double-free
    vulnerability. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2015-8962)

    Sasha Levin discovered that a race condition existed in the performance events and counters subsystem of
    the Linux kernel when handling CPU unplug events. A local attacker could use this to cause a denial of
    service (system crash) or possibly execute arbitrary code. (CVE-2015-8963)

    Tilman Schmidt and Sasha Levin discovered a use-after-free condition in the TTY implementation in the
    Linux kernel. A local attacker could use this to expose sensitive information (kernel memory).
    (CVE-2015-8964)

    It was discovered that the fcntl64() system call in the Linux kernel did not properly set memory limits
    when returning on 32-bit ARM processors. A local attacker could use this to gain administrative
    privileges. (CVE-2015-8966)

    It was discovered that the system call table for ARM 64-bit processors in the Linux kernel was not write-
    protected. An attacker could use this in conjunction with another kernel vulnerability to execute
    arbitrary code. (CVE-2015-8967)

    It was discovered that the generic SCSI block layer in the Linux kernel did not properly restrict write
    operations in certain situations. A local attacker could use this to cause a denial of service (system
    crash) or possibly gain administrative privileges. (CVE-2016-10088)

    Alexander Potapenko discovered a race condition in the Advanced Linux Sound Architecture (ALSA) subsystem
    in the Linux kernel. A local attacker could use this to expose sensitive information (kernel memory).
    (CVE-2017-1000380)

    Li Qiang discovered that the DRM driver for VMware Virtual GPUs in the Linux kernel did not properly
    validate some ioctl arguments. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2017-7346)

    Tuomas Haanp and Ari Kauppi discovered that the NFSv2 and NFSv3 server implementations in the Linux
    kernel did not properly check for the end of buffer. A remote attacker could use this to craft requests
    that cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2017-7895)

    It was discovered that an integer underflow existed in the Edgeport USB Serial Converter device driver of
    the Linux kernel. An attacker with physical access could use this to expose sensitive information (kernel
    memory). (CVE-2017-8924)

    It was discovered that the USB ZyXEL omni.net LCD PLUS driver in the Linux kernel did not properly perform
    reference counting. A local attacker could use this to cause a denial of service (tty exhaustion).
    (CVE-2017-8925)

    Murray McAllister discovered that the DRM driver for VMware Virtual GPUs in the Linux kernel did not
    properly initialize memory. A local attacker could use this to expose sensitive information (kernel
    memory). (CVE-2017-9605)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3360-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7895");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-125-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-125-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-125-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-125-powerpc-e500");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-125-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-125-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-125-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-125-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2017-2024 Canonical, Inc. / NASL script (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '3.13.0-125',
      'generic-lpae': '3.13.0-125',
      'lowlatency': '3.13.0-125',
      'powerpc-e500': '3.13.0-125',
      'powerpc-e500mc': '3.13.0-125',
      'powerpc-smp': '3.13.0-125',
      'powerpc64-emb': '3.13.0-125',
      'powerpc64-smp': '3.13.0-125'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-3360-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2014-9900', 'CVE-2015-8944', 'CVE-2015-8955', 'CVE-2015-8962', 'CVE-2015-8963', 'CVE-2015-8964', 'CVE-2015-8966', 'CVE-2015-8967', 'CVE-2016-10088', 'CVE-2017-7346', 'CVE-2017-7895', 'CVE-2017-8924', 'CVE-2017-8925', 'CVE-2017-9605', 'CVE-2017-1000380');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-3360-1');
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
