#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3698-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(110900);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2017-12154",
    "CVE-2017-12193",
    "CVE-2017-15265",
    "CVE-2018-1130",
    "CVE-2018-3665",
    "CVE-2018-5750",
    "CVE-2018-5803",
    "CVE-2018-6927",
    "CVE-2018-7755",
    "CVE-2018-7757"
  );
  script_xref(name:"USN", value:"3698-1");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel vulnerabilities (USN-3698-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-3698-1 advisory.

    It was discovered that the nested KVM implementation in the Linux kernel in some situations did not
    properly prevent second level guests from reading and writing the hardware CR8 register. A local attacker
    in a guest could use this to cause a denial of service (system crash). (CVE-2017-12154)

    Fan Wu, Haoran Qiu, and Shixiong Zhao discovered that the associative array implementation in the Linux
    kernel sometimes did not properly handle adding a new entry. A local attacker could use this to cause a
    denial of service (system crash). (CVE-2017-12193)

    It was discovered that a race condition existed in the ALSA subsystem of the Linux kernel when creating
    and deleting a port via ioctl(). A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2017-15265)

    It was discovered that a null pointer dereference vulnerability existed in the DCCP protocol
    implementation in the Linux kernel. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2018-1130)

    Julian Stecklina and Thomas Prescher discovered that FPU register states (such as MMX, SSE, and AVX
    registers) which are lazily restored are potentially vulnerable to a side channel attack. A local attacker
    could use this to expose sensitive information. (CVE-2018-3665)

    Wang Qize discovered that an information disclosure vulnerability existed in the SMBus driver for ACPI
    Embedded Controllers in the Linux kernel. A local attacker could use this to expose sensitive information
    (kernel pointer addresses). (CVE-2018-5750)

    It was discovered that the SCTP Protocol implementation in the Linux kernel did not properly validate
    userspace provided payload lengths in some situations. A local attacker could use this to cause a denial
    of service (system crash). (CVE-2018-5803)

    It was discovered that an integer overflow error existed in the futex implementation in the Linux kernel.
    A local attacker could use this to cause a denial of service (system crash). (CVE-2018-6927)

    It was discovered that an information leak vulnerability existed in the floppy driver in the Linux kernel.
    A local attacker could use this to expose sensitive information (kernel memory). (CVE-2018-7755)

    It was discovered that a memory leak existed in the SAS driver subsystem of the Linux kernel. A local
    attacker could use this to cause a denial of service (memory exhaustion). (CVE-2018-7757)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3698-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15265");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-6927");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-153-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-153-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-153-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-153-powerpc-e500");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-153-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-153-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-153-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-153-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2018-2024 Canonical, Inc. / NASL script (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '3.13.0-153',
      'generic-lpae': '3.13.0-153',
      'lowlatency': '3.13.0-153',
      'powerpc-e500': '3.13.0-153',
      'powerpc-e500mc': '3.13.0-153',
      'powerpc-smp': '3.13.0-153',
      'powerpc64-emb': '3.13.0-153',
      'powerpc64-smp': '3.13.0-153'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-3698-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2017-12154', 'CVE-2017-12193', 'CVE-2017-15265', 'CVE-2018-1130', 'CVE-2018-3665', 'CVE-2018-5750', 'CVE-2018-5803', 'CVE-2018-6927', 'CVE-2018-7755', 'CVE-2018-7757');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-3698-1');
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
