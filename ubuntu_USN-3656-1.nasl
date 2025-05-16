#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3656-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(110051);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2017-17975",
    "CVE-2017-18193",
    "CVE-2017-18222",
    "CVE-2018-1065",
    "CVE-2018-1068",
    "CVE-2018-1130",
    "CVE-2018-5803",
    "CVE-2018-7480",
    "CVE-2018-7757",
    "CVE-2018-7995",
    "CVE-2018-8781",
    "CVE-2018-8822"
  );
  script_xref(name:"USN", value:"3656-1");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel (Raspberry Pi 2, Snapdragon) vulnerabilities (USN-3656-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-3656-1 advisory.

    Tuba Yavuz discovered that a double-free error existed in the USBTV007 driver of the Linux kernel. A local
    attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary code.
    (CVE-2017-17975)

    It was discovered that a race condition existed in the F2FS implementation in the Linux kernel. A local
    attacker could use this to cause a denial of service (system crash). (CVE-2017-18193)

    It was discovered that a buffer overflow existed in the Hisilicon HNS Ethernet Device driver in the Linux
    kernel. A local attacker could use this to cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2017-18222)

    It was discovered that the netfilter subsystem in the Linux kernel did not validate that rules containing
    jumps contained user-defined chains. A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2018-1065)

    It was discovered that the netfilter subsystem of the Linux kernel did not properly validate ebtables
    offsets. A local attacker could use this to cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2018-1068)

    It was discovered that a null pointer dereference vulnerability existed in the DCCP protocol
    implementation in the Linux kernel. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2018-1130)

    It was discovered that the SCTP Protocol implementation in the Linux kernel did not properly validate
    userspace provided payload lengths in some situations. A local attacker could use this to cause a denial
    of service (system crash). (CVE-2018-5803)

    It was discovered that a double free error existed in the block layer subsystem of the Linux kernel when
    setting up a request queue. A local attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2018-7480)

    It was discovered that a memory leak existed in the SAS driver subsystem of the Linux kernel. A local
    attacker could use this to cause a denial of service (memory exhaustion). (CVE-2018-7757)

    It was discovered that a race condition existed in the x86 machine check handler in the Linux kernel. A
    local privileged attacker could use this to cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2018-7995)

    Eyal Itkin discovered that the USB displaylink video adapter driver in the Linux kernel did not properly
    validate mmap offsets sent from userspace. A local attacker could use this to expose sensitive information
    (kernel memory) or possibly execute arbitrary code. (CVE-2018-8781)

    Silvio Cesare discovered a buffer overwrite existed in the NCPFS implementation in the Linux kernel. A
    remote attacker controlling a malicious NCPFS server could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2018-8822)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3656-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8822");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1090-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1093-snapdragon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
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
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '16.04': {
    '4.4.0': {
      'raspi2': '4.4.0-1090',
      'snapdragon': '4.4.0-1093'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-3656-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2017-17975', 'CVE-2017-18193', 'CVE-2017-18222', 'CVE-2018-1065', 'CVE-2018-1068', 'CVE-2018-1130', 'CVE-2018-5803', 'CVE-2018-7480', 'CVE-2018-7757', 'CVE-2018-7995', 'CVE-2018-8781', 'CVE-2018-8822');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-3656-1');
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
