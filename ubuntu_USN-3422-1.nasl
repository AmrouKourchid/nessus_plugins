#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3422-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(103326);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2016-10044",
    "CVE-2016-10200",
    "CVE-2016-7097",
    "CVE-2016-8650",
    "CVE-2016-9083",
    "CVE-2016-9084",
    "CVE-2016-9178",
    "CVE-2016-9191",
    "CVE-2016-9604",
    "CVE-2016-9754",
    "CVE-2017-1000251",
    "CVE-2017-5970",
    "CVE-2017-6214",
    "CVE-2017-6346",
    "CVE-2017-6951",
    "CVE-2017-7187",
    "CVE-2017-7472",
    "CVE-2017-7541"
  );
  script_xref(name:"USN", value:"3422-1");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel vulnerabilities (USN-3422-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-3422-1 advisory.

    It was discovered that a buffer overflow existed in the Bluetooth stack of the Linux kernel when handling
    L2CAP configuration responses. A physically proximate attacker could use this to cause a denial of service
    (system crash). (CVE-2017-1000251)

    It was discovered that the asynchronous I/O (aio) subsystem of the Linux kernel did not properly set
    permissions on aio memory mappings in some situations. An attacker could use this to more easily exploit
    other vulnerabilities. (CVE-2016-10044)

    Baozeng Ding and Andrey Konovalov discovered a race condition in the L2TPv3 IP Encapsulation
    implementation in the Linux kernel. A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2016-10200)

    Andreas Gruenbacher and Jan Kara discovered that the filesystem implementation in the Linux kernel did not
    clear the setgid bit during a setxattr call. A local attacker could use this to possibly elevate group
    privileges. (CVE-2016-7097)

    Sergej Schumilo, Ralf Spenneberg, and Hendrik Schwartke discovered that the key management subsystem in
    the Linux kernel did not properly allocate memory in some situations. A local attacker could use this to
    cause a denial of service (system crash). (CVE-2016-8650)

    Vlad Tsyrklevich discovered an integer overflow vulnerability in the VFIO PCI driver for the Linux kernel.
    A local attacker with access to a vfio PCI device file could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2016-9083, CVE-2016-9084)

    It was discovered that an information leak existed in __get_user_asm_ex() in the Linux kernel. A local
    attacker could use this to expose sensitive information. (CVE-2016-9178)

    CAI Qian discovered that the sysctl implementation in the Linux kernel did not properly perform reference
    counting in some situations. An unprivileged attacker could use this to cause a denial of service (system
    hang). (CVE-2016-9191)

    It was discovered that the keyring implementation in the Linux kernel in some situations did not prevent
    special internal keyrings from being joined by userspace keyrings. A privileged local attacker could use
    this to bypass module verification. (CVE-2016-9604)

    It was discovered that an integer overflow existed in the trace subsystem of the Linux kernel. A local
    privileged attacker could use this to cause a denial of service (system crash). (CVE-2016-9754)

    Andrey Konovalov discovered that the IPv4 implementation in the Linux kernel did not properly handle
    invalid IP options in some situations. An attacker could use this to cause a denial of service or possibly
    execute arbitrary code. (CVE-2017-5970)

    Dmitry Vyukov discovered that the Linux kernel did not properly handle TCP packets with the URG flag. A
    remote attacker could use this to cause a denial of service. (CVE-2017-6214)

    It was discovered that a race condition existed in the AF_PACKET handling code in the Linux kernel. A
    local attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary
    code. (CVE-2017-6346)

    It was discovered that the keyring implementation in the Linux kernel did not properly restrict searches
    for dead keys. A local attacker could use this to cause a denial of service (system crash).
    (CVE-2017-6951)

    Dmitry Vyukov discovered that the generic SCSI (sg) subsystem in the Linux kernel contained a stack-based
    buffer overflow. A local attacker with access to an sg device could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2017-7187)

    Eric Biggers discovered a memory leak in the keyring implementation in the Linux kernel. A local attacker
    could use this to cause a denial of service (memory consumption). (CVE-2017-7472)

    It was discovered that a buffer overflow existed in the Broadcom FullMAC WLAN driver in the Linux kernel.
    A local attacker could use this to cause a denial of service (system crash) or possibly execute arbitrary
    code. (CVE-2017-7541)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3422-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000251");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-132-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-132-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-132-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-132-powerpc-e500");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-132-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-132-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-132-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.13.0-132-powerpc64-smp");
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
      'generic': '3.13.0-132',
      'generic-lpae': '3.13.0-132',
      'lowlatency': '3.13.0-132',
      'powerpc-e500': '3.13.0-132',
      'powerpc-e500mc': '3.13.0-132',
      'powerpc-smp': '3.13.0-132',
      'powerpc64-emb': '3.13.0-132',
      'powerpc64-smp': '3.13.0-132'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-3422-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2016-7097', 'CVE-2016-8650', 'CVE-2016-9083', 'CVE-2016-9084', 'CVE-2016-9178', 'CVE-2016-9191', 'CVE-2016-9604', 'CVE-2016-9754', 'CVE-2016-10044', 'CVE-2016-10200', 'CVE-2017-5970', 'CVE-2017-6214', 'CVE-2017-6346', 'CVE-2017-6951', 'CVE-2017-7187', 'CVE-2017-7472', 'CVE-2017-7541', 'CVE-2017-1000251');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-3422-1');
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
