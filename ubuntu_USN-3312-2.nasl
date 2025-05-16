#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3312-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100665);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2016-7913",
    "CVE-2016-7917",
    "CVE-2016-8632",
    "CVE-2016-9083",
    "CVE-2016-9084",
    "CVE-2016-9604",
    "CVE-2017-2596",
    "CVE-2017-2671",
    "CVE-2017-6001",
    "CVE-2017-7472",
    "CVE-2017-7618",
    "CVE-2017-7645",
    "CVE-2017-7889",
    "CVE-2017-7895"
  );
  script_xref(name:"USN", value:"3312-2");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel (Xenial HWE) vulnerabilities (USN-3312-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-3312-2 advisory.

    USN-3312-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04 LTS. This update provides the
    corresponding updates for the Linux Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
    14.04 LTS.

    It was discovered that the netfilter netlink implementation in the Linux kernel did not properly validate
    batch messages. A local attacker with the CAP_NET_ADMIN capability could use this to expose sensitive
    information or cause a denial of service. (CVE-2016-7917)

    Qian Zhang discovered a heap-based buffer overflow in the tipc_msg_build() function in the Linux kernel. A
    local attacker could use to cause a denial of service (system crash) or possibly execute arbitrary code
    with administrative privileges. (CVE-2016-8632)

    It was discovered that the keyring implementation in the Linux kernel in some situations did not prevent
    special internal keyrings from being joined by userspace keyrings. A privileged local attacker could use
    this to bypass module verification. (CVE-2016-9604)

    It was discovered that a buffer overflow existed in the trace subsystem in the Linux kernel. A privileged
    local attacker could use this to execute arbitrary code. (CVE-2017-0605)

    Dmitry Vyukov discovered that KVM implementation in the Linux kernel improperly emulated the VMXON
    instruction. A local attacker in a guest OS could use this to cause a denial of service (memory
    consumption) in the host OS. (CVE-2017-2596)

    Daniel Jiang discovered that a race condition existed in the ipv4 ping socket implementation in the Linux
    kernel. A local privileged attacker could use this to cause a denial of service (system crash).
    (CVE-2017-2671)

    Di Shen discovered that a race condition existed in the perf subsystem of the Linux kernel. A local
    attacker could use this to cause a denial of service or possibly gain administrative privileges.
    (CVE-2017-6001)

    Eric Biggers discovered a memory leak in the keyring implementation in the Linux kernel. A local attacker
    could use this to cause a denial of service (memory consumption). (CVE-2017-7472)

    Sabrina Dubroca discovered that the asynchronous cryptographic hash (ahash) implementation in the Linux
    kernel did not properly handle a full request queue. A local attacker could use this to cause a denial of
    service (infinite recursion). (CVE-2017-7618)

    Tuomas Haanp and Ari Kauppi discovered that the NFSv2 and NFSv3 server implementations in the Linux
    kernel did not properly handle certain long RPC replies. A remote attacker could use this to cause a
    denial of service (system crash). (CVE-2017-7645)

    Tommi Rantala and Brad Spengler discovered that the memory manager in the Linux kernel did not properly
    enforce the CONFIG_STRICT_DEVMEM protection mechanism. A local attacker with access to /dev/mem could use
    this to expose sensitive information or possibly execute arbitrary code. (CVE-2017-7889)

    Tuomas Haanp and Ari Kauppi discovered that the NFSv2 and NFSv3 server implementations in the Linux
    kernel did not properly check for the end of buffer. A remote attacker could use this to craft requests
    that cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2017-7895)

    It was discovered that a use-after-free vulnerability existed in the device driver for XCeive
    xc2028/xc3028 tuners in the Linux kernel. A local attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2016-7913)

    Vlad Tsyrklevich discovered an integer overflow vulnerability in the VFIO PCI driver for the Linux kernel.
    A local attacker with access to a vfio PCI device file could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2016-9083, CVE-2016-9084)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3312-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7895");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-79-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-79-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-79-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-79-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-79-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-79-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-79-powerpc64-smp");
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
    '4.4.0': {
      'generic': '4.4.0-79',
      'generic-lpae': '4.4.0-79',
      'lowlatency': '4.4.0-79',
      'powerpc-e500mc': '4.4.0-79',
      'powerpc-smp': '4.4.0-79',
      'powerpc64-emb': '4.4.0-79',
      'powerpc64-smp': '4.4.0-79'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-3312-2');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2016-7913', 'CVE-2016-7917', 'CVE-2016-8632', 'CVE-2016-9083', 'CVE-2016-9084', 'CVE-2016-9604', 'CVE-2017-2596', 'CVE-2017-2671', 'CVE-2017-6001', 'CVE-2017-7472', 'CVE-2017-7618', 'CVE-2017-7645', 'CVE-2017-7889', 'CVE-2017-7895');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-3312-2');
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
