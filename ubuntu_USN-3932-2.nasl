#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3932-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(123681);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2017-18249",
    "CVE-2018-13097",
    "CVE-2018-13099",
    "CVE-2018-13100",
    "CVE-2018-14610",
    "CVE-2018-14611",
    "CVE-2018-14612",
    "CVE-2018-14613",
    "CVE-2018-14614",
    "CVE-2018-14616",
    "CVE-2018-16884",
    "CVE-2018-9517",
    "CVE-2019-3459",
    "CVE-2019-3460",
    "CVE-2019-3701",
    "CVE-2019-3819",
    "CVE-2019-6974",
    "CVE-2019-7221",
    "CVE-2019-7222",
    "CVE-2019-9213"
  );
  script_xref(name:"USN", value:"3932-2");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel (Xenial HWE) vulnerabilities (USN-3932-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-3932-2 advisory.

    USN-3932-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04 LTS. This update provides the
    corresponding updates for the Linux Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
    14.04 LTS.

    It was discovered that a race condition existed in the f2fs file system implementation in the Linux
    kernel. A local attacker could use this to cause a denial of service. (CVE-2017-18249)

    Wen Xu discovered that the f2fs file system implementation in the Linux kernel did not properly validate
    metadata. An attacker could use this to construct a malicious f2fs image that, when mounted, could cause a
    denial of service (system crash). (CVE-2018-13097, CVE-2018-13099, CVE-2018-13100, CVE-2018-14614,
    CVE-2018-14616)

    Wen Xu and Po-Ning Tseng discovered that btrfs file system implementation in the Linux kernel did not
    properly validate metadata. An attacker could use this to construct a malicious btrfs image that, when
    mounted, could cause a denial of service (system crash). (CVE-2018-14610, CVE-2018-14611, CVE-2018-14612,
    CVE-2018-14613)

    Vasily Averin and Evgenii Shatokhin discovered that a use-after-free vulnerability existed in the NFS41+
    subsystem when multiple network namespaces are in use. A local attacker in a container could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2018-16884)

    It was discovered that a use-after-free vulnerability existed in the PPP over L2TP implementation in the
    Linux kernel. A privileged local attacker could use this to possibly execute arbitrary code.
    (CVE-2018-9517)

    Shlomi Oberman, Yuli Shapiro, and Ran Menscher discovered an information leak in the Bluetooth
    implementation of the Linux kernel. An attacker within Bluetooth range could use this to expose sensitive
    information (kernel memory). (CVE-2019-3459, CVE-2019-3460)

    Jann Horn discovered that the KVM implementation in the Linux kernel contained a use-after-free
    vulnerability. An attacker in a guest VM with access to /dev/kvm could use this to cause a denial of
    service (guest VM crash). (CVE-2019-6974)

    Jim Mattson and Felix Wilhelm discovered a use-after-free vulnerability in the KVM subsystem of the Linux
    kernel, when using nested virtual machines. A local attacker in a guest VM could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code in the host system. (CVE-2019-7221)

    Felix Wilhelm discovered that an information leak vulnerability existed in the KVM subsystem of the Linux
    kernel, when nested virtualization is used. A local attacker could use this to expose sensitive
    information (host system memory to a guest VM). (CVE-2019-7222)

    Jann Horn discovered that the mmap implementation in the Linux kernel did not properly check for the mmap
    minimum address in some situations. A local attacker could use this to assist exploiting a kernel NULL
    pointer dereference vulnerability. (CVE-2019-9213)

    Muyu Yu discovered that the CAN implementation in the Linux kernel in some situations did not properly
    restrict the field size when processing outgoing frames. A local attacker with CAP_NET_ADMIN privileges
    could use this to execute arbitrary code. (CVE-2019-3701)

    Vladis Dronov discovered that the debug interface for the Linux kernel's HID subsystem did not properly
    validate passed parameters in some situations. A local privileged attacker could use this to cause a
    denial of service (infinite loop). (CVE-2019-3819)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3932-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9517");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-6974");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_atomic_free_op NULL pointer dereference Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1040-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-144-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-144-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-144-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-144-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-144-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-144-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-144-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
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
if (! ('14.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '14.04': {
    '4.4.0': {
      'generic': '4.4.0-144',
      'generic-lpae': '4.4.0-144',
      'lowlatency': '4.4.0-144',
      'powerpc-e500mc': '4.4.0-144',
      'powerpc-smp': '4.4.0-144',
      'powerpc64-emb': '4.4.0-144',
      'powerpc64-smp': '4.4.0-144',
      'aws': '4.4.0-1040'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-3932-2');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2017-18249', 'CVE-2018-9517', 'CVE-2018-13097', 'CVE-2018-13099', 'CVE-2018-13100', 'CVE-2018-14610', 'CVE-2018-14611', 'CVE-2018-14612', 'CVE-2018-14613', 'CVE-2018-14614', 'CVE-2018-14616', 'CVE-2018-16884', 'CVE-2019-3459', 'CVE-2019-3460', 'CVE-2019-3701', 'CVE-2019-3819', 'CVE-2019-6974', 'CVE-2019-7221', 'CVE-2019-7222', 'CVE-2019-9213');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-3932-2');
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
