#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3752-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(112189);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2018-1000200",
    "CVE-2018-1000204",
    "CVE-2018-10323",
    "CVE-2018-10840",
    "CVE-2018-10881",
    "CVE-2018-1093",
    "CVE-2018-1108",
    "CVE-2018-1120",
    "CVE-2018-11412",
    "CVE-2018-11506",
    "CVE-2018-12232",
    "CVE-2018-12233",
    "CVE-2018-12904",
    "CVE-2018-13094",
    "CVE-2018-13405",
    "CVE-2018-13406",
    "CVE-2018-5814",
    "CVE-2018-9415"
  );
  script_xref(name:"USN", value:"3752-3");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Linux kernel (Azure, GCP, OEM) vulnerabilities (USN-3752-3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-3752-3 advisory.

    It was discovered that, when attempting to handle an out-of-memory situation, a null pointer dereference
    could be triggered in the Linux kernel in some circumstances. A local attacker could use this to cause a
    denial of service (system crash). (CVE-2018-1000200)

    Wen Xu discovered that the XFS filesystem implementation in the Linux kernel did not properly validate
    meta-data information. An attacker could use this to construct a malicious xfs image that, when mounted,
    could cause a denial of service (system crash). (CVE-2018-10323)

    Wen Xu discovered that the XFS filesystem implementation in the Linux kernel did not properly validate
    xattr information. An attacker could use this to construct a malicious xfs image that, when mounted, could
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2018-10840)

    Wen Xu discovered that the ext4 filesystem implementation in the Linux kernel did not properly keep meta-
    data information consistent in some situations. An attacker could use this to construct a malicious ext4
    image that, when mounted, could cause a denial of service (system crash). (CVE-2018-10881)

    Wen Xu discovered that the ext4 filesystem implementation in the Linux kernel did not properly handle
    corrupted meta data in some situations. An attacker could use this to specially craft an ext4 filesystem
    that caused a denial of service (system crash) when mounted. (CVE-2018-1093)

    Jann Horn discovered that the Linux kernel's implementation of random seed data reported that it was in a
    ready state before it had gathered sufficient entropy. An attacker could use this to expose sensitive
    information. (CVE-2018-1108)

    It was discovered that the procfs filesystem did not properly handle processes mapping some memory
    elements onto files. A local attacker could use this to block utilities that examine the procfs filesystem
    to report operating system state, such as ps(1). (CVE-2018-1120)

    Jann Horn discovered that the ext4 filesystem implementation in the Linux kernel did not properly keep
    xattr information consistent in some situations. An attacker could use this to construct a malicious ext4
    image that, when mounted, could cause a denial of service (system crash) or possibly execute arbitrary
    code. (CVE-2018-11412)

    Piotr Gabriel Kosinski and Daniel Shapira discovered a stack-based buffer overflow in the CDROM driver
    implementation of the Linux kernel. A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2018-11506)

    Shankara Pailoor discovered that a race condition existed in the socket handling code in the Linux kernel.
    A local attacker could use this to cause a denial of service (system crash). (CVE-2018-12232)

    Shankara Pailoor discovered that the JFS filesystem implementation in the Linux kernel contained a buffer
    overflow when handling extended attributes. A local attacker could use this to cause a denial of service
    (system crash) or possibly execute arbitrary code. (CVE-2018-12233)

    Felix Wilhelm discovered that the KVM implementation in the Linux kernel did not properly perform
    permission checks in some situations when nested virtualization is used. An attacker in a guest VM could
    possibly use this to escape into an outer VM or the host OS. (CVE-2018-12904)

    Wen Xu discovered that the XFS filesystem implementation in the Linux kernel did not properly handle an
    error condition with a corrupted xfs image. An attacker could use this to construct a malicious xfs image
    that, when mounted, could cause a denial of service (system crash). (CVE-2018-13094)

    It was discovered that the Linux kernel did not properly handle setgid file creation when performed by a
    non-member of the group. A local attacker could use this to gain elevated privileges. (CVE-2018-13405)

    Silvio Cesare discovered that the generic VESA frame buffer driver in the Linux kernel contained an
    integer overflow. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2018-13406)

    Jakub Jirasek discovered that multiple use-after-free errors existed in the USB/IP implementation in the
    Linux kernel. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2018-5814)

    It was discovered that a race condition existed in the ARM Advanced Microcontroller Bus Architecture
    (AMBA) driver in the Linux kernel that could result in a double free. A local attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2018-9415)

    It was discovered that an information leak existed in the generic SCSI driver in the Linux kernel. A local
    attacker could use this to expose sensitive information (kernel memory). (CVE-2018-1000204)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3752-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13406");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-9415");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1017-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1018-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1022-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
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
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '16.04': {
    '4.15.0': {
      'gcp': '4.15.0-1018',
      'azure': '4.15.0-1022'
    }
  },
  '18.04': {
    '4.15.0': {
      'oem': '4.15.0-1017',
      'azure': '4.15.0-1022'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-3752-3');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2018-1093', 'CVE-2018-1108', 'CVE-2018-1120', 'CVE-2018-5814', 'CVE-2018-9415', 'CVE-2018-10323', 'CVE-2018-10840', 'CVE-2018-10881', 'CVE-2018-11412', 'CVE-2018-11506', 'CVE-2018-12232', 'CVE-2018-12233', 'CVE-2018-12904', 'CVE-2018-13094', 'CVE-2018-13405', 'CVE-2018-13406', 'CVE-2018-1000200', 'CVE-2018-1000204');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-3752-3');
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
