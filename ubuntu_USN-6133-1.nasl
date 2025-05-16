#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6133-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176617);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2022-3707",
    "CVE-2022-27672",
    "CVE-2023-0459",
    "CVE-2023-1075",
    "CVE-2023-1078",
    "CVE-2023-1118",
    "CVE-2023-1513",
    "CVE-2023-1829",
    "CVE-2023-1872",
    "CVE-2023-2162",
    "CVE-2023-20938",
    "CVE-2023-32269"
  );
  script_xref(name:"USN", value:"6133-1");

  script_name(english:"Ubuntu 22.04 LTS : Linux kernel (Intel IoTG) vulnerabilities (USN-6133-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6133-1 advisory.

    It was discovered that the Traffic-Control Index (TCINDEX) implementation in the Linux kernel did not
    properly perform filter deactivation in some situations. A local attacker could possibly use this to gain
    elevated privileges. Please note that with the fix for this CVE, kernel support for the TCINDEX classifier
    has been removed. (CVE-2023-1829)

    It was discovered that some AMD x86-64 processors with SMT enabled could speculatively execute
    instructions using a return address from a sibling thread. A local attacker could possibly use this to
    expose sensitive information. (CVE-2022-27672)

    Zheng Wang discovered that the Intel i915 graphics driver in the Linux kernel did not properly handle
    certain error conditions, leading to a double-free. A local attacker could possibly use this to cause a
    denial of service (system crash). (CVE-2022-3707)

    Jordy Zomer and Alexandra Sandulescu discovered that the Linux kernel did not properly implement
    speculative execution barriers in usercopy functions in certain situations. A local attacker could use
    this to expose sensitive information (kernel memory). (CVE-2023-0459)

    It was discovered that the TLS subsystem in the Linux kernel contained a type confusion vulnerability in
    some situations. A local attacker could use this to cause a denial of service (system crash) or possibly
    expose sensitive information. (CVE-2023-1075)

    It was discovered that the Reliable Datagram Sockets (RDS) protocol implementation in the Linux kernel
    contained a type confusion vulnerability in some situations. An attacker could use this to cause a denial
    of service (system crash). (CVE-2023-1078)

    Xingyuan Mo discovered that the x86 KVM implementation in the Linux kernel did not properly initialize
    some data structures. A local attacker could use this to expose sensitive information (kernel memory).
    (CVE-2023-1513)

    It was discovered that a race condition existed in the io_uring subsystem in the Linux kernel, leading to
    a use-after-free vulnerability. A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2023-1872)

    It was discovered that the Android Binder IPC subsystem in the Linux kernel did not properly validate
    inputs in some situations, leading to a use- after-free vulnerability. A local attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-20938)

    It was discovered that a use-after-free vulnerability existed in the iSCSI TCP implementation in the Linux
    kernel. A local attacker could possibly use this to cause a denial of service (system crash).
    (CVE-2023-2162)

    It was discovered that the NET/ROM protocol implementation in the Linux kernel contained a race condition
    in some situations, leading to a use- after-free vulnerability. A local attacker could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-32269)

    Duoming Zhou discovered that a race condition existed in the infrared receiver/transceiver driver in the
    Linux kernel, leading to a use-after- free vulnerability. A privileged attacker could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2023-1118)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6133-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20938");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1030-intel-iotg");
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
if (! ('22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '22.04': {
    '5.15.0': {
      'intel-iotg': '5.15.0-1030'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6133-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-3707', 'CVE-2022-27672', 'CVE-2023-0459', 'CVE-2023-1075', 'CVE-2023-1078', 'CVE-2023-1118', 'CVE-2023-1513', 'CVE-2023-1829', 'CVE-2023-1872', 'CVE-2023-2162', 'CVE-2023-20938', 'CVE-2023-32269');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6133-1');
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
