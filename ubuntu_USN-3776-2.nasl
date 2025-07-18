#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3776-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(117871);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2017-18216",
    "CVE-2018-10902",
    "CVE-2018-14633",
    "CVE-2018-15572",
    "CVE-2018-15594",
    "CVE-2018-16276",
    "CVE-2018-17182",
    "CVE-2018-6554",
    "CVE-2018-6555"
  );
  script_xref(name:"USN", value:"3776-2");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel (Xenial HWE) vulnerabilities (USN-3776-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-3776-2 advisory.

    USN-3776-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04 LTS. This update provides the
    corresponding updates for the Linux Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
    14.04 LTS.

    Jann Horn discovered that the vmacache subsystem did not properly handle sequence number overflows,
    leading to a use-after-free vulnerability. A local attacker could use this to cause a denial of service
    (system crash) or execute arbitrary code. (CVE-2018-17182)

    It was discovered that the paravirtualization implementation in the Linux kernel did not properly handle
    some indirect calls, reducing the effectiveness of Spectre v2 mitigations for paravirtual guests. A local
    attacker could use this to expose sensitive information. (CVE-2018-15594)

    It was discovered that microprocessors utilizing speculative execution and prediction of return addresses
    via Return Stack Buffer (RSB) may allow unauthorized memory reads via sidechannel attacks. An attacker
    could use this to expose sensitive information. (CVE-2018-15572)

    It was discovered that a NULL pointer dereference could be triggered in the OCFS2 file system
    implementation in the Linux kernel. A local attacker could use this to cause a denial of service (system
    crash). (CVE-2017-18216)

    It was discovered that a race condition existed in the raw MIDI driver for the Linux kernel, leading to a
    double free vulnerability. A local attacker could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2018-10902)

    It was discovered that a stack-based buffer overflow existed in the iSCSI target implementation of the
    Linux kernel. A remote attacker could use this to cause a denial of service (system crash).
    (CVE-2018-14633)

    It was discovered that the YUREX USB device driver for the Linux kernel did not properly restrict user
    space reads or writes. A physically proximate attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2018-16276)

    It was discovered that a memory leak existed in the IRDA subsystem of the Linux kernel. A local attacker
    could use this to cause a denial of service (kernel memory exhaustion). (CVE-2018-6554)

    It was discovered that a use-after-free vulnerability existed in the IRDA implementation in the Linux
    kernel. A local attacker could use this to cause a denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2018-6555)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3776-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14633");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-6555");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1031-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-137-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-137-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-137-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-137-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-137-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-137-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-137-powerpc64-smp");
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
    '4.4.0': {
      'generic': '4.4.0-137',
      'generic-lpae': '4.4.0-137',
      'lowlatency': '4.4.0-137',
      'powerpc-e500mc': '4.4.0-137',
      'powerpc-smp': '4.4.0-137',
      'powerpc64-emb': '4.4.0-137',
      'powerpc64-smp': '4.4.0-137',
      'aws': '4.4.0-1031'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-3776-2');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2017-18216', 'CVE-2018-6554', 'CVE-2018-6555', 'CVE-2018-10902', 'CVE-2018-14633', 'CVE-2018-15572', 'CVE-2018-15594', 'CVE-2018-16276', 'CVE-2018-17182');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-3776-2');
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
