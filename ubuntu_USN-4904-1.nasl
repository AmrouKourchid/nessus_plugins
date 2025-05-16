##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4904-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148498);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2015-1350",
    "CVE-2017-5967",
    "CVE-2017-16644",
    "CVE-2018-13095",
    "CVE-2019-16231",
    "CVE-2019-16232",
    "CVE-2019-19061",
    "CVE-2021-20261",
    "CVE-2021-26930",
    "CVE-2021-26931",
    "CVE-2021-28038"
  );
  script_xref(name:"USN", value:"4904-1");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel vulnerabilities (USN-4904-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-4904-1 advisory.

    Ben Harris discovered that the Linux kernel would strip extended privilege attributes of files when
    performing a failed unprivileged system call. A local attacker could use this to cause a denial of
    service. (CVE-2015-1350)

    Andrey Konovalov discovered that the video4linux driver for Hauppauge HD PVR USB devices in the Linux
    kernel did not properly handle some error conditions. A physically proximate attacker could use this to
    cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2017-16644)

    It was discovered that the timer stats implementation in the Linux kernel allowed the discovery of a real
    PID value while inside a PID namespace. A local attacker could use this to expose sensitive information.
    (CVE-2017-5967)

    Wen Xu discovered that the xfs file system implementation in the Linux kernel did not properly validate
    the number of extents in an inode. An attacker could use this to construct a malicious xfs image that,
    when mounted, could cause a denial of service (system crash). (CVE-2018-13095)

    It was discovered that the Fujitsu ES network device driver for the Linux kernel did not properly check
    for errors in some situations, leading to a NULL pointer dereference. A local attacker could use this to
    cause a denial of service. (CVE-2019-16231)

    It was discovered that the Marvell 8xxx Libertas WLAN device driver in the Linux kernel did not properly
    check for errors in certain situations, leading to a NULL pointer dereference. A local attacker could
    possibly use this to cause a denial of service. (CVE-2019-16232)

    It was discovered that the ADIS16400 IIO IMU Driver for the Linux kernel did not properly deallocate
    memory in certain error conditions. A local attacker could use this to cause a denial of service (memory
    exhaustion). (CVE-2019-19061)

    It was discovered that a race condition existed in the floppy device driver in the Linux kernel. An
    attacker with access to the floppy device could use this to cause a denial of service (system crash) or
    possibly execute arbitrary code. (CVE-2021-20261)

    Olivier Benjamin, Norbert Manthey, Martin Mazein, and Jan H. Schnherr discovered that the Xen
    paravirtualization backend in the Linux kernel did not properly propagate errors to frontend drivers in
    some situations. An attacker in a guest VM could possibly use this to cause a denial of service (host
    domain crash). (CVE-2021-26930)

    Jan Beulich discovered that multiple Xen backends in the Linux kernel did not properly handle certain
    error conditions under paravirtualization. An attacker in a guest VM could possibly use this to cause a
    denial of service (host domain crash). (CVE-2021-26931)

    Jan Beulich discovered that the Xen netback backend in the Linux kernel did not properly handle certain
    error conditions under paravirtualization. An attacker in a guest VM could possibly use this to cause a
    denial of service (host domain crash). (CVE-2021-28038)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4904-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16644");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-26930");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1091-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1126-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1150-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1154-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-208-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-208-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-208-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-208-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-208-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-208-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-208-powerpc64-smp");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2024 Canonical, Inc. / NASL script (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '4.4.0-208',
      'generic-lpae': '4.4.0-208',
      'lowlatency': '4.4.0-208',
      'powerpc-e500mc': '4.4.0-208',
      'powerpc-smp': '4.4.0-208',
      'powerpc64-emb': '4.4.0-208',
      'powerpc64-smp': '4.4.0-208',
      'kvm': '4.4.0-1091',
      'aws': '4.4.0-1126',
      'raspi2': '4.4.0-1150',
      'snapdragon': '4.4.0-1154'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-4904-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2015-1350', 'CVE-2017-5967', 'CVE-2017-16644', 'CVE-2018-13095', 'CVE-2019-16231', 'CVE-2019-16232', 'CVE-2019-19061', 'CVE-2021-20261', 'CVE-2021-26930', 'CVE-2021-26931', 'CVE-2021-28038');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4904-1');
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
