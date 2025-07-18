#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2890-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88525);
  script_version("2.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2013-7446",
    "CVE-2015-7513",
    "CVE-2015-7550",
    "CVE-2015-7990",
    "CVE-2015-8374",
    "CVE-2015-8543",
    "CVE-2015-8569",
    "CVE-2015-8575",
    "CVE-2015-8787"
  );
  script_xref(name:"USN", value:"2890-2");

  script_name(english:"Ubuntu 14.04 LTS : Linux kernel (Wily HWE) vulnerabilities (USN-2890-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-2890-2 advisory.

    It was discovered that a use-after-free vulnerability existed in the AF_UNIX implementation in the Linux
    kernel. A local attacker could use crafted epoll_ctl calls to cause a denial of service (system crash) or
    expose sensitive information. (CVE-2013-7446)

    It was discovered that the KVM implementation in the Linux kernel did not properly restore the values of
    the Programmable Interrupt Timer (PIT). A user-assisted attacker in a KVM guest could cause a denial of
    service in the host (system crash). (CVE-2015-7513)

    It was discovered that the Linux kernel keyring subsystem contained a race between read and revoke
    operations. A local attacker could use this to cause a denial of service (system crash). (CVE-2015-7550)

    Sasha Levin discovered that the Reliable Datagram Sockets (RDS) implementation in the Linux kernel had a
    race condition when checking whether a socket was bound or not. A local attacker could use this to cause a
    denial of service (system crash). (CVE-2015-7990)

    It was discovered that the Btrfs implementation in the Linux kernel incorrectly handled compressed inline
    extants on truncation. A local attacker could use this to expose sensitive information. (CVE-2015-8374)

     discovered that the Linux kernel networking implementation did not validate protocol identifiers
    for certain protocol families, A local attacker could use this to cause a denial of service (system crash)
    or possibly gain administrative privileges. (CVE-2015-8543)

    Dmitry Vyukov discovered that the pptp implementation in the Linux kernel did not verify an address length
    when setting up a socket. A local attacker could use this to craft an application that exposed sensitive
    information from kernel memory. (CVE-2015-8569)

    David Miller discovered that the Bluetooth implementation in the Linux kernel did not properly validate
    the socket address length for Synchronous Connection-Oriented (SCO) sockets. A local attacker could use
    this to expose sensitive information. (CVE-2015-8575)

    It was discovered that the netfilter Network Address Translation (NAT) implementation did not ensure that
    data structures were initialized when handling IPv4 addresses. An attacker could use this to cause a
    denial of service (system crash). (CVE-2015-8787)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2890-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8787");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2.0-27-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2.0-27-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2.0-27-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2.0-27-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2.0-27-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2.0-27-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.2.0-27-powerpc64-smp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2016-2020 Canonical, Inc. / NASL script (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    '4.2.0': {
      'generic': '4.2.0-27',
      'generic-lpae': '4.2.0-27',
      'lowlatency': '4.2.0-27',
      'powerpc-e500mc': '4.2.0-27',
      'powerpc-smp': '4.2.0-27',
      'powerpc64-emb': '4.2.0-27',
      'powerpc64-smp': '4.2.0-27'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-2890-2');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2013-7446', 'CVE-2015-7513', 'CVE-2015-7550', 'CVE-2015-7990', 'CVE-2015-8374', 'CVE-2015-8543', 'CVE-2015-8569', 'CVE-2015-8575', 'CVE-2015-8787');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-2890-2');
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
