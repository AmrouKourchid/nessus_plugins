##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4657-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143433);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-0427",
    "CVE-2020-4788",
    "CVE-2020-10135",
    "CVE-2020-12352",
    "CVE-2020-14351",
    "CVE-2020-14390",
    "CVE-2020-25211",
    "CVE-2020-25284",
    "CVE-2020-25643",
    "CVE-2020-25645",
    "CVE-2020-25705",
    "CVE-2020-28915"
  );
  script_xref(name:"USN", value:"4657-1");
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"Ubuntu 16.04 LTS : Linux kernel vulnerabilities (USN-4657-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-4657-1 advisory.

    Elena Petrova discovered that the pin controller device tree implementation in the Linux kernel did not
    properly handle string references. A local attacker could use this to expose sensitive information (kernel
    memory). (CVE-2020-0427)

    Daniele Antonioli, Nils Ole Tippenhauer, and Kasper Rasmussen discovered that legacy pairing and secure-
    connections pairing authentication in the Bluetooth protocol could allow an unauthenticated user to
    complete authentication without pairing credentials via adjacent access. A physically proximate attacker
    could use this to impersonate a previously paired Bluetooth device. (CVE-2020-10135)

    Andy Nguyen discovered that the Bluetooth A2MP implementation in the Linux kernel did not properly
    initialize memory in some situations. A physically proximate remote attacker could use this to expose
    sensitive information (kernel memory). (CVE-2020-12352)

    It was discovered that a race condition existed in the perf subsystem of the Linux kernel, leading to a
    use-after-free vulnerability. An attacker with access to the perf subsystem could use this to cause a
    denial of service (system crash) or possibly execute arbitrary code. (CVE-2020-14351)

    It was discovered that the frame buffer implementation in the Linux kernel did not properly handle some
    edge cases in software scrollback. A local attacker could use this to cause a denial of service (system
    crash) or possibly execute arbitrary code. (CVE-2020-14390)

    It was discovered that the netfilter connection tracker for netlink in the Linux kernel did not properly
    perform bounds checking in some situations. A local attacker could use this to cause a denial of service
    (system crash). (CVE-2020-25211)

    It was discovered that the Rados block device (rbd) driver in the Linux kernel did not properly perform
    privilege checks for access to rbd devices in some situations. A local attacker could use this to map or
    unmap rbd block devices. (CVE-2020-25284)

    It was discovered that the HDLC PPP implementation in the Linux kernel did not properly validate input in
    some situations. A local attacker could use this to cause a denial of service (system crash) or possibly
    execute arbitrary code. (CVE-2020-25643)

    It was discovered that the GENEVE tunnel implementation in the Linux kernel when combined with IPSec did
    not properly select IP routes in some situations. An attacker could use this to expose sensitive
    information (unencrypted network traffic). (CVE-2020-25645)

    Keyu Man discovered that the ICMP global rate limiter in the Linux kernel could be used to assist in
    scanning open UDP ports. A remote attacker could use to facilitate attacks on UDP based services that
    depend on source port randomization. (CVE-2020-25705)

    It was discovered that the framebuffer implementation in the Linux kernel did not properly perform range
    checks in certain situations. A local attacker could use this to expose sensitive information (kernel
    memory). (CVE-2020-28915)

    It was discovered that Power 9 processors could be coerced to expose information from the L1 cache in
    certain situations. A local attacker could use this to expose sensitive information. (CVE-2020-4788)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4657-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25643");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14351");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1084-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1118-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1142-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-1146-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-197-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-197-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-197-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-197-powerpc-e500mc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-197-powerpc-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-197-powerpc64-emb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4.0-197-powerpc64-smp");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2024 Canonical, Inc. / NASL script (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'generic': '4.4.0-197',
      'generic-lpae': '4.4.0-197',
      'lowlatency': '4.4.0-197',
      'powerpc-e500mc': '4.4.0-197',
      'powerpc-smp': '4.4.0-197',
      'powerpc64-emb': '4.4.0-197',
      'powerpc64-smp': '4.4.0-197',
      'kvm': '4.4.0-1084',
      'aws': '4.4.0-1118',
      'raspi2': '4.4.0-1142',
      'snapdragon': '4.4.0-1146'
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
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-4657-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2020-0427', 'CVE-2020-4788', 'CVE-2020-10135', 'CVE-2020-12352', 'CVE-2020-14351', 'CVE-2020-14390', 'CVE-2020-25211', 'CVE-2020-25284', 'CVE-2020-25643', 'CVE-2020-25645', 'CVE-2020-25705', 'CVE-2020-28915');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-4657-1');
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
