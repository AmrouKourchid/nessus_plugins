#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2974-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(91122);
  script_version("2.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2016-2391",
    "CVE-2016-2392",
    "CVE-2016-2538",
    "CVE-2016-2841",
    "CVE-2016-2857",
    "CVE-2016-2858",
    "CVE-2016-3710",
    "CVE-2016-3712",
    "CVE-2016-4001",
    "CVE-2016-4002",
    "CVE-2016-4020",
    "CVE-2016-4037"
  );
  script_xref(name:"USN", value:"2974-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : QEMU vulnerabilities (USN-2974-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-2974-1 advisory.

    Zuozhi Fzz discovered that QEMU incorrectly handled USB OHCI emulation support. A privileged attacker
    inside the guest could use this issue to cause QEMU to crash, resulting in a denial of service.
    (CVE-2016-2391)

    Qinghao Tang discovered that QEMU incorrectly handled USB Net emulation support. A privileged attacker
    inside the guest could use this issue to cause QEMU to crash, resulting in a denial of service.
    (CVE-2016-2392)

    Qinghao Tang discovered that QEMU incorrectly handled USB Net emulation support. A privileged attacker
    inside the guest could use this issue to cause QEMU to crash, resulting in a denial of service, or
    possibly leak host memory bytes. (CVE-2016-2538)

    Hongke Yang discovered that QEMU incorrectly handled NE2000 emulation support. A privileged attacker
    inside the guest could use this issue to cause QEMU to crash, resulting in a denial of service.
    (CVE-2016-2841)

    Ling Liu discovered that QEMU incorrectly handled IP checksum routines. An attacker inside the guest could
    use this issue to cause QEMU to crash, resulting in a denial of service, or possibly leak host memory
    bytes. (CVE-2016-2857)

    It was discovered that QEMU incorrectly handled the PRNG back-end support. An attacker inside the guest
    could use this issue to cause QEMU to crash, resulting in a denial of service. This issue only applied to
    Ubuntu 14.04 LTS, Ubuntu 15.10 and Ubuntu 16.04 LTS. (CVE-2016-2858)

    Wei Xiao and Qinghao Tang discovered that QEMU incorrectly handled access in the VGA module. A privileged
    attacker inside the guest could use this issue to cause QEMU to crash, resulting in a denial of service,
    or possibly execute arbitrary code on the host. In the default installation, when QEMU is used with
    libvirt, attackers would be isolated by the libvirt AppArmor profile. (CVE-2016-3710)

    Zuozhi Fzz discovered that QEMU incorrectly handled access in the VGA module. A privileged attacker inside
    the guest could use this issue to cause QEMU to crash, resulting in a denial of service, or possibly
    execute arbitrary code on the host. In the default installation, when QEMU is used with libvirt, attackers
    would be isolated by the libvirt AppArmor profile. (CVE-2016-3712)

    Oleksandr Bazhaniuk discovered that QEMU incorrectly handled Luminary Micro Stellaris ethernet controller
    emulation. A remote attacker could use this issue to cause QEMU to crash, resulting in a denial of
    service. (CVE-2016-4001)

    Oleksandr Bazhaniuk discovered that QEMU incorrectly handled MIPSnet controller emulation. A remote
    attacker could use this issue to cause QEMU to crash, resulting in a denial of service. (CVE-2016-4002)

    Donghai Zdh discovered that QEMU incorrectly handled the Task Priority Register(TPR). A privileged
    attacker inside the guest could use this issue to possibly leak host memory bytes. This issue only applied
    to Ubuntu 14.04 LTS, Ubuntu 15.10 and Ubuntu 16.04 LTS. (CVE-2016-4020)

    Du Shaobo discovered that QEMU incorrectly handled USB EHCI emulation support. A privileged attacker
    inside the guest could use this issue to cause QEMU to consume resources, resulting in a denial of
    service. (CVE-2016-4037)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2974-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3710");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-4002");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user-binfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-block-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-keymaps");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2016-2024 Canonical, Inc. / NASL script (C) 2016-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'qemu', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-common', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-keymaps', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-kvm', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-system', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-system-aarch64', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-system-arm', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-system-common', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-system-mips', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-system-misc', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-system-x86', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-user', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-user-static', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '14.04', 'pkgname': 'qemu-utils', 'pkgver': '2.0.0+dfsg-2ubuntu1.24'},
    {'osver': '16.04', 'pkgname': 'qemu', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-kvm', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-system', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-system-aarch64', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-user', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'},
    {'osver': '16.04', 'pkgname': 'qemu-utils', 'pkgver': '1:2.5+dfsg-5ubuntu10.1'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  var extra = '';
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-block-extra / qemu-common / qemu-guest-agent / etc');
}
