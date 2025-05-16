#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6567-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187683);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2020-14394",
    "CVE-2020-24165",
    "CVE-2021-3611",
    "CVE-2021-3638",
    "CVE-2023-1544",
    "CVE-2023-2861",
    "CVE-2023-3180",
    "CVE-2023-3255",
    "CVE-2023-3301",
    "CVE-2023-3354",
    "CVE-2023-4135",
    "CVE-2023-5088",
    "CVE-2023-40360",
    "CVE-2023-42467"
  );
  script_xref(name:"IAVB", value:"2023-B-0058-S");
  script_xref(name:"USN", value:"6567-1");
  script_xref(name:"IAVB", value:"2023-B-0073-S");
  script_xref(name:"IAVB", value:"2024-B-0022-S");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 : QEMU vulnerabilities (USN-6567-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.04 / 23.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6567-1 advisory.

    Gaoning Pan and Xingwei Li discovered that QEMU incorrectly handled the USB xHCI controller device. A
    privileged guest attacker could possibly use this issue to cause QEMU to crash, leading to a denial of
    service. This issue only affected Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2020-14394)

    It was discovered that QEMU incorrectly handled the TCG Accelerator. A local attacker could use this issue
    to cause QEMU to crash, leading to a denial of service, or possibly execute arbitrary code and esclate
    privileges. This issue only affected Ubuntu 20.04 LTS. (CVE-2020-24165)

    It was discovered that QEMU incorrectly handled the Intel HD audio device. A malicious guest attacker
    could use this issue to cause QEMU to crash, leading to a denial of service. This issue only affected
    Ubuntu 22.04 LTS. (CVE-2021-3611)

    It was discovered that QEMU incorrectly handled the ATI VGA device. A malicious guest attacker could use
    this issue to cause QEMU to crash, leading to a denial of service. This issue only affected Ubuntu 20.04
    LTS. (CVE-2021-3638)

    It was discovered that QEMU incorrectly handled the VMWare paravirtual RDMA device. A malicious guest
    attacker could use this issue to cause QEMU to crash, leading to a denial of service. (CVE-2023-1544)

    It was discovered that QEMU incorrectly handled the 9p passthrough filesystem. A malicious guest attacker
    could possibly use this issue to open special files and escape the exported 9p tree. This issue only
    affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, and Ubuntu 23.04. (CVE-2023-2861)

    It was discovered that QEMU incorrectly handled the virtual crypto device. A malicious guest attacker
    could use this issue to cause QEMU to crash, leading to a denial of service, or possibly execute arbitrary
    code. This issue only affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS, and Ubuntu 23.04. (CVE-2023-3180)

    It was discovered that QEMU incorrectly handled the built-in VNC server. A remote authenticated attacker
    could possibly use this issue to cause QEMU to stop responding, resulting in a denial of service. This
    issue only affected Ubuntu 22.04 LTS and Ubuntu 23.04. (CVE-2023-3255)

    It was discovered that QEMU incorrectly handled net device hot-unplugging. A malicious guest attacker
    could use this issue to cause QEMU to crash, leading to a denial of service. This issue only affected
    Ubuntu 22.04 LTS and Ubuntu 23.04. (CVE-2023-3301)

    It was discovered that QEMU incorrectly handled the built-in VNC server. A remote attacker could possibly
    use this issue to cause QEMU to crash, resulting in a denial of service. This issue only affected Ubuntu
    20.04 LTS, Ubuntu 22.04 LTS, and Ubuntu 23.04. (CVE-2023-3354)

    It was discovered that QEMU incorrectly handled NVME devices. A malicious guest attacker could use this
    issue to cause QEMU to crash, leading to a denial of service. This issue only affected Ubuntu 23.10.
    (CVE-2023-40360)

    It was discovered that QEMU incorrectly handled NVME devices. A malicious guest attacker could use this
    issue to cause QEMU to crash, leading to a denial of service, or possibly obtain sensitive information.
    This issue only affected Ubuntu 23.10. (CVE-2023-4135)

    It was discovered that QEMU incorrectly handled SCSI devices. A malicious guest attacker could use this
    issue to cause QEMU to crash, leading to a denial of service. This issue only affected Ubuntu 23.04 and
    Ubuntu 23.10. (CVE-2023-42467)

    It was discovered that QEMU incorrectly handled certain disk offsets. A malicious guest attacker could
    possibly use this issue to gain control of the host in certain nested virtualization scenarios.
    (CVE-2023-5088)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6567-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3638");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-24165");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-block-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86-microvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-x86-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-system-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user-binfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'qemu', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-kvm', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-system', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-system-data', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-system-gui', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86-microvm', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-system-x86-xen', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-user', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '20.04', 'pkgname': 'qemu-utils', 'pkgver': '1:4.2-3ubuntu6.28'},
    {'osver': '22.04', 'pkgname': 'qemu', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-system', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-system-data', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-system-gui', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-system-x86-microvm', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-system-x86-xen', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-user', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '22.04', 'pkgname': 'qemu-utils', 'pkgver': '1:6.2+dfsg-2ubuntu6.16'},
    {'osver': '23.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-system', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-system-data', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-system-gui', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-system-x86-xen', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-system-xen', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-user', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.04', 'pkgname': 'qemu-utils', 'pkgver': '1:7.2+dfsg-5ubuntu2.4'},
    {'osver': '23.10', 'pkgname': 'qemu-block-extra', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-system', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-system-arm', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-system-common', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-system-data', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-system-gui', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-system-mips', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-system-misc', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-system-x86', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-system-x86-xen', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-system-xen', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-user', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-user-static', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'},
    {'osver': '23.10', 'pkgname': 'qemu-utils', 'pkgver': '1:8.0.4+dfsg-1ubuntu3.23.10.2'}
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
    severity   : SECURITY_NOTE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-block-extra / qemu-guest-agent / qemu-kvm / qemu-system / etc');
}
