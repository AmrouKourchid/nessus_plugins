#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3261-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(99581);
  script_version("3.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2016-10028",
    "CVE-2016-10029",
    "CVE-2016-10155",
    "CVE-2016-7907",
    "CVE-2016-8667",
    "CVE-2016-8669",
    "CVE-2016-9381",
    "CVE-2016-9602",
    "CVE-2016-9603",
    "CVE-2016-9776",
    "CVE-2016-9845",
    "CVE-2016-9846",
    "CVE-2016-9907",
    "CVE-2016-9908",
    "CVE-2016-9911",
    "CVE-2016-9912",
    "CVE-2016-9913",
    "CVE-2016-9914",
    "CVE-2016-9915",
    "CVE-2016-9916",
    "CVE-2016-9921",
    "CVE-2016-9922",
    "CVE-2017-2615",
    "CVE-2017-2620",
    "CVE-2017-2633",
    "CVE-2017-5525",
    "CVE-2017-5526",
    "CVE-2017-5552",
    "CVE-2017-5578",
    "CVE-2017-5579",
    "CVE-2017-5667",
    "CVE-2017-5856",
    "CVE-2017-5857",
    "CVE-2017-5898",
    "CVE-2017-5973",
    "CVE-2017-5987",
    "CVE-2017-6505"
  );
  script_xref(name:"USN", value:"3261-1");
  script_xref(name:"IAVB", value:"2017-B-0024-S");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : QEMU vulnerabilities (USN-3261-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3261-1 advisory.

    Zhenhao Hong discovered that QEMU incorrectly handled the Virtio GPU device. An attacker inside the guest
    could use this issue to cause QEMU to crash, resulting in a denial of service. This issue only affected
    Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-10028, CVE-2016-10029)

    Li Qiang discovered that QEMU incorrectly handled the 6300esb watchdog. A privileged attacker inside the
    guest could use this issue to cause QEMU to crash, resulting in a denial of service. (CVE-2016-10155)

    Li Qiang discovered that QEMU incorrectly handled the i.MX Fast Ethernet Controller. A privileged attacker
    inside the guest could use this issue to cause QEMU to crash, resulting in a denial of service. This issue
    only affected Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-7907)

    It was discovered that QEMU incorrectly handled the JAZZ RC4030 device. A privileged attacker inside the
    guest could use this issue to cause QEMU to crash, resulting in a denial of service. (CVE-2016-8667)

    It was discovered that QEMU incorrectly handled the 16550A UART device. A privileged attacker inside the
    guest could use this issue to cause QEMU to crash, resulting in a denial of service. (CVE-2016-8669)

    It was discovered that QEMU incorrectly handled the shared rings when used with Xen. A privileged attacker
    inside the guest could use this issue to cause QEMU to crash, resulting in a denial of service, or
    possibly execute arbitrary code on the host. (CVE-2016-9381)

    Jann Horn discovered that QEMU incorrectly handled VirtFS directory sharing. A privileged attacker inside
    the guest could use this issue to access files on the host file system outside of the shared directory and
    possibly escalate their privileges. In the default installation, when QEMU is used with libvirt, attackers
    would be isolated by the libvirt AppArmor profile. (CVE-2016-9602)

    Gerd Hoffmann discovered that QEMU incorrectly handled the Cirrus VGA device when being used with a VNC
    connection. A privileged attacker inside the guest could use this issue to cause QEMU to crash, resulting
    in a denial of service, or possibly execute arbitrary code on the host. In the default installation, when
    QEMU is used with libvirt, attackers would be isolated by the libvirt AppArmor profile. (CVE-2016-9603)

    It was discovered that QEMU incorrectly handled the ColdFire Fast Ethernet Controller. A privileged
    attacker inside the guest could use this issue to cause QEMU to crash, resulting in a denial of service.
    (CVE-2016-9776)

    Li Qiang discovered that QEMU incorrectly handled the Virtio GPU device. An attacker inside the guest
    could use this issue to cause QEMU to leak contents of host memory. This issue only affected Ubuntu 16.04
    LTS and Ubuntu 16.10. (CVE-2016-9845, CVE-2016-9908)

    Li Qiang discovered that QEMU incorrectly handled the Virtio GPU device. An attacker inside the guest
    could use this issue to cause QEMU to crash, resulting in a denial of service. This issue only affected
    Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-9846, CVE-2016-9912, CVE-2017-5552, CVE-2017-5578,
    CVE-2017-5857)

    Li Qiang discovered that QEMU incorrectly handled the USB redirector. An attacker inside the guest could
    use this issue to cause QEMU to crash, resulting in a denial of service. This issue only affected Ubuntu
    16.04 LTS and Ubuntu 16.10. (CVE-2016-9907)

    Li Qiang discovered that QEMU incorrectly handled USB EHCI emulation. An attacker inside the guest could
    use this issue to cause QEMU to crash, resulting in a denial of service. (CVE-2016-9911)

    Li Qiang discovered that QEMU incorrectly handled VirtFS directory sharing. A privileged attacker inside
    the guest could use this issue to cause QEMU to crash, resulting in a denial of service. (CVE-2016-9913,
    CVE-2016-9914, CVE-2016-9915, CVE-2016-9916)

    Qinghao Tang, Li Qiang, and Jiangxin discovered that QEMU incorrectly handled the Cirrus VGA device. A
    privileged attacker inside the guest could use this issue to cause QEMU to crash, resulting in a denial of
    service. (CVE-2016-9921, CVE-2016-9922)

    Wjjzhang and Li Qiang discovered that QEMU incorrectly handled the Cirrus VGA device. A privileged
    attacker inside the guest could use this issue to cause QEMU to crash, resulting in a denial of service,
    or possibly execute arbitrary code on the host. In the default installation, when QEMU is used with
    libvirt, attackers would be isolated by the libvirt AppArmor profile. (CVE-2017-2615)

    It was discovered that QEMU incorrectly handled the Cirrus VGA device. A privileged attacker inside the
    guest could use this issue to cause QEMU to crash, resulting in a denial of service, or possibly execute
    arbitrary code on the host. In the default installation, when QEMU is used with libvirt, attackers would
    be isolated by the libvirt AppArmor profile. (CVE-2017-2620)

    It was discovered that QEMU incorrectly handled VNC connections. An attacker inside the guest could use
    this issue to cause QEMU to crash, resulting in a denial of service. (CVE-2017-2633)

    Li Qiang discovered that QEMU incorrectly handled the ac97 audio device. A privileged attacker inside the
    guest could use this issue to cause QEMU to crash, resulting in a denial of service. (CVE-2017-5525)

    Li Qiang discovered that QEMU incorrectly handled the es1370 audio device. A privileged attacker inside
    the guest could use this issue to cause QEMU to crash, resulting in a denial of service. (CVE-2017-5526)

    Li Qiang discovered that QEMU incorrectly handled the 16550A UART device. A privileged attacker inside the
    guest could use this issue to cause QEMU to crash, resulting in a denial of service. (CVE-2017-5579)

    Jiang Xin discovered that QEMU incorrectly handled SDHCI device emulation. A privileged attacker inside
    the guest could use this issue to cause QEMU to crash, resulting in a denial of service, or possibly
    execute arbitrary code on the host. In the default installation, when QEMU is used with libvirt, attackers
    would be isolated by the libvirt AppArmor profile. (CVE-2017-5667)

    Li Qiang discovered that QEMU incorrectly handled the MegaRAID SAS device. A privileged attacker inside
    the guest could use this issue to cause QEMU to crash, resulting in a denial of service. (CVE-2017-5856)

    Li Qiang discovered that QEMU incorrectly handled the CCID Card device. A privileged attacker inside the
    guest could use this issue to cause QEMU to crash, resulting in a denial of service. (CVE-2017-5898)

    Li Qiang discovered that QEMU incorrectly handled USB xHCI controller emulation. A privileged attacker
    inside the guest could use this issue to cause QEMU to crash, resulting in a denial of service.
    (CVE-2017-5973)

    Jiang Xin and Wjjzhang discovered that QEMU incorrectly handled SDHCI device emulation. A privileged
    attacker inside the guest could use this issue to cause QEMU to crash, resulting in a denial of service.
    (CVE-2017-5987)

    Li Qiang discovered that QEMU incorrectly handled USB OHCI controller emulation. A privileged attacker
    inside the guest could use this issue to cause QEMU to hang, resulting in a denial of service.
    (CVE-2017-6505)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3261-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2620");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:qemu-kvm");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2017-2024 Canonical, Inc. / NASL script (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'qemu', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-common', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-keymaps', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-kvm', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-system', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-system-aarch64', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-system-arm', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-system-common', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-system-mips', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-system-misc', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-system-x86', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-user', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-user-static', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '14.04', 'pkgname': 'qemu-utils', 'pkgver': '2.0.0+dfsg-2ubuntu1.33'},
    {'osver': '16.04', 'pkgname': 'qemu', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-block-extra', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-guest-agent', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-kvm', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-system', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-system-aarch64', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-system-arm', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-system-common', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-system-mips', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-system-misc', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-system-ppc', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-system-s390x', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-system-sparc', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-system-x86', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-user', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-user-binfmt', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-user-static', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'},
    {'osver': '16.04', 'pkgname': 'qemu-utils', 'pkgver': '1:2.5+dfsg-5ubuntu10.11'}
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
