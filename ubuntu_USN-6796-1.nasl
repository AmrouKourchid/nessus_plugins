#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6796-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198063);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2023-22745", "CVE-2024-29040");
  script_xref(name:"USN", value:"6796-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 23.10 / 24.04 LTS : TPM2 Software Stack vulnerabilities (USN-6796-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 23.10 / 24.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-6796-1 advisory.

    Fergus Dall discovered that TPM2 Software Stack did not properly handle layer arrays. An attacker could
    possibly use this issue to cause

    TPM2 Software Stack to crash, resulting in a denial of service, or

    possibly execute arbitrary code. (CVE-2023-22745)

    Jurgen Repp and Andreas Fuchs discovered that TPM2 Software Stack did not

    validate the quote data after deserialization. An attacker could generate an arbitrary quote and cause
    TPM2 Software Stack to have unknown behavior.

    (CVE-2024-29040)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6796-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22745");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-esys-3.0.2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-esys-3.0.2-0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-esys0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-fapi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-fapi1t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-mu-4.0.1-0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-mu0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-policy0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-policy0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-rc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-rc0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-sys1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-sys1t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tcti-cmd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tcti-cmd0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tcti-device0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tcti-device0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tcti-libtpms0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tcti-libtpms0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tcti-mssim0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tcti-mssim0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tcti-pcap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tcti-pcap0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tcti-spi-helper0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tcti-spi-helper0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tcti-swtpm0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tcti-swtpm0t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tctildr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtss2-tctildr0t64");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release || '24.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 23.10 / 24.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libtss2-dev', 'pkgver': '2.3.2-1ubuntu0.20.04.2'},
    {'osver': '20.04', 'pkgname': 'libtss2-esys0', 'pkgver': '2.3.2-1ubuntu0.20.04.2'},
    {'osver': '22.04', 'pkgname': 'libtss2-dev', 'pkgver': '3.2.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libtss2-esys-3.0.2-0', 'pkgver': '3.2.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libtss2-fapi1', 'pkgver': '3.2.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libtss2-mu0', 'pkgver': '3.2.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libtss2-rc0', 'pkgver': '3.2.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libtss2-sys1', 'pkgver': '3.2.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libtss2-tcti-cmd0', 'pkgver': '3.2.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libtss2-tcti-device0', 'pkgver': '3.2.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libtss2-tcti-mssim0', 'pkgver': '3.2.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libtss2-tcti-swtpm0', 'pkgver': '3.2.0-1ubuntu1.1'},
    {'osver': '22.04', 'pkgname': 'libtss2-tctildr0', 'pkgver': '3.2.0-1ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-dev', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-esys-3.0.2-0', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-fapi1', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-mu0', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-policy0', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-rc0', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-sys1', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-tcti-cmd0', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-tcti-device0', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-tcti-libtpms0', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-tcti-mssim0', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-tcti-pcap0', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-tcti-spi-helper0', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-tcti-swtpm0', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '23.10', 'pkgname': 'libtss2-tctildr0', 'pkgver': '4.0.1-3ubuntu1.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-dev', 'pkgver': '4.0.1-7.1ubuntu5.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-esys-3.0.2-0t64', 'pkgver': '4.0.1-7.1ubuntu5.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-fapi1t64', 'pkgver': '4.0.1-7.1ubuntu5.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-mu-4.0.1-0t64', 'pkgver': '4.0.1-7.1ubuntu5.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-policy0t64', 'pkgver': '4.0.1-7.1ubuntu5.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-rc0t64', 'pkgver': '4.0.1-7.1ubuntu5.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-sys1t64', 'pkgver': '4.0.1-7.1ubuntu5.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-tcti-cmd0t64', 'pkgver': '4.0.1-7.1ubuntu5.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-tcti-device0t64', 'pkgver': '4.0.1-7.1ubuntu5.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-tcti-libtpms0t64', 'pkgver': '4.0.1-7.1ubuntu5.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-tcti-mssim0t64', 'pkgver': '4.0.1-7.1ubuntu5.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-tcti-pcap0t64', 'pkgver': '4.0.1-7.1ubuntu5.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-tcti-spi-helper0t64', 'pkgver': '4.0.1-7.1ubuntu5.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-tcti-swtpm0t64', 'pkgver': '4.0.1-7.1ubuntu5.1'},
    {'osver': '24.04', 'pkgname': 'libtss2-tctildr0t64', 'pkgver': '4.0.1-7.1ubuntu5.1'}
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
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtss2-dev / libtss2-esys-3.0.2-0 / libtss2-esys-3.0.2-0t64 / etc');
}
