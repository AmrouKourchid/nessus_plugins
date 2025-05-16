#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3845-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119655);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2018-8784",
    "CVE-2018-8785",
    "CVE-2018-8786",
    "CVE-2018-8787",
    "CVE-2018-8788",
    "CVE-2018-8789"
  );
  script_xref(name:"USN", value:"3845-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS : FreeRDP vulnerabilities (USN-3845-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-3845-1 advisory.

    Eyal Itkin discovered FreeRDP incorrectly handled certain stream encodings.

    A malicious server could use this issue to cause FreeRDP to crash, resulting in a denial of service, or
    possibly execute arbitrary code. This issue only applies to Ubuntu 18.04 LTS and Ubuntu 18.10.
    (CVE-2018-8784, CVE-2018-8785)

    Eyal Itkin discovered FreeRDP incorrectly handled bitmaps.

    A malicious server could use this issue to cause FreeRDP to crash, resulting in a denial of service, or
    possibly execute arbitrary code. (CVE-2018-8786, CVE-2018-8787)

    Eyal Itkin discovered FreeRDP incorrectly handled certain stream encodings.

    A malicious server could use this issue to cause FreeRDP to crash, resulting in a denial of service, or
    possibly execute arbitrary code. This issue only applies to Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu
    18.10. (CVE-2018-8788)

    Eyal Itkin discovered FreeRDP incorrectly handled NTLM authentication.

    A malicious server could use this issue to cause FreeRDP to crash, resulting in a denial of service, or
    possibly execute arbitrary code. This issue only applies to Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu
    18.10. (CVE-2018-8789)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3845-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-client1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-client2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-codec1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-common1.1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-core1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-crypto1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-gdi1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-locale1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-plugins-standard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-primitives1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-rail1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-server2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-shadow-subsystem2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-shadow2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-utils1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuwac0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuwac0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-asn1-0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-bcrypt0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-credentials0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-credui0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-crt0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-crypto0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-dsparse0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-environment0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-error0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-file0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-handle0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-heap0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-input0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-interlocked0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-io0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-library0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-path0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-pipe0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-pool0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-registry0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-rpc0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-sspi0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-sspicli0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-synch0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-sysinfo0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-thread0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-timezone0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-tools2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-utils0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-winhttp0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-winsock0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxfreerdp-client1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:winpr-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freerdp-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freerdp2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freerdp2-shadow-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freerdp2-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freerdp2-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-cache1.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2018-2024 Canonical, Inc. / NASL script (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('14.04' >< os_release || '16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04 / 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'freerdp-x11', 'pkgver': '1.0.2-2ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'libfreerdp-dev', 'pkgver': '1.0.2-2ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'libfreerdp-plugins-standard', 'pkgver': '1.0.2-2ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'libfreerdp1', 'pkgver': '1.0.2-2ubuntu1.2'},
    {'osver': '16.04', 'pkgname': 'freerdp-x11', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libfreerdp-cache1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libfreerdp-client1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libfreerdp-codec1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libfreerdp-common1.1.0', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libfreerdp-core1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libfreerdp-crypto1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libfreerdp-dev', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libfreerdp-gdi1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libfreerdp-locale1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libfreerdp-plugins-standard', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libfreerdp-primitives1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libfreerdp-rail1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libfreerdp-utils1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-asn1-0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-bcrypt0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-credentials0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-credui0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-crt0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-crypto0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-dev', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-dsparse0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-environment0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-error0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-file0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-handle0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-heap0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-input0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-interlocked0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-io0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-library0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-path0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-pipe0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-pool0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-registry0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-rpc0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-sspi0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-sspicli0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-synch0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-sysinfo0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-thread0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-timezone0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-utils0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-winhttp0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libwinpr-winsock0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libxfreerdp-client1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'freerdp2-dev', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'freerdp2-shadow-x11', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'freerdp2-wayland', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'freerdp2-x11', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-client2-2', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-server2-2', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-shadow-subsystem2-2', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-shadow2-2', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libfreerdp2-2', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libuwac0-0', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libuwac0-dev', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libwinpr-tools2-2', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libwinpr2-2', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'libwinpr2-dev', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'},
    {'osver': '18.04', 'pkgname': 'winpr-utils', 'pkgver': '2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp-x11 / freerdp2-dev / freerdp2-shadow-x11 / freerdp2-wayland / etc');
}
