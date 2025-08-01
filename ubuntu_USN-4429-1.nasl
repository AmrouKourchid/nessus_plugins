#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4429-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138873);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/29");

  script_cve_id("CVE-2020-14928");
  script_xref(name:"USN", value:"4429-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : Evolution Data Server vulnerability (USN-4429-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-4429-1 advisory.

    It was discovered that Evolution Data Server incorrectly handled STARTTLS when using SMTP and POP3. A
    remote attacker could possibly use this issue to perform a response injection attack.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4429-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14928");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:evolution-data-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:evolution-data-server-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:evolution-data-server-online-accounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:evolution-data-server-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-camel-1.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-ebackend-1.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-ebook-1.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-ebookcontacts-1.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-ecal-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-edatabook-1.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-edatacal-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-edataserver-1.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-edataserverui-1.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcamel-1.2-54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcamel-1.2-61");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcamel-1.2-62");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcamel1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libebackend-1.2-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libebackend1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libebook-1.2-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libebook-1.2-19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libebook-1.2-20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libebook-contacts-1.2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libebook-contacts-1.2-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libebook-contacts1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libebook1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecal-1.2-19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecal-2.0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecal1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libecal2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedata-book-1.2-25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedata-book-1.2-26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedata-book1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedata-cal-1.2-28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedata-cal-2.0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedata-cal1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedata-cal2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedataserver-1.2-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedataserver-1.2-23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedataserver-1.2-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedataserver1.2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedataserverui-1.2-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedataserverui-1.2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libedataserverui1.2-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2024 Canonical, Inc. / NASL script (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'evolution-data-server', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'evolution-data-server-common', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'evolution-data-server-dev', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'evolution-data-server-online-accounts', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'gir1.2-ebook-1.2', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'gir1.2-ebookcontacts-1.2', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'gir1.2-edataserver-1.2', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libcamel-1.2-54', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libcamel1.2-dev', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libebackend-1.2-10', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libebackend1.2-dev', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libebook-1.2-16', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libebook-contacts-1.2-2', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libebook-contacts1.2-dev', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libebook1.2-dev', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libecal-1.2-19', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libecal1.2-dev', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libedata-book-1.2-25', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libedata-book1.2-dev', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libedata-cal-1.2-28', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libedata-cal1.2-dev', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libedataserver-1.2-21', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libedataserver1.2-dev', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libedataserverui-1.2-1', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '16.04', 'pkgname': 'libedataserverui1.2-dev', 'pkgver': '3.18.5-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'evolution-data-server', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'evolution-data-server-common', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'evolution-data-server-dev', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'evolution-data-server-online-accounts', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'evolution-data-server-tests', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'gir1.2-camel-1.2', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'gir1.2-ebook-1.2', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'gir1.2-ebookcontacts-1.2', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'gir1.2-edataserver-1.2', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'gir1.2-edataserverui-1.2', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libcamel-1.2-61', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libcamel1.2-dev', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libebackend-1.2-10', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libebackend1.2-dev', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libebook-1.2-19', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libebook-contacts-1.2-2', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libebook-contacts1.2-dev', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libebook1.2-dev', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libecal-1.2-19', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libecal1.2-dev', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libedata-book-1.2-25', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libedata-book1.2-dev', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libedata-cal-1.2-28', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libedata-cal1.2-dev', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libedataserver-1.2-23', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libedataserver1.2-dev', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libedataserverui-1.2-2', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '18.04', 'pkgname': 'libedataserverui1.2-dev', 'pkgver': '3.28.5-0ubuntu0.18.04.3'},
    {'osver': '20.04', 'pkgname': 'evolution-data-server', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'evolution-data-server-common', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'evolution-data-server-dev', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'evolution-data-server-tests', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-camel-1.2', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-ebackend-1.2', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-ebook-1.2', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-ebookcontacts-1.2', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-ecal-2.0', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-edatabook-1.2', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-edatacal-2.0', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-edataserver-1.2', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-edataserverui-1.2', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libcamel-1.2-62', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libcamel1.2-dev', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libebackend-1.2-10', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libebackend1.2-dev', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libebook-1.2-20', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libebook-contacts-1.2-3', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libebook-contacts1.2-dev', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libebook1.2-dev', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libecal-2.0-1', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libecal2.0-dev', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libedata-book-1.2-26', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libedata-book1.2-dev', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libedata-cal-2.0-1', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libedata-cal2.0-dev', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libedataserver-1.2-24', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libedataserver1.2-dev', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libedataserverui-1.2-2', 'pkgver': '3.36.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libedataserverui1.2-dev', 'pkgver': '3.36.3-0ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'evolution-data-server / evolution-data-server-common / etc');
}
