#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3346-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(101157);
  script_version("3.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2017-3142", "CVE-2017-3143");
  script_xref(name:"USN", value:"3346-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS : bind9 vulnerabilities (USN-3346-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS / 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-3346-1 advisory.

    Clment Berthaux discovered that Bind did not correctly check TSIG authentication for zone update
    requests. An attacker could use this to improperly perform zone updates. (CVE-2017-3143)

    Clment Berthaux discovered that Bind did not correctly check TSIG authentication for zone transfer
    requests. An attacker could use this to improperly transfer entire zones. (CVE-2017-3142)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3346-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3143");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind-export-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind9-140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libbind9-90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns-export162");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns-export162-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns162");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libirs-export141");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libirs-export141-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libirs141");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc-export160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc-export160-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc160");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisc95");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc-export140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc-export140-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccc90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg-export140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg-export140-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg140");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libisccfg90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblwres141");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblwres90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lwresd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2017-2025 Canonical, Inc. / NASL script (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'bind9', 'pkgver': '1:9.9.5.dfsg-3ubuntu0.15'},
    {'osver': '14.04', 'pkgname': 'bind9-host', 'pkgver': '1:9.9.5.dfsg-3ubuntu0.15'},
    {'osver': '14.04', 'pkgname': 'bind9utils', 'pkgver': '1:9.9.5.dfsg-3ubuntu0.15'},
    {'osver': '14.04', 'pkgname': 'dnsutils', 'pkgver': '1:9.9.5.dfsg-3ubuntu0.15'},
    {'osver': '14.04', 'pkgname': 'host', 'pkgver': '1:9.9.5.dfsg-3ubuntu0.15'},
    {'osver': '14.04', 'pkgname': 'libbind-dev', 'pkgver': '1:9.9.5.dfsg-3ubuntu0.15'},
    {'osver': '14.04', 'pkgname': 'libbind9-90', 'pkgver': '1:9.9.5.dfsg-3ubuntu0.15'},
    {'osver': '14.04', 'pkgname': 'libdns100', 'pkgver': '1:9.9.5.dfsg-3ubuntu0.15'},
    {'osver': '14.04', 'pkgname': 'libisc95', 'pkgver': '1:9.9.5.dfsg-3ubuntu0.15'},
    {'osver': '14.04', 'pkgname': 'libisccc90', 'pkgver': '1:9.9.5.dfsg-3ubuntu0.15'},
    {'osver': '14.04', 'pkgname': 'libisccfg90', 'pkgver': '1:9.9.5.dfsg-3ubuntu0.15'},
    {'osver': '14.04', 'pkgname': 'liblwres90', 'pkgver': '1:9.9.5.dfsg-3ubuntu0.15'},
    {'osver': '14.04', 'pkgname': 'lwresd', 'pkgver': '1:9.9.5.dfsg-3ubuntu0.15'},
    {'osver': '16.04', 'pkgname': 'bind9', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'bind9-host', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'bind9utils', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'dnsutils', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'host', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libbind-dev', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libbind-export-dev', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libbind9-140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libdns-export162', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libdns-export162-udeb', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libdns162', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libirs-export141', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libirs-export141-udeb', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libirs141', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libisc-export160', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libisc-export160-udeb', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libisc160', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libisccc-export140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libisccc-export140-udeb', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libisccc140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libisccfg-export140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libisccfg-export140-udeb', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'libisccfg140', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'liblwres141', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'},
    {'osver': '16.04', 'pkgname': 'lwresd', 'pkgver': '1:9.10.3.dfsg.P4-8ubuntu1.7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind9 / bind9-host / bind9utils / dnsutils / host / libbind-dev / etc');
}
