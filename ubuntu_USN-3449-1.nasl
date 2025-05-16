#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3449-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(103812);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2015-3241",
    "CVE-2015-3280",
    "CVE-2015-5162",
    "CVE-2015-7548",
    "CVE-2015-7713",
    "CVE-2015-8749",
    "CVE-2016-2140"
  );
  script_xref(name:"USN", value:"3449-1");

  script_name(english:"Ubuntu 14.04 LTS : OpenStack Nova vulnerabilities (USN-3449-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-3449-1 advisory.

    George Shuklin discovered that OpenStack Nova incorrectly handled the migration process. A remote
    authenticated user could use this issue to consume resources, resulting in a denial of service.
    (CVE-2015-3241)

    George Shuklin and Tushar Patil discovered that OpenStack Nova incorrectly handled deleting instances. A
    remote authenticated user could use this issue to consume disk resources, resulting in a denial of
    service. (CVE-2015-3280)

    It was discovered that OpenStack Nova incorrectly limited qemu-img calls. A remote authenticated user
    could use this issue to consume resources, resulting in a denial of service. (CVE-2015-5162)

    Matthew Booth discovered that OpenStack Nova incorrectly handled snapshots. A remote authenticated user
    could use this issue to read arbitrary files. (CVE-2015-7548)

    Sreekumar S. and Suntao discovered that OpenStack Nova incorrectly applied security group changes. A
    remote attacker could possibly use this issue to bypass intended restriction changes by leveraging an
    instance that was running when the change was made. (CVE-2015-7713)

    Matt Riedemann discovered that OpenStack Nova incorrectly handled logging. A local attacker could possibly
    use this issue to obtain sensitive information from log files. (CVE-2015-8749)

    Matthew Booth discovered that OpenStack Nova incorrectly handled certain qcow2 headers. A remote
    authenticated user could possibly use this issue to read arbitrary files. (CVE-2016-2140)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-3449-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7713");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-nova");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-ajax-console-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api-os-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api-os-volume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-baremetal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-cells");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-cert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-compute-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-conductor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-consoleauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-novncproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-objectstore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-spiceproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-volume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-xvpvncproxy");
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
if (! ('14.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 14.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '14.04', 'pkgname': 'nova-ajax-console-proxy', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-api', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-api-ec2', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-api-metadata', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-api-os-compute', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-api-os-volume', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-baremetal', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-cells', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-cert', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-common', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-compute', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-compute-kvm', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-compute-libvirt', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-compute-lxc', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-compute-qemu', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-compute-vmware', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-compute-xen', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-conductor', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-console', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-consoleauth', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-network', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-novncproxy', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-objectstore', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-scheduler', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-spiceproxy', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-volume', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'nova-xvpvncproxy', 'pkgver': '1:2014.1.5-0ubuntu1.7'},
    {'osver': '14.04', 'pkgname': 'python-nova', 'pkgver': '1:2014.1.5-0ubuntu1.7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nova-ajax-console-proxy / nova-api / nova-api-ec2 / etc');
}
