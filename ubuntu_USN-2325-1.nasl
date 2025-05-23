#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2325-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77325);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2014-3517");
  script_xref(name:"USN", value:"2325-1");

  script_name(english:"Ubuntu 14.04 LTS : OpenStack Nova vulnerability (USN-2325-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-2325-1 advisory.

    Alex Gaynor discovered that OpenStack Nova would sometimes respond with variable times when comparing
    authentication tokens. If nova were configured to proxy metadata requests via Neutron, a remote
    authenticated attacker could exploit this to conduct timing attacks and ascertain configuration details of
    another instance.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2325-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3517");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/22");

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

  script_copyright(english:"Ubuntu Security Notice (C) 2014-2020 Canonical, Inc. / NASL script (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '14.04', 'pkgname': 'nova-ajax-console-proxy', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-api', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-api-ec2', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-api-metadata', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-api-os-compute', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-api-os-volume', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-baremetal', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-cells', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-cert', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-common', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-compute', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-compute-kvm', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-compute-libvirt', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-compute-lxc', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-compute-qemu', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-compute-vmware', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-compute-xen', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-conductor', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-console', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-consoleauth', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-network', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-novncproxy', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-objectstore', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-scheduler', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-spiceproxy', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-volume', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'nova-xvpvncproxy', 'pkgver': '1:2014.1.2-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'python-nova', 'pkgver': '1:2014.1.2-0ubuntu1.1'}
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
