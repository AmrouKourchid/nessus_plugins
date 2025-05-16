#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2247-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76109);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id(
    "CVE-2013-1068",
    "CVE-2013-4463",
    "CVE-2013-4469",
    "CVE-2013-6491",
    "CVE-2013-7130",
    "CVE-2014-0134",
    "CVE-2014-0167"
  );
  script_bugtraq_id(
    63467,
    63468,
    65106,
    65276,
    66495,
    66753,
    68094
  );
  script_xref(name:"USN", value:"2247-1");

  script_name(english:"Ubuntu 14.04 LTS : OpenStack Nova vulnerabilities (USN-2247-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-2247-1 advisory.

    Darragh O'Reilly discovered that the Ubuntu packaging for OpenStack Nova did not properly set up its sudo
    configuration. If a different flaw was found in OpenStack Nova, this vulnerability could be used to
    escalate privileges. This issue only affected Ubuntu 13.10 and Ubuntu 14.04 LTS. (CVE-2013-1068)

    Bernhard M. Wiedemann and Pedraig Brady discovered that OpenStack Nova did not properly verify the virtual
    size of a QCOW2 images. A remote authenticated attacker could exploit this to create a denial of service
    via disk consumption. This issue did not affect Ubuntu 14.04 LTS. (CVE-2013-4463, CVE-2013-4469)

    JuanFra Rodriguez Cardoso discovered that OpenStack Nova did not enforce SSL connections when Nova was
    configured to use QPid and qpid_protocol is set to 'ssl'. If a remote attacker were able to perform a
    machine-in-the-middle attack, this flaw could be exploited to view sensitive information. Ubuntu does not
    use QPid with Nova by default. This issue did not affect Ubuntu 14.04 LTS. (CVE-2013-6491)

    Loganathan Parthipan discovered that OpenStack Nova did not properly create expected files during KVM live
    block migration. A remote authenticated attacker could exploit this to obtain root disk snapshot contents
    via ephemeral storage. This issue did not affect Ubuntu 14.04 LTS. (CVE-2013-7130)

    Stanislaw Pitucha discovered that OpenStack Nova did not enforce the image format when rescuing an
    instance. A remote authenticated attacker could exploit this to read host files. In the default
    installation, attackers would be isolated by the libvirt guest AppArmor profile. This issue only affected
    Ubuntu 13.10. (CVE-2014-0134)

    Mark Heckmann discovered that OpenStack Nova did not enforce RBAC policy when adding security group rules
    via the EC2 API. A remote authenticated user could exploit this to gain unintended access to this API.
    This issue only affected Ubuntu 13.10. (CVE-2014-0167)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2247-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-7130");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-0167");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

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
    {'osver': '14.04', 'pkgname': 'nova-ajax-console-proxy', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-api', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-api-ec2', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-api-metadata', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-api-os-compute', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-api-os-volume', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-baremetal', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-cells', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-cert', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-common', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-compute', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-compute-kvm', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-compute-libvirt', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-compute-lxc', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-compute-qemu', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-compute-vmware', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-compute-xen', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-conductor', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-console', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-consoleauth', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-network', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-novncproxy', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-objectstore', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-scheduler', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-spiceproxy', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-volume', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'nova-xvpvncproxy', 'pkgver': '1:2014.1-0ubuntu1.2'},
    {'osver': '14.04', 'pkgname': 'python-nova', 'pkgver': '1:2014.1-0ubuntu1.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nova-ajax-console-proxy / nova-api / nova-api-ec2 / etc');
}
