#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2408-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79214);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2014-6414");
  script_xref(name:"USN", value:"2408-1");

  script_name(english:"Ubuntu 14.04 LTS : OpenStack Neutron vulnerability (USN-2408-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 14.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-2408-1 advisory.

    Elena Ezhova discovered that OpenStack Neutron did not properly perform access control checks for
    attributes. A remote authenticated attacker could exploit this to bypass intended access controls and
    reset admin-only attributes to default values.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-2408-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6414");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-neutron");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-dhcp-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-l3-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-lbaas-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-metadata-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-metering-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-bigswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-bigswitch-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-brocade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-cisco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-hyperv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-ibm-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-linuxbridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-linuxbridge-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-metaplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-metering-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-midonet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-ml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-mlnx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-mlnx-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-nec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-nec-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-nicira");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-oneconvergence");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-oneconvergence-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-openflow-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-openvswitch-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-plumgrid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-ryu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-ryu-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-plugin-vpn-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:neutron-vpn-agent");
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
    {'osver': '14.04', 'pkgname': 'neutron-common', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-dhcp-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-l3-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-lbaas-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-metadata-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-metering-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-bigswitch', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-bigswitch-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-brocade', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-cisco', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-hyperv', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-ibm', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-ibm-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-linuxbridge', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-linuxbridge-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-metaplugin', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-metering-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-midonet', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-ml2', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-mlnx', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-mlnx-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-nec', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-nec-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-nicira', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-oneconvergence', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-oneconvergence-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-openflow-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-openvswitch', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-openvswitch-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-plumgrid', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-ryu', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-ryu-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-vmware', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-plugin-vpn-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-server', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'neutron-vpn-agent', 'pkgver': '1:2014.1.3-0ubuntu1.1'},
    {'osver': '14.04', 'pkgname': 'python-neutron', 'pkgver': '1:2014.1.3-0ubuntu1.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'neutron-common / neutron-dhcp-agent / neutron-l3-agent / etc');
}
