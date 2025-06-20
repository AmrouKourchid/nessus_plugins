#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5866-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171386);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id(
    "CVE-2015-9543",
    "CVE-2017-18191",
    "CVE-2020-17376",
    "CVE-2021-3654",
    "CVE-2022-37394"
  );
  script_xref(name:"USN", value:"5866-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS : Nova vulnerabilities (USN-5866-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5866-1 advisory.

    It was discovered that Nova did not properly manage data logged into the log file. An attacker with read
    access to the service's logs could exploit this issue and may obtain sensitive information. This issue
    only affected Ubuntu 16.04 ESM and Ubuntu 18.04 LTS. (CVE-2015-9543)

    It was discovered that Nova did not properly handle attaching and reattaching the encrypted volume. An
    attacker could possibly use this issue to perform a denial of service attack. This issue only affected
    Ubuntu 16.04 ESM. (CVE-2017-18191)

    It was discovered that Nova did not properly handle the updation of domain XML after live migration. An
    attacker could possibly use this issue to corrupt the volume or perform a denial of service attack. This
    issue only affected Ubuntu 18.04 LTS. (CVE-2020-17376)

    It was discovered that Nova was not properly validating the URL passed to noVNC. An attacker could
    possibly use this issue by providing malicious URL to the noVNC proxy to redirect to any desired URL. This
    issue only affected Ubuntu 16.04 ESM and Ubuntu 18.04 LTS. (CVE-2021-3654)

    It was discovered that Nova did not properly handle changes in the neutron port of vnic_type type. An
    authenticated user could possibly use this issue to perform a denial of service attack. This issue only
    affected Ubuntu 20.04 LTS. (CVE-2022-37394)

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5866-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17376");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-ajax-console-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api-os-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-api-os-volume");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-placement-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-serialproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-spiceproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-volume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nova-xvpvncproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-nova");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-nova");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
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
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'nova-ajax-console-proxy', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-api', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-api-metadata', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-api-os-compute', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-api-os-volume', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-cells', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-cert', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-common', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-compute', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-compute-kvm', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-compute-libvirt', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-compute-lxc', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-compute-qemu', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-compute-vmware', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-compute-xen', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-conductor', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-console', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-consoleauth', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-network', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-novncproxy', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-scheduler', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-serialproxy', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-spiceproxy', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-volume', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'nova-xvpvncproxy', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python-nova', 'pkgver': '2:13.1.4-0ubuntu4.5+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'nova-ajax-console-proxy', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-api', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-api-metadata', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-api-os-compute', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-api-os-volume', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-cells', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-common', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-compute', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-compute-kvm', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-compute-libvirt', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-compute-lxc', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-compute-qemu', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-compute-vmware', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-compute-xen', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-conductor', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-console', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-consoleauth', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-network', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-novncproxy', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-placement-api', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-scheduler', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-serialproxy', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-spiceproxy', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-volume', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'nova-xvpvncproxy', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '18.04', 'pkgname': 'python-nova', 'pkgver': '2:17.0.13-0ubuntu5.3', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-ajax-console-proxy', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-api', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-api-metadata', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-api-os-compute', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-api-os-volume', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-cells', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-common', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-compute', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-compute-kvm', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-compute-libvirt', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-compute-lxc', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-compute-qemu', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-compute-vmware', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-compute-xen', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-conductor', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-novncproxy', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-scheduler', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-serialproxy', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-spiceproxy', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'nova-volume', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3-nova', 'pkgver': '2:21.2.4-0ubuntu2.2', 'ubuntu_pro': FALSE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) {
        flag++;
        if (!ubuntu_pro_detected && !pro_caveat_needed) pro_caveat_needed = pro_required;
    }
  }
}

if (flag)
{
  var extra = '';
  if (pro_caveat_needed) {
    extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
    extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
    extra += 'require an Ubuntu Pro subscription.\n\n';
  }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nova-ajax-console-proxy / nova-api / nova-api-metadata / etc');
}
