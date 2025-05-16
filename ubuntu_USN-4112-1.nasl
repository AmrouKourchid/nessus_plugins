#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4112-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128323);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2019-10222");
  script_xref(name:"USN", value:"4112-1");

  script_name(english:"Ubuntu 18.04 LTS : Ceph vulnerability (USN-4112-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-4112-1 advisory.

    Abhishek Lekshmanan discovered that the RADOS gateway implementation in Ceph did not handle client
    disconnects properly in some situations. A remote attacker could use this to cause a denial of service.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4112-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librados-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libradosstriper-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librgw-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rados-objclass-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rbd-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rbd-nbd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2019-2024 Canonical, Inc. / NASL script (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'ceph', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'ceph-base', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'ceph-common', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'ceph-fuse', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'ceph-mds', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'ceph-mgr', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'ceph-mon', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'ceph-osd', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'ceph-resource-agents', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'ceph-test', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libcephfs-dev', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libcephfs-java', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libcephfs-jni', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libcephfs2', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'librados-dev', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'librados2', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libradosstriper-dev', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libradosstriper1', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'librbd-dev', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'librbd1', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'librgw-dev', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'librgw2', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'python-ceph', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'python-cephfs', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'python-rados', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'python-rbd', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'python-rgw', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3-ceph-argparse', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3-cephfs', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3-rados', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3-rbd', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'python3-rgw', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'rados-objclass-dev', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'radosgw', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'rbd-fuse', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'rbd-mirror', 'pkgver': '12.2.12-0ubuntu0.18.04.2'},
    {'osver': '18.04', 'pkgname': 'rbd-nbd', 'pkgver': '12.2.12-0ubuntu0.18.04.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph / ceph-base / ceph-common / ceph-fuse / ceph-mds / ceph-mgr / etc');
}
