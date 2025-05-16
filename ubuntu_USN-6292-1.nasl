#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6292-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179904);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/28");

  script_cve_id("CVE-2022-3650");
  script_xref(name:"USN", value:"6292-1");

  script_name(english:"Ubuntu 23.04 : Ceph vulnerability (USN-6292-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 23.04 host has packages installed that are affected by a vulnerability as referenced in the USN-6292-1
advisory.

    It was discovered that Ceph incorrectly handled crash dumps. A local attacker could possibly use this
    issue to escalate privileges to root.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6292-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3650");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-grafana-dashboards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-immutable-object-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-dashboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-diskprediction-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-k8sevents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-rook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-prometheus-alerts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-volume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cephfs-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cephfs-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:crimson-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librados-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libradospp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libradosstriper-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librgw-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsqlite3-mod-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsqlite3-mod-ceph-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rados-objclass-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rbd-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rbd-nbd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('23.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '23.04', 'pkgname': 'ceph', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-base', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-common', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-fuse', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-grafana-dashboards', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-immutable-object-cache', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-mds', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-mgr', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-mgr-cephadm', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-mgr-dashboard', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-mgr-diskprediction-local', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-mgr-k8sevents', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-mgr-modules-core', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-mgr-rook', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-mon', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-osd', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-prometheus-alerts', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-resource-agents', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'ceph-volume', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'cephadm', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'cephfs-mirror', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'cephfs-shell', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'crimson-osd', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'libcephfs-dev', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'libcephfs-java', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'libcephfs-jni', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'libcephfs2', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'librados-dev', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'librados2', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'libradospp-dev', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'libradosstriper-dev', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'libradosstriper1', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'librbd-dev', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'librbd1', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'librgw-dev', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'librgw2', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'libsqlite3-mod-ceph', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'libsqlite3-mod-ceph-dev', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'python3-ceph', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'python3-ceph-argparse', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'python3-ceph-common', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'python3-cephfs', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'python3-rados', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'python3-rbd', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'python3-rgw', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'rados-objclass-dev', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'radosgw', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'rbd-fuse', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'rbd-mirror', 'pkgver': '17.2.6-0ubuntu0.23.04.2'},
    {'osver': '23.04', 'pkgname': 'rbd-nbd', 'pkgver': '17.2.6-0ubuntu0.23.04.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph / ceph-base / ceph-common / ceph-fuse / etc');
}
