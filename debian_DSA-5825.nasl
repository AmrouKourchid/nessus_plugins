#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5825. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(212141);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/06");

  script_cve_id("CVE-2023-43040", "CVE-2024-48916");

  script_name(english:"Debian dsa-5825 : ceph - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5825 advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5825-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    December 06, 2024                     https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : ceph
    CVE ID         : CVE-2023-43040 CVE-2024-48916

    Sage McTaggart discovered an authentication bypass in radosgw, the RADOS
    REST gateway of Ceph, a distributed storage and file system.

    For the stable distribution (bookworm), these problems have been fixed in
    version 16.2.15+ds-0+deb12u1.

    We recommend that you upgrade your ceph packages.

    For the detailed security status of ceph please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/ceph

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ceph");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-43040");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-48916");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/ceph");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ceph packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-43040");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-base-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-common-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-grafana-dashboards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-immutable-object-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-immutable-object-cache-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mds-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mgr-cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mgr-dashboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mgr-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mgr-k8sevents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mgr-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mgr-rook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-osd-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-prometheus-alerts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cephfs-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cephfs-mirror-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cephfs-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cephfs-top");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librados-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librados2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libradospp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libradosstriper-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libradosstriper1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librbd1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librgw-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librgw2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite3-mod-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite3-mod-ceph-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsqlite3-mod-ceph-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rados-objclass-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:radosgw-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rbd-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rbd-fuse-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rbd-mirror-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rbd-nbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rbd-nbd-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'ceph', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-base', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-base-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-common', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-common-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-fuse', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-grafana-dashboards', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-immutable-object-cache', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-immutable-object-cache-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-mds', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-mds-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-mgr', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-mgr-cephadm', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-mgr-dashboard', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-mgr-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-mgr-k8sevents', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-mgr-modules-core', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-mgr-rook', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-mon', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-mon-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-osd', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-osd-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-prometheus-alerts', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-resource-agents', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'ceph-test', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'cephadm', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'cephfs-mirror', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'cephfs-mirror-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'cephfs-shell', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'cephfs-top', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libcephfs-dev', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libcephfs-java', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libcephfs-jni', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libcephfs2', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libcephfs2-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'librados-dev', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'librados2', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'librados2-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libradospp-dev', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libradosstriper-dev', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libradosstriper1', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libradosstriper1-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'librbd-dev', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'librbd1', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'librbd1-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'librgw-dev', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'librgw2', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'librgw2-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libsqlite3-mod-ceph', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libsqlite3-mod-ceph-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libsqlite3-mod-ceph-dev', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'python3-ceph', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'python3-ceph-argparse', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'python3-ceph-common', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'python3-cephfs', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'python3-rados', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'python3-rbd', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'python3-rgw', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'rados-objclass-dev', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'radosgw', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'radosgw-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'rbd-fuse', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'rbd-fuse-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'rbd-mirror', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'rbd-mirror-dbg', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'rbd-nbd', 'reference': '16.2.15+ds-0+deb12u1'},
    {'release': '12.0', 'prefix': 'rbd-nbd-dbg', 'reference': '16.2.15+ds-0+deb12u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph / ceph-base / ceph-base-dbg / ceph-common / ceph-common-dbg / etc');
}
