#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6613-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189748);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2023-43040");
  script_xref(name:"USN", value:"6613-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 LTS / 23.10 : Ceph vulnerability (USN-6613-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 ESM / 20.04 LTS / 22.04 LTS / 23.10 host has packages installed that are affected by
a vulnerability as referenced in the USN-6613-1 advisory.

    Lucas Henry discovered that Ceph incorrectly handled specially crafted POST requests. An uprivileged user
    could use this to

    bypass Ceph's authorization checks and upload a file to any bucket.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6613-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-43040");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-fs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-grafana-dashboards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-immutable-object-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-dashboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-diskprediction-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-diskprediction-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-k8sevents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mgr-rook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-prometheus-alerts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ceph-volume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cephfs-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:cephfs-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:crimson-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcephfs1");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-rgw");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:rest-bench");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2024 Canonical, Inc. / NASL script (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release || '23.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04 / 23.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'ceph', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'ceph-common', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'ceph-fs-common', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'ceph-fuse', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'ceph-mds', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'ceph-resource-agents', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'ceph-test', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcephfs-dev', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcephfs-java', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcephfs-jni', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libcephfs1', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'librados-dev', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'librados2', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libradosstriper-dev', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libradosstriper1', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'librbd-dev', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'librbd1', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'librgw-dev', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'librgw2', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python-ceph', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python-cephfs', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python-rados', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'python-rbd', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'radosgw', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'rbd-fuse', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'rbd-mirror', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'rbd-nbd', 'pkgver': '10.2.11-0ubuntu0.16.04.3+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'ceph', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'ceph-base', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'ceph-common', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'ceph-fuse', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'ceph-mds', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'ceph-mgr', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'ceph-mon', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'ceph-osd', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'ceph-resource-agents', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'ceph-test', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libcephfs-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libcephfs-java', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libcephfs-jni', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libcephfs2', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'librados-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'librados2', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libradosstriper-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'libradosstriper1', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'librbd-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'librbd1', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'librgw-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'librgw2', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python-ceph', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python-cephfs', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python-rados', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python-rbd', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python-rgw', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3-ceph-argparse', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3-cephfs', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3-rados', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3-rbd', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'python3-rgw', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'rados-objclass-dev', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'radosgw', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'rbd-fuse', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'rbd-mirror', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '18.04', 'pkgname': 'rbd-nbd', 'pkgver': '12.2.13-0ubuntu0.18.04.11+esm1', 'ubuntu_pro': TRUE},
    {'osver': '20.04', 'pkgname': 'ceph', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-base', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-common', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-fuse', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-immutable-object-cache', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-mds', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-mgr', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-cephadm', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-dashboard', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-diskprediction-cloud', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-diskprediction-local', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-k8sevents', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-modules-core', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-mgr-rook', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-mon', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-osd', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'ceph-resource-agents', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'cephadm', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'cephfs-shell', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libcephfs-dev', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libcephfs-java', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libcephfs-jni', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libcephfs2', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'librados-dev', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'librados2', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libradospp-dev', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libradosstriper-dev', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'libradosstriper1', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'librbd-dev', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'librbd1', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'librgw-dev', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'librgw2', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3-ceph', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3-ceph-argparse', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3-ceph-common', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3-cephfs', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3-rados', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3-rbd', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'python3-rgw', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'rados-objclass-dev', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'radosgw', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'rbd-fuse', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'rbd-mirror', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '20.04', 'pkgname': 'rbd-nbd', 'pkgver': '15.2.17-0ubuntu0.20.04.6', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-base', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-common', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-fuse', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-grafana-dashboards', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-immutable-object-cache', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-mds', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-mgr', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-mgr-cephadm', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-mgr-dashboard', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-mgr-diskprediction-local', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-mgr-k8sevents', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-mgr-modules-core', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-mgr-rook', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-mon', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-osd', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-prometheus-alerts', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-resource-agents', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'ceph-volume', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'cephadm', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'cephfs-mirror', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'cephfs-shell', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'crimson-osd', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libcephfs-dev', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libcephfs-java', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libcephfs-jni', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libcephfs2', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'librados-dev', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'librados2', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libradospp-dev', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libradosstriper-dev', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libradosstriper1', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'librbd-dev', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'librbd1', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'librgw-dev', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'librgw2', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libsqlite3-mod-ceph', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'libsqlite3-mod-ceph-dev', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3-ceph', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3-ceph-argparse', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3-ceph-common', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3-cephfs', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3-rados', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3-rbd', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'python3-rgw', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'rados-objclass-dev', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'radosgw', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'rbd-fuse', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'rbd-mirror', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '22.04', 'pkgname': 'rbd-nbd', 'pkgver': '17.2.6-0ubuntu0.22.04.3', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-base', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-common', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-fuse', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-grafana-dashboards', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-immutable-object-cache', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-mds', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-mgr', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-mgr-cephadm', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-mgr-dashboard', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-mgr-diskprediction-local', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-mgr-k8sevents', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-mgr-modules-core', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-mgr-rook', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-mon', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-osd', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-prometheus-alerts', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-resource-agents', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'ceph-volume', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'cephadm', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'cephfs-mirror', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'cephfs-shell', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'crimson-osd', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libcephfs-dev', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libcephfs-java', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libcephfs-jni', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libcephfs2', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'librados-dev', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'librados2', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libradospp-dev', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libradosstriper-dev', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libradosstriper1', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'librbd-dev', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'librbd1', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'librgw-dev', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'librgw2', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libsqlite3-mod-ceph', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'libsqlite3-mod-ceph-dev', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3-ceph', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3-ceph-argparse', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3-ceph-common', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3-cephfs', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3-rados', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3-rbd', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'python3-rgw', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'rados-objclass-dev', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'radosgw', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'rbd-fuse', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'rbd-mirror', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE},
    {'osver': '23.10', 'pkgname': 'rbd-nbd', 'pkgver': '18.2.0-0ubuntu3.1', 'ubuntu_pro': FALSE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph / ceph-base / ceph-common / ceph-fs-common / ceph-fuse / etc');
}
