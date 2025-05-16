#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3629. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(183749);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2019-10222",
    "CVE-2020-1700",
    "CVE-2020-1760",
    "CVE-2020-10753",
    "CVE-2020-12059",
    "CVE-2020-25678",
    "CVE-2020-27781",
    "CVE-2021-3524",
    "CVE-2021-3531",
    "CVE-2021-3979",
    "CVE-2021-20288",
    "CVE-2023-43040"
  );

  script_name(english:"Debian dla-3629 : ceph - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3629 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3629-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    October 23, 2023                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : ceph
    Version        : 12.2.11+dfsg1-2.1+deb10u1
    CVE ID         : CVE-2019-10222 CVE-2020-1700 CVE-2020-1760 CVE-2020-10753
                     CVE-2020-12059 CVE-2020-25678 CVE-2020-27781 CVE-2021-3524
                     CVE-2021-3531 CVE-2021-3979 CVE-2021-20288 CVE-2023-43040
    Debian Bug     : 1053690

    Multiple vulnerabilities were fixed in Ceph, a massively scalable,
    open-source, distributed storage system that runs on commodity hardware
    and delivers object, block and file system storage.

    CVE-2019-10222

        A Denial of service was fixed: An unauthenticated attacker could crash
        the Ceph RGW server by sending valid HTTP headers and terminating the
        connection, resulting in a remote denial of service for Ceph RGW clients.

    CVE-2020-1700

        A Denial of Service was fixed: A flaw was found in the way the Ceph RGW
        Beast front-end handles unexpected disconnects. An authenticated attacker
        can abuse this flaw by making multiple disconnect attempts resulting in a
        permanent leak of a socket connection by radosgw. This flaw could lead to
        a denial of service condition by pile up of CLOSE_WAIT sockets, eventually
        leading to the exhaustion of available resources, preventing legitimate
        users from connecting to the system.

    CVE-2020-1760

        A XSS attack was fixed: A flaw was found in the Ceph Object Gateway,
        where it supports request sent by an anonymous user in Amazon S3.
        This flaw could lead to potential XSS attacks due to the lack
        of proper neutralization of untrusted input.

    CVE-2020-10753

        A Header Injection attack was fixed: It was possible to
        inject HTTP headers via a CORS ExposeHeader tag in an Amazon S3 bucket. The
        newline character in the ExposeHeader tag in the CORS configuration file
        generates a header injection in the response when the CORS request is
        made.

    CVE-2020-12059

        A Denial of Service was fixed: A POST request with an invalid tagging
        XML could crash the RGW process by triggering a NULL pointer exception.

    CVE-2020-25678

        An Information Disclosure was fixed: ceph stores mgr module passwords
        in clear text. This can be found by searching the mgr logs for grafana and
        dashboard, with passwords visible.

    CVE-2020-27781

        A Privilege Escalation was fixed: User credentials could be manipulated
        and stolen by Native CephFS consumers of OpenStack Manila, resulting in
        potential privilege escalation. An Open Stack Manila user can request
        access to a share to an arbitrary cephx user, including existing users.
        The access key is retrieved via the interface drivers. Then, all users of
        the requesting OpenStack project can view the access key. This enables the
        attacker to target any resource that the user has access to. This can be
        done to even admin users, compromising the ceph administrator.

    CVE-2021-3524

        Similar to CVE-2020-10753, a Header Injection attack was fixed:
        It was possible to inject HTTP headers via a CORS ExposeHeader
        tag in an Amazon S3 bucket

    CVE-2021-3531

        A Denial of Service was fixed: When processing a GET Request in Ceph
        Storage RGW for a swift URL that ends with two slashes it could cause the
        rgw to crash, resulting in a denial of service.

    CVE-2021-3979

        A Loss of Confidentiality was fixed: A key length flaw was found in
        Ceph Storage. An attacker could exploit the fact that the key length is
        incorrectly passed in an encryption algorithm to create a non random key,
        which is weaker and can be exploited for loss of confidentiality and
        integrity on encrypted disks.

    CVE-2021-20288

        A Potential Privilege Escalation was fixed: When handling
        CEPHX_GET_PRINCIPAL_SESSION_KEY requests, ignore CEPH_ENTITY_TYPE_AUTH in
        CephXServiceTicketRequest::keys.

    CVE-2023-43040

        A flaw was found in Ceph RGW. An unprivileged
        user can write to any bucket(s) accessible by a given key
        if a POST's form-data contains a key called 'bucket'
        with a value matching the name of the bucket used to sign
        the request. The result of this is that a user could actually
        upload to any bucket accessible by the specified access key
        as long as the bucket in the POST policy matches the bucket
        in said POST form part.

    For Debian 10 buster, these problems have been fixed in version
    12.2.11+dfsg1-2.1+deb10u1.

    We recommend that you upgrade your ceph packages.

    For the detailed security status of ceph please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/ceph

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ceph");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-10222");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-10753");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-12059");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1700");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1760");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-25678");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-27781");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-20288");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3524");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3531");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3979");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-43040");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/ceph");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ceph packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20288");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librados-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libradosstriper-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librbd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librgw-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rados-objclass-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rbd-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rbd-nbd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'ceph', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'ceph-base', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'ceph-common', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'ceph-fuse', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'ceph-mds', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'ceph-mgr', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'ceph-mon', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'ceph-osd', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'ceph-resource-agents', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'ceph-test', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libcephfs-dev', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libcephfs-java', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libcephfs-jni', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libcephfs2', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'librados-dev', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'librados2', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libradosstriper-dev', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'libradosstriper1', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'librbd-dev', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'librbd1', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'librgw-dev', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'librgw2', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'python-ceph', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'python-cephfs', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'python-rados', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'python-rbd', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'python-rgw', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-ceph', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-cephfs', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-rados', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-rbd', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-rgw', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'rados-objclass-dev', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'radosgw', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'rbd-fuse', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'rbd-mirror', 'reference': '12.2.11+dfsg1-2.1+deb10u1'},
    {'release': '10.0', 'prefix': 'rbd-nbd', 'reference': '12.2.11+dfsg1-2.1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph / ceph-base / ceph-common / ceph-fuse / ceph-mds / ceph-mgr / etc');
}
