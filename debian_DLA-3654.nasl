#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3654. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(185962);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2021-41160",
    "CVE-2022-24883",
    "CVE-2022-39282",
    "CVE-2022-39283",
    "CVE-2022-39316",
    "CVE-2022-39318",
    "CVE-2022-39319",
    "CVE-2022-39347",
    "CVE-2022-41877",
    "CVE-2023-39283"
  );

  script_name(english:"Debian dla-3654 : freerdp2-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3654 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3654-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    November 17, 2023                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : freerdp2
    Version        : 2.3.0+dfsg1-2+deb10u4
    CVE ID         : CVE-2021-41160 CVE-2022-24883 CVE-2022-39282 CVE-2022-39283
                     CVE-2022-39316 CVE-2022-39318 CVE-2022-39319 CVE-2022-39347
                     CVE-2022-41877

    Debian Bug     : 1001062 1021659

    Multiple vulnerabilties have been found in freelrdp2, a free implementation of
    the Remote Desktop Protocol (RDP). The vulnerabilties potentially allows
    authentication bypasses on configuration errors, buffer overreads, DoS vectors,
    buffer overflows or accessing files outside of a shared directory.

    CVE-2021-41160

        In affected versions a malicious server might trigger out of bound writes in a
        connected client. Connections using GDI or SurfaceCommands to send graphics
        updates to the client might send `0` width/height or out of bound rectangles to
        trigger out of bound writes. With `0` width or heigth the memory allocation
        will be `0` but the missing bounds checks allow writing to the pointer at this
        (not allocated) region.

    CVE-2022-24883

        Prior to version 2.7.0, server side authentication against a `SAM` file might
        be successful for invalid credentials if the server has configured an invalid
        `SAM` file path. FreeRDP based clients are not affected. RDP server
        implementations using FreeRDP to authenticate against a `SAM` file are
        affected. Version 2.7.0 contains a fix for this issue. As a workaround, use
        custom authentication via `HashCallback` and/or ensure the `SAM` database path
        configured is valid and the application has file handles left.

    CVE-2022-39282

        FreeRDP based clients on unix systems using `/parallel` command line switch
        might read uninitialized data and send it to the server the client is currently
        connected to. FreeRDP based server implementations are not affected.

    CVE-2023-39283

        All FreeRDP based clients when using the `/video` command line switch might
        read uninitialized data, decode it as audio/video and display the result.
        FreeRDP based server implementations are not affected.

    CVE-2022-39316

        In affected versions there is an out of bound read in ZGFX decoder component of
        FreeRDP. A malicious server can trick a FreeRDP based client to read out of
        bound data and try to decode it likely resulting in a crash.

    CVE-2022-39318

        Affected versions of FreeRDP are missing input validation in `urbdrc` channel.
        A malicious server can trick a FreeRDP based client to crash with division by
        zero.

    CVE-2022-39319

        Affected versions of FreeRDP are missing input length validation in the
        `urbdrc` channel. A malicious server can trick a FreeRDP based client to read
        out of bound data and send it back to the server.

    CVE-2022-39347

        Affected versions of FreeRDP are missing path canonicalization and base path
        check for `drive` channel. A malicious server can trick a FreeRDP based client
        to read files outside the shared directory.

    CVE-2022-41877

        Affected versions of FreeRDP are missing input length validation in `drive`
        channel. A malicious server can trick a FreeRDP based client to read out of
        bound data and send it back to the server.


    For Debian 10 buster, these problems have been fixed in version
    2.3.0+dfsg1-2+deb10u4.

    We recommend that you upgrade your freerdp2 packages.

    For the detailed security status of freerdp2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/freerdp2

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/freerdp2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41160");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24883");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39282");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39283");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39316");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39318");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39319");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39347");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41877");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39283");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/freerdp2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the freerdp2-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24883");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-shadow-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freerdp2-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-client2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-server2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-shadow-subsystem2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp-shadow2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreerdp2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuwac0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuwac0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr-tools2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwinpr2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:winpr-utils");
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
    {'release': '10.0', 'prefix': 'freerdp2-dev', 'reference': '2.3.0+dfsg1-2+deb10u4'},
    {'release': '10.0', 'prefix': 'freerdp2-shadow-x11', 'reference': '2.3.0+dfsg1-2+deb10u4'},
    {'release': '10.0', 'prefix': 'freerdp2-wayland', 'reference': '2.3.0+dfsg1-2+deb10u4'},
    {'release': '10.0', 'prefix': 'freerdp2-x11', 'reference': '2.3.0+dfsg1-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libfreerdp-client2-2', 'reference': '2.3.0+dfsg1-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libfreerdp-server2-2', 'reference': '2.3.0+dfsg1-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libfreerdp-shadow-subsystem2-2', 'reference': '2.3.0+dfsg1-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libfreerdp-shadow2-2', 'reference': '2.3.0+dfsg1-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libfreerdp2-2', 'reference': '2.3.0+dfsg1-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libuwac0-0', 'reference': '2.3.0+dfsg1-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libuwac0-dev', 'reference': '2.3.0+dfsg1-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libwinpr-tools2-2', 'reference': '2.3.0+dfsg1-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libwinpr2-2', 'reference': '2.3.0+dfsg1-2+deb10u4'},
    {'release': '10.0', 'prefix': 'libwinpr2-dev', 'reference': '2.3.0+dfsg1-2+deb10u4'},
    {'release': '10.0', 'prefix': 'winpr-utils', 'reference': '2.3.0+dfsg1-2+deb10u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp2-dev / freerdp2-shadow-x11 / freerdp2-wayland / freerdp2-x11 / etc');
}
