#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5664. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(193483);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-22201");

  script_name(english:"Debian dsa-5664 : jetty9 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5664
advisory.

    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA512

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5664-1                   security@debian.org
    https://www.debian.org/security/                          Markus Koschany
    April 17, 2024                        https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : jetty9
    CVE ID         : CVE-2024-22201

    Jetty 9 is a Java based web server and servlet engine. It was discovered that
    remote attackers may leave many HTTP/2 connections in ESTABLISHED state (not
    closed), TCP congested and idle. Eventually the server will stop accepting new
    connections from valid clients which can cause a denial of service.

    For the oldstable distribution (bullseye), this problem has been fixed
    in version 9.4.50-4+deb11u2.

    For the stable distribution (bookworm), this problem has been fixed in
    version 9.4.50-4+deb12u3.

    We recommend that you upgrade your jetty9 packages.

    For the detailed security status of jetty9 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/jetty9

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org
    -----BEGIN PGP SIGNATURE-----

    iQKTBAEBCgB9FiEErPPQiO8y7e9qGoNf2a0UuVE7UeQFAmYgPqhfFIAAAAAALgAo
    aXNzdWVyLWZwckBub3RhdGlvbnMub3BlbnBncC5maWZ0aGhvcnNlbWFuLm5ldEFD
    RjNEMDg4RUYzMkVERUY2QTFBODM1RkQ5QUQxNEI5NTEzQjUxRTQACgkQ2a0UuVE7
    UeS8Wg/+JvDyNdRq1Tu6rEqfHprMuxVifvPSH4RefpWMVY1MUIwRSxCyL9GEKCtu
    q0a+Vf/JycNVbTcRB0n/UpgFdCCWE6dUngLIoYX/SmA+dXKLN9a+FIKj/aivOvOr
    CUEkaJiVBjARYoBxDzoLG8STAJkxJvCAIduOSZ4Pr3iaZ+3+mHLpz38aAHz7QCXS
    NoqaD66hMTCVPnVTTr3CvrhCIjcdxQRteJwkJ0XxT5WxYSBmVuB+zEAxHUt6ocv2
    5bMel+B4OMcNrRrdQiUtqAF2i7ktAPO2HUo5+9kxYCwkB1DbgIEhdtkA6aBtTYZ0
    ZJbx4kV206DrQO7PjLzbY6RA2o2EiNb1zEZlaaFuGq6ctIpR52PplC0sEPUTVbDH
    LlDAQUIXzmmJGhD2etF5dpknbBTcAhUjGebCiasqwZ8HWiVUeIEwi89je7+CThjB
    3phSjyzqZivdkpYiZTApy3UU3lzXHViCtTIverkaQNoYExWVCKihvMRtSAlhw4b0
    ukEt+PNzrgl2N0M3bYh1oEh+TGqiP961Je38l5756wKLSxgzfTwTlrPmH6BFwhkF
    EnMxzjX4jvRWkVC2Yz4/DiJnRnAEjS3iOsvvDnP/lZkWZOXMT3TY0bRJSwUuEgCc
    NPF/PE/q6KRtzyxJLuTOFRwk/xob/q4GucD+RuqwHEC2w3fN7WE=
    =HK3G
    -----END PGP SIGNATURE-----

    Reply to:
    debian-security-announce@lists.debian.org
    Markus Koschany (on-list)
    Markus Koschany (off-list)

    Prev by Date:
    [SECURITY] [DSA 5663-1] firefox-esr security update

    Next by Date:
    [SECURITY] [DSA 5665-1] tomcat10 security update

    Previous by thread:
    [SECURITY] [DSA 5663-1] firefox-esr security update

    Next by thread:
    [SECURITY] [DSA 5665-1] tomcat10 security update

    Index(es):

    Date
    Thread

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/jetty9");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-22201");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/jetty9");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/jetty9");
  script_set_attribute(attribute:"solution", value:
"Upgrade the jetty9 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22201");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jetty9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjetty9-extra-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjetty9-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'jetty9', 'reference': '9.4.50-4+deb11u2'},
    {'release': '11.0', 'prefix': 'libjetty9-extra-java', 'reference': '9.4.50-4+deb11u2'},
    {'release': '11.0', 'prefix': 'libjetty9-java', 'reference': '9.4.50-4+deb11u2'},
    {'release': '12.0', 'prefix': 'jetty9', 'reference': '9.4.50-4+deb12u3'},
    {'release': '12.0', 'prefix': 'libjetty9-extra-java', 'reference': '9.4.50-4+deb12u3'},
    {'release': '12.0', 'prefix': 'libjetty9-java', 'reference': '9.4.50-4+deb12u3'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jetty9 / libjetty9-extra-java / libjetty9-java');
}
