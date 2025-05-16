#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4091. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(233322);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/25");

  script_cve_id("CVE-2024-7347", "CVE-2025-23419");
  script_xref(name:"IAVA", value:"2025-A-0086");

  script_name(english:"Debian dla-4091 : libnginx-mod-http-auth-pam - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4091 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4091-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Andrej Shadura
    March 25, 2025                                https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : nginx
    Version        : 1.18.0-6.1+deb11u4
    CVE ID         : CVE-2024-7347 CVE-2025-23419

    This upload fixes two security issues in the version of nginx shipped
    in bullseye.

    CVE-2024-7347

        Nginx has a vulnerability in the ngx_http_mp4_module, which might
        allow an attacker to over-read nginx worker memory resulting in
        its termination using a specially crafted mp4 file. The issue only
        affects nginx if it is built with the ngx_http_mp4_module and the
        mp4 directive is used in the configuration file. Additionally, the
        attack is possible only if an attacker can trigger the processing
        of a specially crafted mp4 file with the ngx_http_mp4_module.

    CVE-2025-23419

        When multiple server blocks are configured to share the same
        IP address and port, an attacker can use session resumption
        to bypass client certificate authentication requirements on
        these servers. This vulnerability arises when TLS Session Tickets
        are used and/or the SSL session cache
        are used in the default server and the default server is performing
        client certificate authentication.
        This issue did not affect ngx_stream_ssl_module in bullseye since
        the stream virtual servers funcionality was added in a later
        release.

    For Debian 11 bullseye, these problems have been fixed in version
    1.18.0-6.1+deb11u4.

    We recommend that you upgrade your nginx packages.

    For the detailed security status of nginx please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/nginx

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/nginx");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-7347");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-23419");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/nginx");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libnginx-mod-http-auth-pam packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7347");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-auth-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-cache-purge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-dav-ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-echo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-fancyindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-geoip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-headers-more-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-image-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-ndk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-subs-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-uploadprogress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-upstream-fair");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-http-xslt-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-nchan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-rtmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-stream-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnginx-mod-stream-geoip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-full");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nginx-light");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libnginx-mod-http-auth-pam', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-cache-purge', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-dav-ext', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-echo', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-fancyindex', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-geoip', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-geoip2', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-headers-more-filter', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-image-filter', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-lua', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-ndk', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-perl', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-subs-filter', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-uploadprogress', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-upstream-fair', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-xslt-filter', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-mail', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-nchan', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-rtmp', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-stream', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-stream-geoip', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'libnginx-mod-stream-geoip2', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'nginx', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'nginx-common', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'nginx-core', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'nginx-doc', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'nginx-extras', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'nginx-full', 'reference': '1.18.0-6.1+deb11u4'},
    {'release': '11.0', 'prefix': 'nginx-light', 'reference': '1.18.0-6.1+deb11u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnginx-mod-http-auth-pam / libnginx-mod-http-cache-purge / etc');
}
