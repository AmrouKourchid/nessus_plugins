#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5281. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(167747);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2022-41741", "CVE-2022-41742");
  script_xref(name:"IAVA", value:"2022-A-0440-S");

  script_name(english:"Debian DSA-5281-1 : nginx - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5281 advisory.

    It was discovered that parsing errors in the mp4 module of Nginx, a high-performance web and reverse proxy
    server, could result in denial of service, memory disclosure or potentially the execution of arbitrary
    code when processing a malformed mp4 file. This module is only enabled in the nginx-extras binary package.
    For the stable distribution (bullseye), these problems have been fixed in version 1.18.0-6.1+deb11u3. We
    recommend that you upgrade your nginx packages. For the detailed security status of nginx please refer to
    its security tracker page at: https://security-tracker.debian.org/tracker/nginx

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/nginx");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5281");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41741");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41742");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/nginx");
  script_set_attribute(attribute:"solution", value:
"Upgrade the nginx packages.

For the stable distribution (bullseye), these problems have been fixed in version 1.18.0-6.1+deb11u3.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41741");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2022-41742");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/16");

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
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'libnginx-mod-http-auth-pam', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-cache-purge', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-dav-ext', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-echo', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-fancyindex', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-geoip', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-geoip2', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-headers-more-filter', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-image-filter', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-lua', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-ndk', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-perl', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-subs-filter', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-uploadprogress', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-upstream-fair', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-http-xslt-filter', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-mail', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-nchan', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-rtmp', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-stream', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-stream-geoip', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'libnginx-mod-stream-geoip2', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'nginx', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'nginx-common', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'nginx-core', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'nginx-doc', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'nginx-extras', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'nginx-full', 'reference': '1.18.0-6.1+deb11u3'},
    {'release': '11.0', 'prefix': 'nginx-light', 'reference': '1.18.0-6.1+deb11u3'}
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
