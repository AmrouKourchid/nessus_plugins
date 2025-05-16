#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5662. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(193369);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/12");

  script_cve_id(
    "CVE-2023-31122",
    "CVE-2023-38709",
    "CVE-2023-43622",
    "CVE-2023-45802",
    "CVE-2024-24795",
    "CVE-2024-27316"
  );
  script_xref(name:"IAVA", value:"2023-A-0572-S");
  script_xref(name:"IAVA", value:"2024-A-0202-S");

  script_name(english:"Debian dsa-5662 : apache2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5662 advisory.

  - Out-of-bounds Read vulnerability in mod_macro of Apache HTTP Server.This issue affects Apache HTTP Server:
    through 2.4.57. (CVE-2023-31122)

  - Faulty input validation in the core of Apache allows malicious or exploitable backend/content generators
    to split HTTP responses. This issue affects Apache HTTP Server: through 2.4.58. (CVE-2023-38709)

  - An attacker, opening a HTTP/2 connection with an initial window size of 0, was able to block handling of
    that connection indefinitely in Apache HTTP Server. This could be used to exhaust worker resources in the
    server, similar to the well known slow loris attack pattern. This has been fixed in version 2.4.58, so
    that such connection are terminated properly after the configured connection timeout. This issue affects
    Apache HTTP Server: from 2.4.55 through 2.4.57. Users are recommended to upgrade to version 2.4.58, which
    fixes the issue. (CVE-2023-43622)

  - When a HTTP/2 stream was reset (RST frame) by a client, there was a time window were the request's memory
    resources were not reclaimed immediately. Instead, de-allocation was deferred to connection close. A
    client could send new requests and resets, keeping the connection busy and open and causing the memory
    footprint to keep on growing. On connection close, all resources were reclaimed, but the process might run
    out of memory before that. This was found by the reporter during testing of CVE-2023-44487 (HTTP/2 Rapid
    Reset Exploit) with their own test client. During normal HTTP/2 use, the probability to hit this bug is
    very low. The kept memory would not become noticeable before the connection closes or times out. Users are
    recommended to upgrade to version 2.4.58, which fixes the issue. (CVE-2023-45802)

  - HTTP Response splitting in multiple modules in Apache HTTP Server allows an attacker that can inject
    malicious response headers into backend applications to cause an HTTP desynchronization attack. Users are
    recommended to upgrade to version 2.4.59, which fixes this issue. (CVE-2024-24795)

  - HTTP/2 incoming headers exceeding the limit are temporarily buffered in nghttp2 in order to generate an
    informative HTTP 413 response. If a client does not stop sending headers, this leads to memory exhaustion.
    (CVE-2024-27316)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/apache2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-31122");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38709");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-43622");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45802");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-24795");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-27316");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/apache2");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/apache2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the apache2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27316");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-ssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-custom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-suexec-pristine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-proxy-uwsgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'apache2', 'reference': '2.4.59-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-bin', 'reference': '2.4.59-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-data', 'reference': '2.4.59-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-dev', 'reference': '2.4.59-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-doc', 'reference': '2.4.59-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-ssl-dev', 'reference': '2.4.59-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-suexec-custom', 'reference': '2.4.59-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-suexec-pristine', 'reference': '2.4.59-1~deb11u1'},
    {'release': '11.0', 'prefix': 'apache2-utils', 'reference': '2.4.59-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libapache2-mod-md', 'reference': '2.4.59-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libapache2-mod-proxy-uwsgi', 'reference': '2.4.59-1~deb11u1'},
    {'release': '12.0', 'prefix': 'apache2', 'reference': '2.4.59-1~deb12u1'},
    {'release': '12.0', 'prefix': 'apache2-bin', 'reference': '2.4.59-1~deb12u1'},
    {'release': '12.0', 'prefix': 'apache2-data', 'reference': '2.4.59-1~deb12u1'},
    {'release': '12.0', 'prefix': 'apache2-dev', 'reference': '2.4.59-1~deb12u1'},
    {'release': '12.0', 'prefix': 'apache2-doc', 'reference': '2.4.59-1~deb12u1'},
    {'release': '12.0', 'prefix': 'apache2-ssl-dev', 'reference': '2.4.59-1~deb12u1'},
    {'release': '12.0', 'prefix': 'apache2-suexec-custom', 'reference': '2.4.59-1~deb12u1'},
    {'release': '12.0', 'prefix': 'apache2-suexec-pristine', 'reference': '2.4.59-1~deb12u1'},
    {'release': '12.0', 'prefix': 'apache2-utils', 'reference': '2.4.59-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libapache2-mod-md', 'reference': '2.4.59-1~deb12u1'},
    {'release': '12.0', 'prefix': 'libapache2-mod-proxy-uwsgi', 'reference': '2.4.59-1~deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2 / apache2-bin / apache2-data / apache2-dev / apache2-doc / etc');
}
