#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3208. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168207);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2020-11653", "CVE-2022-45060");

  script_name(english:"Debian dla-3208 : libvarnishapi-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3208 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3208-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Markus Koschany
    November 27, 2022                             https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : varnish
    Version        : 6.1.1-1+deb10u4
    CVE ID         : CVE-2020-11653 CVE-2022-45060
    Debian Bug     : 956307 1023751

    Martin van Kervel Smedshammer discovered a request forgery attack can be
    performed on Varnish Cache servers that have the HTTP/2 protocol turned on. An
    attacker may introduce characters through the HTTP/2 pseudo-headers that are
    invalid in the context of an HTTP/1 request line, causing the Varnish server to
    produce invalid HTTP/1 requests to the backend. This may in turn be used to
    successfully exploit vulnerabilities in a server behind the Varnish server.

    For Debian 10 buster, these problems have been fixed in version
    6.1.1-1+deb10u4.

    We recommend that you upgrade your varnish packages.

    For the detailed security status of varnish please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/varnish

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/varnish");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11653");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45060");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/varnish");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libvarnishapi-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11653");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-45060");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvarnishapi-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvarnishapi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:varnish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:varnish-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'libvarnishapi-dev', 'reference': '6.1.1-1+deb10u4'},
    {'release': '10.0', 'prefix': 'libvarnishapi2', 'reference': '6.1.1-1+deb10u4'},
    {'release': '10.0', 'prefix': 'varnish', 'reference': '6.1.1-1+deb10u4'},
    {'release': '10.0', 'prefix': 'varnish-doc', 'reference': '6.1.1-1+deb10u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvarnishapi-dev / libvarnishapi2 / varnish / varnish-doc');
}
