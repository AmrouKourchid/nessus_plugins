#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3401. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(174709);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2023-25690", "CVE-2023-27522");
  script_xref(name:"IAVA", value:"2023-A-0124-S");

  script_name(english:"Debian dla-3401 : apache2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3401 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3401-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    April 24, 2023                                https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : apache2
    Version        : 2.4.38-3+deb10u10
    CVE ID         : CVE-2023-25690 CVE-2023-27522
    Debian Bug     : 1032476

    Several vulnerabilities have been discovered in apache2,
    a webserver that may be used as front-end proxy for other applications.
    These vulnerabilities may lead to HTTP request smuggling, and thus
    to front-end security controls being bypassed.

    Unfortunately, fixing these security vulnerabilities may require
    changes to configuration files. Some out-of-specification
    RewriteRule directives that were previously silently accepted,
    are now rejected with error AH10409. For instance, some RewriteRules
    that included a back-reference and the flags [L,NC] will need to
    be written with extra escaping flags such as [B= ?,BNP,QSA].

    CVE-2023-25690

      Some mod_proxy configurations allow an HTTP request Smuggling
      attack. Configurations are affected when mod_proxy is
      enabled along with some form of RewriteRule
      or ProxyPassMatch in which a non-specific pattern matches
      some portion of the user-supplied request-target (URL)
      data and is then re-inserted into the proxied request-target
      using variable substitution.

    CVE-2023-27522

        HTTP Response Smuggling in mod_proxy_uwsgi

    For Debian 10 buster, these problems have been fixed in version
    2.4.38-3+deb10u10.

    We recommend that you upgrade your apache2 packages.

    For the detailed security status of apache2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/apache2

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/apache2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-25690");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-27522");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/apache2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the apache2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25690");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '10.0', 'prefix': 'apache2', 'reference': '2.4.38-3+deb10u10'},
    {'release': '10.0', 'prefix': 'apache2-bin', 'reference': '2.4.38-3+deb10u10'},
    {'release': '10.0', 'prefix': 'apache2-data', 'reference': '2.4.38-3+deb10u10'},
    {'release': '10.0', 'prefix': 'apache2-dev', 'reference': '2.4.38-3+deb10u10'},
    {'release': '10.0', 'prefix': 'apache2-doc', 'reference': '2.4.38-3+deb10u10'},
    {'release': '10.0', 'prefix': 'apache2-ssl-dev', 'reference': '2.4.38-3+deb10u10'},
    {'release': '10.0', 'prefix': 'apache2-suexec-custom', 'reference': '2.4.38-3+deb10u10'},
    {'release': '10.0', 'prefix': 'apache2-suexec-pristine', 'reference': '2.4.38-3+deb10u10'},
    {'release': '10.0', 'prefix': 'apache2-utils', 'reference': '2.4.38-3+deb10u10'},
    {'release': '10.0', 'prefix': 'libapache2-mod-md', 'reference': '2.4.38-3+deb10u10'},
    {'release': '10.0', 'prefix': 'libapache2-mod-proxy-uwsgi', 'reference': '2.4.38-3+deb10u10'}
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
