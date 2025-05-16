#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2686-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(150806);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2018-20060",
    "CVE-2019-11236",
    "CVE-2019-11324",
    "CVE-2020-26137"
  );

  script_name(english:"Debian DLA-2686-1 : python-urllib3 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2686 advisory.

    Several vulnerabilities were discovered in python-urllib3, a HTTP client for Python. CVE-2018-20060
    Urllib3 does not remove the Authorization HTTP header when following a cross-origin redirect (i.e., a
    redirect that differs in host, port, or scheme). This can allow for credentials in the Authorization
    header to be exposed to unintended hosts or transmitted in cleartext. CVE-2019-11236 CRLF injection is
    possible if the attacker controls the request parameter. CVE-2019-11324 Urllib3 mishandles certain cases
    where the desired set of CA certificates is different from the OS store of CA certificates, which results
    in SSL connections succeeding in situations where a verification failure is the correct outcome. This is
    related to use of the ssl_context, ca_certs, or ca_certs_dir argument. CVE-2020-26137 Urllib3 allows CRLF
    injection if the attacker controls the HTTP request method, as demonstrated by inserting CR and LF control
    characters in the first argument of putrequest(). For Debian 9 stretch, these problems have been fixed in
    version 1.19.1-1+deb9u1. We recommend that you upgrade your python-urllib3 packages. For the detailed
    security status of python-urllib3 please refer to its security tracker page at: https://security-
    tracker.debian.org/tracker/python-urllib3 Further information about Debian LTS security advisories, how to
    apply these updates to your system and frequently asked questions can be found at:
    https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/python-urllib3");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-20060");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-11236");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-11324");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-26137");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2686");
  # https://security-tracker.debian.org/tracker/source-package/python-urllib3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb907009");
  script_set_attribute(attribute:"solution", value:
"Upgrade the python-urllib3 packages.

For Debian 9 stretch, these problems have been fixed in version 1.19.1-1+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26137");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-20060");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-urllib3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(9)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'python-urllib3', 'reference': '1.19.1-1+deb9u1'},
    {'release': '9.0', 'prefix': 'python3-urllib3', 'reference': '1.19.1-1+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-urllib3 / python3-urllib3');
}
