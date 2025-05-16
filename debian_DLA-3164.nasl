#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3164. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(166698);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2020-24583",
    "CVE-2020-24584",
    "CVE-2021-3281",
    "CVE-2021-23336",
    "CVE-2022-34265"
  );

  script_name(english:"Debian dla-3164 : python-django - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3164 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3164-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                           Chris Lamb
    October 28, 2022                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : python-django
    Version        : 1:1.11.29-1+deb10u2
    CVE IDs        : CVE-2020-24583 CVE-2020-24584 CVE-2021-3281
                     CVE-2021-23336 CVE-2022-34265
    Debian Bugs    : 969367 981562 983090 1014541

    Multiple vulnerabilities were discovered in Django, a popular
    Python-based web development framework:

     * CVE-2020-24583: Fix incorrect permissions on intermediate-level
       directories on Python 3.7+. FILE_UPLOAD_DIRECTORY_PERMISSIONS mode
       was not applied to intermediate-level directories created in the
       process of uploading files and to intermediate-level collected
       static directories when using the collectstatic management
       command. You should review and manually fix permissions on
       existing intermediate-level directories.

     * CVE-2020-24584: Correct permission escalation vulnerability in
       intermediate-level directories of the file system cache. On Python
       3.7 and above, the intermediate-level directories of the file
       system cache had the system's standard umask rather than 0o077 (no
       group or others permissions).

     * CVE-2021-3281: Fix a potential directory-traversal exploit via
       archive.extract(). The django.utils.archive.extract() function,
       used by startapp --template and startproject --template, allowed
       directory traversal via an archive with absolute paths or relative
       paths with dot segments.

     * CVE-2021-23336: Prevent a web cache poisoning attack via parameter
       cloaking. Django contains a copy of urllib.parse.parse_qsl()
       which was added to backport some security fixes. A further
       security fix has been issued recently such that parse_qsl() no
       longer allows using ; as a query parameter separator by default.

     * CVE-2022-34265: The Trunc() and Extract() database functions were
       subject to a potential SQL injection attach if untrusted data was
       used as a value for the kind or lookup_name parameters.
       Applications that constrain the choice to a known safe list were
       unaffected.

    For Debian 10 buster, these problems have been fixed in version
    1:1.11.29-1+deb10u2.

    We recommend that you upgrade your python-django packages.

    For the detailed security status of python-django please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/python-django

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/python-django
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22eb32f6");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-24583");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-24584");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23336");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3281");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-34265");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/python-django");
  script_set_attribute(attribute:"solution", value:
"Upgrade the python-django packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34265");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-django");
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
    {'release': '10.0', 'prefix': 'python-django', 'reference': '1:1.11.29-1+deb10u2'},
    {'release': '10.0', 'prefix': 'python-django-common', 'reference': '1:1.11.29-1+deb10u2'},
    {'release': '10.0', 'prefix': 'python-django-doc', 'reference': '1:1.11.29-1+deb10u2'},
    {'release': '10.0', 'prefix': 'python3-django', 'reference': '1:1.11.29-1+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-django / python-django-common / python-django-doc / etc');
}
