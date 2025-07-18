#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3744. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(191437);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2021-28658",
    "CVE-2021-31542",
    "CVE-2021-33203",
    "CVE-2021-33571"
  );

  script_name(english:"Debian dla-3744 : python-django - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3744 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3744-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                           Chris Lamb
    February 29, 2024                             https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : python-django
    Version        : 1:1.11.29-1+deb10u11
    CVE IDs        : CVE-2021-28658 CVE-2021-31542 CVE-2021-33203 CVE-2021-33571
    Debian Bugs    : 986447 988053 989394

    It was discovered that there were a number of issues in Django, a
    popular Python-based web development framework:

     * CVE-2021-28658: Prevent a directory traversal issue which could
       have been exploited by maliciously crafted filenames. However, the
       built-in upload handlers were not affected by this vulnerability.
       (#986447)

     * CVE-2021-31542: Fix a potential directory-traversal vulnerability
       that could have been exploited by uploaded files. The
       MultiPartParser, UploadedFile and FieldFile classes allowed
       directory-traversal via uploaded files with suitably crafted file
       names. In order to mitigate this risk, stricter basename and path
       sanitation is now applied. Specifically, empty file names and
       paths with dot segments are rejected. (#988053)

     * CVE-2021-33203: Prevent a potential directory traversal via
       admindocs. Staff members could use the admindocs
       TemplateDetailView view to check the existence of arbitrary files.
       Additionally, if (and only if) the default admindocs templates
       have been customized by the developers to also expose the file
       contents, then not only the existence but also the file contents
       would have been exposed. As a mitigation, path sanitation is now
       applied and only files within the template root directories can be
       loaded. (#989394)

     * CVE-2021-33571: Prevent possible SSRF, RFI (Remote File Inclusion)
       and LFI (Local File Inclusion) attacks, since validators accepted
       leading zeros in IPv4 addresses URLValidator,
       validate_ipv4_address() and validate_ipv46_address() did not
       prohibit leading zeros in octal literals. (#989394)

    For Debian 10 buster, these problems have been fixed in version
    1:1.11.29-1+deb10u11.

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
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-28658");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31542");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33203");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-33571");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/python-django");
  script_set_attribute(attribute:"solution", value:
"Upgrade the python-django packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33571");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/29");

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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'python-django', 'reference': '1:1.11.29-1+deb10u11'},
    {'release': '10.0', 'prefix': 'python-django-common', 'reference': '1:1.11.29-1+deb10u11'},
    {'release': '10.0', 'prefix': 'python-django-doc', 'reference': '1:1.11.29-1+deb10u11'},
    {'release': '10.0', 'prefix': 'python3-django', 'reference': '1:1.11.29-1+deb10u11'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-django / python-django-common / python-django-doc / etc');
}
