#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3442. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(176658);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2021-32862");

  script_name(english:"Debian dla-3442 : jupyter-nbconvert - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3442
advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3442-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    June 03, 2023                                 https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : nbconvert
    Version        : 5.4-2+deb10u1
    CVE ID         : CVE-2021-32862

    Alvaro Muoz from the GitHub Security Lab discovered sixteen ways to
    exploit a cross-site scripting vulnerability in nbconvert, a tool and
    library used to convert notebooks to various other formats via Jinja
    templates.

    When using nbconvert to generate an HTML version of a user-controllable
    notebook, it is possible to inject arbitrary HTML which may lead to
    cross-site scripting (XSS) vulnerabilities if these HTML notebooks are
    served by a web server without tight Content-Security-Policy (e.g.,
    nbviewer).

      * GHSL-2021-1013: XSS in notebook.metadata.language_info.pygments_lexer;
      * GHSL-2021-1014: XSS in notebook.metadata.title;
      * GHSL-2021-1015: XSS in notebook.metadata.widgets;
      * GHSL-2021-1016: XSS in notebook.cell.metadata.tags;
      * GHSL-2021-1017: XSS in output data text/html cells;
      * GHSL-2021-1018: XSS in output data image/svg+xml cells;
      * GHSL-2021-1019: XSS in notebook.cell.output.svg_filename;
      * GHSL-2021-1020: XSS in output data text/markdown cells;
      * GHSL-2021-1021: XSS in output data application/javascript cells;
      * GHSL-2021-1022: XSS in output.metadata.filenames image/png and
        image/jpeg;
      * GHSL-2021-1023: XSS in output data image/png and image/jpeg cells;
      * GHSL-2021-1024: XSS in output.metadata.width/height image/png and
        image/jpeg;
      * GHSL-2021-1025: XSS in output data application/vnd.jupyter.widget-state+
        json cells;
      * GHSL-2021-1026: XSS in output data application/vnd.jupyter.widget-view+
        json cells;
      * GHSL-2021-1027: XSS in raw cells; and
      * GHSL-2021-1028: XSS in markdown cells.

    Some of these vulnerabilities, namely GHSL-2021-1017, -1020, -1021, and
    -1028, are actually design decisions where text/html, text/markdown,
    application/JavaScript and markdown cells should allow for arbitrary
    JavaScript code execution.  These vulnerabilities are therefore left open
    by default, but users can now opt-out and strip down all JavaScript
    elements via a new HTMLExporter option `sanitize_html`.

    For Debian 10 buster, this problem has been fixed in version
    5.4-2+deb10u1.

    We recommend that you upgrade your nbconvert packages.

    For the detailed security status of nbconvert please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/nbconvert

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/nbconvert");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32862");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/nbconvert");
  script_set_attribute(attribute:"solution", value:
"Upgrade the jupyter-nbconvert packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32862");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jupyter-nbconvert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-nbconvert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-nbconvert-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-nbconvert");
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
    {'release': '10.0', 'prefix': 'jupyter-nbconvert', 'reference': '5.4-2+deb10u1'},
    {'release': '10.0', 'prefix': 'python-nbconvert', 'reference': '5.4-2+deb10u1'},
    {'release': '10.0', 'prefix': 'python-nbconvert-doc', 'reference': '5.4-2+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-nbconvert', 'reference': '5.4-2+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jupyter-nbconvert / python-nbconvert / python-nbconvert-doc / etc');
}
