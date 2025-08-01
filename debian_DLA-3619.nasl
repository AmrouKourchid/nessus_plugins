#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3619. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(183091);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2020-11987",
    "CVE-2022-38398",
    "CVE-2022-38648",
    "CVE-2022-40146",
    "CVE-2022-44729",
    "CVE-2022-44730"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian dla-3619 : libbatik-java - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3619 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3619-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    October 14, 2023                              https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : batik
    Version        : 1.10-2+deb10u3
    CVE ID         : CVE-2020-11987 CVE-2022-38398 CVE-2022-38648 CVE-2022-40146
                     CVE-2022-44729 CVE-2022-44730
    Debian Bug     : 984829 1020589

    Batik is a toolkit for applications or applets that want to use images
    in the Scalable Vector Graphics (SVG) format for various purposes,
    such as viewing, generation or manipulation.

    CVE-2020-11987

        A server-side request forgery was found,
        caused by improper input validation by the NodePickerPanel.
        By using a specially-crafted argument, an attacker could exploit
        this vulnerability to cause the underlying server to make
        arbitrary GET requests.

    CVE-2022-38398

        A Server-Side Request Forgery (SSRF) vulnerability
        was found that allows an attacker to load a url thru the jar
        protocol.

    CVE-2022-38648

        A Server-Side Request Forgery (SSRF) vulnerability
        was found that allows an attacker to fetch external resources.

    CVE-2022-40146

        A Server-Side Request Forgery (SSRF) vulnerability
        was found that allows an attacker to access files using a Jar url.

    CVE-2022-44729

        A Server-Side Request Forgery (SSRF) vulnerability
        was found. A malicious SVG could trigger loading external resources
        by default, causing resource consumption or in some
        cases even information disclosure.

    CVE-2022-44730

        A Server-Side Request Forgery (SSRF) vulnerability
        was found. A malicious SVG can probe user profile / data and send
        it directly as parameter to a URL.

    For Debian 10 buster, these problems have been fixed in version
    1.10-2+deb10u3.

    We recommend that you upgrade your batik packages.

    For the detailed security status of batik please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/batik

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/batik");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11987");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38398");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-38648");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-40146");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-44729");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-44730");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/batik");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libbatik-java packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11987");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbatik-java");
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
    {'release': '10.0', 'prefix': 'libbatik-java', 'reference': '1.10-2+deb10u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libbatik-java');
}
