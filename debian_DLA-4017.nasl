#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4017. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(214321);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id(
    "CVE-2024-21733",
    "CVE-2024-38286",
    "CVE-2024-50379",
    "CVE-2024-52316",
    "CVE-2024-56337"
  );
  script_xref(name:"IAVA", value:"2023-A-0661-S");
  script_xref(name:"IAVA", value:"2024-A-0589-S");
  script_xref(name:"IAVA", value:"2024-A-0754-S");
  script_xref(name:"IAVA", value:"2024-A-0822-S");

  script_name(english:"Debian dla-4017 : libtomcat9-embed-java - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4017 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4017-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Markus Koschany
    January 17, 2025                              https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : tomcat9
    Version        : 9.0.43-2~deb11u11
    CVE ID         : CVE-2024-21733 CVE-2024-38286 CVE-2024-50379 CVE-2024-52316
                     CVE-2024-56337

    Several problems have been addressed in Tomcat 9, a Java based web server,
    servlet and JSP engine which may lead to a denial-of-service or the disclosure
    of sensitive information.

    CVE-2024-21733

        Generation of Error Message Containing Sensitive Information vulnerability
        in Apache Tomcat.

    CVE-2024-38286

        Apache Tomcat, under certain configurations, allows an attacker to cause an
        OutOfMemoryError by abusing the TLS handshake process.

    CVE-2024-52316

        Unchecked Error Condition vulnerability in Apache Tomcat. If Tomcat is
        configured to use a custom Jakarta Authentication (formerly JASPIC)
        ServerAuthContext component which may throw an exception during the
        authentication process without explicitly setting an HTTP status to
        indicate failure, the authentication may not fail, allowing the user to
        bypass the authentication process. There are no known Jakarta
        Authentication components that behave in this way.

    CVE-2024-50379 / CVE-2024-56337

        Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability during JSP
        compilation in Apache Tomcat permits an RCE on case insensitive file
        systems when the default servlet is enabled for write (non-default
        configuration).
        Some users may need additional configuration to fully mitigate
        CVE-2024-50379 depending on which version of Java they are using with
        Tomcat. For Debian 11 bullseye the system property
        sun.io.useCanonCaches must be explicitly set to false (it defaults to
        true). Most Debian users will not be affected because Debian uses case
        sensitive file systems by default.

    For Debian 11 bullseye, these problems have been fixed in version
    9.0.43-2~deb11u11.

    We recommend that you upgrade your tomcat9 packages.

    For the detailed security status of tomcat9 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/tomcat9

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/tomcat9");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-21733");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38286");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50379");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-52316");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56337");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/tomcat9");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/tomcat9");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libtomcat9-embed-java packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21733");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat9-embed-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat9-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat9-user");
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
    {'release': '11.0', 'prefix': 'libtomcat9-embed-java', 'reference': '9.0.43-2~deb11u11'},
    {'release': '11.0', 'prefix': 'libtomcat9-java', 'reference': '9.0.43-2~deb11u11'},
    {'release': '11.0', 'prefix': 'tomcat9', 'reference': '9.0.43-2~deb11u11'},
    {'release': '11.0', 'prefix': 'tomcat9-admin', 'reference': '9.0.43-2~deb11u11'},
    {'release': '11.0', 'prefix': 'tomcat9-common', 'reference': '9.0.43-2~deb11u11'},
    {'release': '11.0', 'prefix': 'tomcat9-docs', 'reference': '9.0.43-2~deb11u11'},
    {'release': '11.0', 'prefix': 'tomcat9-examples', 'reference': '9.0.43-2~deb11u11'},
    {'release': '11.0', 'prefix': 'tomcat9-user', 'reference': '9.0.43-2~deb11u11'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtomcat9-embed-java / libtomcat9-java / tomcat9 / tomcat9-admin / etc');
}
