#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5845. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(214338);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id(
    "CVE-2024-34750",
    "CVE-2024-38286",
    "CVE-2024-50379",
    "CVE-2024-52316",
    "CVE-2024-54677",
    "CVE-2024-56337"
  );
  script_xref(name:"IAVA", value:"2024-A-0393-S");
  script_xref(name:"IAVA", value:"2024-A-0589-S");
  script_xref(name:"IAVA", value:"2024-A-0754-S");
  script_xref(name:"IAVA", value:"2024-A-0822-S");

  script_name(english:"Debian dsa-5845 : libtomcat10-embed-java - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5845 advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5845-1                   security@debian.org
    https://www.debian.org/security/                          Markus Koschany
    January 17, 2025                      https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : tomcat10
    CVE ID         : CVE-2024-34750 CVE-2024-38286 CVE-2024-50379 CVE-2024-52316
                     CVE-2024-54677 CVE-2024-56337

    Several problems have been addressed in Tomcat 10, a Java based web server,
    servlet and JSP engine which may lead to a denial-of-service.


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
        Tomcat. For Debian 12 bookworm the system property
        sun.io.useCanonCaches must be explicitly set to false (it defaults to
        false). Most Debian users will not be affected because Debian uses case
        sensitive file systems by default.

    CVE-2024-34750

        Improper Handling of Exceptional Conditions, Uncontrolled Resource
        Consumption vulnerability in Apache Tomcat. When processing an HTTP/2
        stream, Tomcat did not handle some cases of excessive HTTP headers
        correctly. This led to a miscounting of active HTTP/2 streams which in turn
        led to the use of an incorrect infinite timeout which allowed connections
        to remain open which should have been closed.

    CVE-2024-54677

        Uncontrolled Resource Consumption vulnerability in the examples web
        application provided with Apache Tomcat leads to denial of service.


    For the stable distribution (bookworm), these problems have been fixed in
    version 10.1.34-0+deb12u1.

    We recommend that you upgrade your tomcat10 packages.

    For the detailed security status of tomcat10 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/tomcat10

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/tomcat10");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-34750");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-38286");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50379");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-52316");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-54677");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56337");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/tomcat10");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/tomcat10");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libtomcat10-embed-java packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52316");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-38286");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat10-embed-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat10-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat10-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat10-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat10-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat10-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat10-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'libtomcat10-embed-java', 'reference': '10.1.34-0+deb12u1'},
    {'release': '12.0', 'prefix': 'libtomcat10-java', 'reference': '10.1.34-0+deb12u1'},
    {'release': '12.0', 'prefix': 'tomcat10', 'reference': '10.1.34-0+deb12u1'},
    {'release': '12.0', 'prefix': 'tomcat10-admin', 'reference': '10.1.34-0+deb12u1'},
    {'release': '12.0', 'prefix': 'tomcat10-common', 'reference': '10.1.34-0+deb12u1'},
    {'release': '12.0', 'prefix': 'tomcat10-docs', 'reference': '10.1.34-0+deb12u1'},
    {'release': '12.0', 'prefix': 'tomcat10-examples', 'reference': '10.1.34-0+deb12u1'},
    {'release': '12.0', 'prefix': 'tomcat10-user', 'reference': '10.1.34-0+deb12u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtomcat10-embed-java / libtomcat10-java / tomcat10 / tomcat10-admin / etc');
}
