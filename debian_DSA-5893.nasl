#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5893. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(233874);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2025-24813");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/04/22");
  script_xref(name:"IAVA", value:"2025-A-0156");

  script_name(english:"Debian dsa-5893 : libtomcat10-embed-java - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5893
advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5893-1                   security@debian.org
    https://www.debian.org/security/                          Markus Koschany
    April 05, 2025                        https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : tomcat10
    CVE ID         : CVE-2025-24813

    A security vulnerability was found in Tomcat 10, a Java based web server and
    servlet engine. A malicious user was able to view security sensitive files
    and/or inject content into those files when writes were enabled for the default
    servlet (disabled by default) and support for partial PUT was enabled
    (default). Under certain circumstances, depending on the application in use,
    remote code execution may have been possible.

    For the stable distribution (bookworm), this problem has been fixed in
    version 10.1.34-0+deb12u2.

    We recommend that you upgrade your tomcat10 packages.

    For the detailed security status of tomcat10 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/tomcat10

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/tomcat10");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-24813");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/tomcat10");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libtomcat10-embed-java packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24813");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/04");

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
    {'release': '12.0', 'prefix': 'libtomcat10-embed-java', 'reference': '10.1.34-0+deb12u2'},
    {'release': '12.0', 'prefix': 'libtomcat10-java', 'reference': '10.1.34-0+deb12u2'},
    {'release': '12.0', 'prefix': 'tomcat10', 'reference': '10.1.34-0+deb12u2'},
    {'release': '12.0', 'prefix': 'tomcat10-admin', 'reference': '10.1.34-0+deb12u2'},
    {'release': '12.0', 'prefix': 'tomcat10-common', 'reference': '10.1.34-0+deb12u2'},
    {'release': '12.0', 'prefix': 'tomcat10-docs', 'reference': '10.1.34-0+deb12u2'},
    {'release': '12.0', 'prefix': 'tomcat10-examples', 'reference': '10.1.34-0+deb12u2'},
    {'release': '12.0', 'prefix': 'tomcat10-user', 'reference': '10.1.34-0+deb12u2'}
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
