#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5290. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168228);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/20");

  script_cve_id("CVE-2022-33980");

  script_name(english:"Debian DSA-5290-1 : commons-configuration2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5290
advisory.

  - Apache Commons Configuration performs variable interpolation, allowing properties to be dynamically
    evaluated and expanded. The standard format for interpolation is ${prefix:name}, where prefix is used
    to locate an instance of org.apache.commons.configuration2.interpol.Lookup that performs the
    interpolation. Starting with version 2.4 and continuing through 2.7, the set of default Lookup instances
    included interpolators that could result in arbitrary code execution or contact with remote servers. These
    lookups are: - script - execute expressions using the JVM script execution engine (javax.script) - dns
    - resolve dns records - url - load values from urls, including from remote servers Applications using
    the interpolation defaults in the affected versions may be vulnerable to remote code execution or
    unintentional contact with remote servers if untrusted configuration values are used. Users are
    recommended to upgrade to Apache Commons Configuration 2.8.0, which disables the problematic interpolators
    by default. (CVE-2022-33980)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1014960");
  # https://security-tracker.debian.org/tracker/source-package/commons-configuration2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8d47290");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5290");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33980");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/commons-configuration2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the commons-configuration2 packages.

For the stable distribution (bullseye), this problem has been fixed in version 2.8.0-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-33980");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcommons-configuration2-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcommons-configuration2-java-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '11.0', 'prefix': 'libcommons-configuration2-java', 'reference': '2.8.0-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libcommons-configuration2-java-doc', 'reference': '2.8.0-1~deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcommons-configuration2-java / libcommons-configuration2-java-doc');
}
