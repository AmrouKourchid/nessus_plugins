#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2815. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155123);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2020-28243",
    "CVE-2020-28972",
    "CVE-2020-35662",
    "CVE-2021-3144",
    "CVE-2021-3148",
    "CVE-2021-3197",
    "CVE-2021-25281",
    "CVE-2021-25282",
    "CVE-2021-25283",
    "CVE-2021-25284",
    "CVE-2021-31607"
  );
  script_xref(name:"IAVA", value:"2021-A-0112-S");
  script_xref(name:"IAVA", value:"2021-A-0524-S");

  script_name(english:"Debian DLA-2815-1 : salt - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2815 advisory.

    Multiple security vulnerabilities have been discovered in Salt, a powerful remote execution manager, that
    allow for local privilege escalation on a minion, server side template injection attacks, insufficient
    checks for eauth credentials, shell and command injections or incorrect validation of SSL certificates.
    For Debian 9 stretch, these problems have been fixed in version 2016.11.2+ds-1+deb9u7. We recommend that
    you upgrade your salt packages. For the detailed security status of salt please refer to its security
    tracker page at: https://security-tracker.debian.org/tracker/salt Further information about Debian LTS
    security advisories, how to apply these updates to your system and frequently asked questions can be found
    at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=987496");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/salt");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2815");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-28243");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-28972");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-35662");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-25281");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-25282");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-25283");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-25284");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3144");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3148");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31607");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3197");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/salt");
  script_set_attribute(attribute:"solution", value:
"Upgrade the salt packages.

For Debian 9 stretch, these problems have been fixed in version 2016.11.2+ds-1+deb9u7.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3197");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt API Unauthenticated RCE through wheel_async client');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-syndic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'release': '9.0', 'prefix': 'salt-api', 'reference': '2016.11.2+ds-1+deb9u7'},
    {'release': '9.0', 'prefix': 'salt-cloud', 'reference': '2016.11.2+ds-1+deb9u7'},
    {'release': '9.0', 'prefix': 'salt-common', 'reference': '2016.11.2+ds-1+deb9u7'},
    {'release': '9.0', 'prefix': 'salt-doc', 'reference': '2016.11.2+ds-1+deb9u7'},
    {'release': '9.0', 'prefix': 'salt-master', 'reference': '2016.11.2+ds-1+deb9u7'},
    {'release': '9.0', 'prefix': 'salt-minion', 'reference': '2016.11.2+ds-1+deb9u7'},
    {'release': '9.0', 'prefix': 'salt-proxy', 'reference': '2016.11.2+ds-1+deb9u7'},
    {'release': '9.0', 'prefix': 'salt-ssh', 'reference': '2016.11.2+ds-1+deb9u7'},
    {'release': '9.0', 'prefix': 'salt-syndic', 'reference': '2016.11.2+ds-1+deb9u7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'salt-api / salt-cloud / salt-common / salt-doc / salt-master / etc');
}
