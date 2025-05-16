#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4130. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(234692);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/21");

  script_cve_id("CVE-2023-4641", "CVE-2023-29383");

  script_name(english:"Debian dla-4130 : login - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4130 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4130-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Sylvain Beucler
    April 18, 2025                                https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : shadow
    Version        : 1:4.8.1-1+deb11u1
    CVE ID         : CVE-2023-4641 CVE-2023-29383
    Debian Bug     : 1034482 1051062

    Several vulnerabilities were discovered in the shadow suite of login
    tools. An attacker may extract a password from memory in limited
    situations, and confuse an administrator inspecting /etc/passwd from
    within a terminal.

    CVE-2023-4641

        When asking for a new password, shadow-utils asks the password
        twice. If the password fails on the second attempt, shadow-utils
        fails in cleaning the buffer used to store the first entry. This
        may allow an attacker with enough access to retrieve the password
        from the memory.

    CVE-2023-29383

        It is possible to inject control characters into fields provided
        to the SUID program chfn (change finger). Although it is not
        possible to exploit this directly (e.g., adding a new user fails
        because \n is in the block list), it is possible to misrepresent
        the /etc/passwd file when viewed.

    For Debian 11 bullseye, these problems have been fixed in version
    1:4.8.1-1+deb11u1.

    We recommend that you upgrade your shadow packages.

    For the detailed security status of shadow please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/shadow

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/shadow");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-29383");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-4641");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/shadow");
  script_set_attribute(attribute:"solution", value:
"Upgrade the login packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4641");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:login");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:passwd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uidmap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'release': '11.0', 'prefix': 'login', 'reference': '1:4.8.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'passwd', 'reference': '1:4.8.1-1+deb11u1'},
    {'release': '11.0', 'prefix': 'uidmap', 'reference': '1:4.8.1-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'login / passwd / uidmap');
}
