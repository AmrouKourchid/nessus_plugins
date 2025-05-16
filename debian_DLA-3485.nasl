#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3485. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(178052);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2022-39369");

  script_name(english:"Debian dla-3485 : php-cas - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by a vulnerability as referenced in the dla-3485
advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3485-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Tobias Frost
    July 08, 2023                                 https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : php-cas
    Version        : 1.3.6-1+deb10u1
    CVE ID         : CVE-2022-39369
    Debian Bug     : 1023571

    A vulnerability has been found in phpCAS, a Central Authentication
    Service client library in php, which may allow an attacker to gain
    access to a victim's account on a vulnerable CASified service without
    victim's knowledge, when the victim visits attacker's website while
    being logged in to the same CAS server.

    The fix for this vulnerabilty requires an API breaking change in php-cas
    and will require that software using the library be updated.

    For buster, all packages in the Debian repositories which are using
    php-cas have been updated, though additional manual configuration is to
    be expected, as php-cas needs additional site information -- the service
    base URL -- for it to function. The DLAs for the respective packages
    will have additional information, as well as the package's NEWS files.

    For 3rd party software using php-cas, please be note that upstream
    provided following instructions how to update this software [1]:

    phpCAS now requires an additional service base URL argument when constructing
    the client class. It accepts any argument of:

    1. A service base URL string. The service URL discovery will always use this
       server name (protocol, hostname and port number) without using any external
       host names.
    2. An array of service base URL strings. The service URL discovery will check
       against this list before using the auto discovered base URL. If there is no
       match, the first base URL in the array will be used as the default. This
       option is helpful if your PHP website is accessible through multiple domains
       without a canonical name, or through both HTTP and HTTPS.
    3. A class that implements CAS_ServiceBaseUrl_Interface. If you need to
       customize the base URL discovery behavior, you can pass in a class that
       implements the interface.

    Constructing the client class is usually done with phpCAS::client().

    For example, using the first possiblity:
      phpCAS::client(CAS_VERSION_2_0, $cas_host, $cas_port, $cas_context);
    could become:
      phpCAS::client(CAS_VERSION_2_0, $cas_host, $cas_port, $cas_context, https://casified-
    service.example.org:8080);


    Details of the vulnerability:

    CVE-2022-39369

        The phpCAS library uses HTTP headers to determine the service URL used
        to validate tickets. This allows an attacker to control the host header
        and use a valid ticket granted for any authorized service in the same
        SSO realm (CAS server) to authenticate to the service protected by
        phpCAS.  Depending on the settings of the CAS server service registry in
        worst case this may be any other service URL (if the allowed URLs are
        configured to ^(https)://.*) or may be strictly limited to known and
        authorized services in the same SSO federation if proper URL service
        validation is applied.

    [1]
    https://github.com/apereo/phpCAS/blob/f3db27efd1f5020e71f2116f637a25cc9dbda1e3/docs/Upgrading#L1C1-L1C1

    For Debian 10 buster, this problem has been fixed in version
    1.3.6-1+deb10u1.

    We recommend that you upgrade your php-cas packages.

    For the detailed security status of php-cas please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/php-cas

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/php-cas");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39369");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/php-cas");
  script_set_attribute(attribute:"solution", value:
"Upgrade the php-cas packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39369");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-cas");
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
    {'release': '10.0', 'prefix': 'php-cas', 'reference': '1.3.6-1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php-cas');
}
