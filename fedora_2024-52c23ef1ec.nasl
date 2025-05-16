#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-52c23ef1ec
#

include('compat.inc');

if (description)
{
  script_id(200458);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id(
    "CVE-2012-1823",
    "CVE-2024-1874",
    "CVE-2024-2408",
    "CVE-2024-4577",
    "CVE-2024-5458",
    "CVE-2024-5585"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/07/03");
  script_xref(name:"IAVB", value:"2012-B-0054-S");
  script_xref(name:"FEDORA", value:"2024-52c23ef1ec");
  script_xref(name:"IAVA", value:"2024-A-0244-S");
  script_xref(name:"IAVA", value:"2024-A-0330-S");

  script_name(english:"Fedora 39 : php (2024-52c23ef1ec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 39 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2024-52c23ef1ec advisory.

    **PHP version 8.2.20** (06 Jun 2024)

    **CGI:**

    * Fixed buffer limit on Windows, replacing read call usage by _read. (David Carlier)
    * Fixed bug [GHSA-3qgc-jrrr-25jv](https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv)
    (Bypass of CVE-2012-1823, Argument Injection in PHP-CGI). (CVE-2024-4577) (nielsdos)

    **CLI:**

    * Fixed bug [GH-14189](https://github.com/php/php-src/issues/14189) (PHP Interactive shell input state
    incorrectly handles quoted heredoc literals.). (nielsdos)

    **Core:**

    * Fixed bug [GH-13970](https://github.com/php/php-src/issues/13970) (Incorrect validation of #[Attribute]
    flags type for non-compile-time expressions). (ilutov)
    * Fixed bug [GH-14140](https://github.com/php/php-src/issues/14140) (Floating point bug in range operation
    on Apple Silicon hardware). (Derick, Saki)

    **DOM:**

    * Fix crashes when entity declaration is removed while still having entity references. (nielsdos)
    * Fix references not handled correctly in C14N. (nielsdos)
    * Fix crash when calling childNodes next() when iterator is exhausted. (nielsdos)
    * Fix crash in ParentNode::append() when dealing with a fragment containing text nodes. (nielsdos)

    **FFI:**

    * Fixed bug [GH-14215](https://github.com/php/php-src/issues/14215) (Cannot use FFI::load on CRLF header
    file with apache2handler). (nielsdos)

    **Filter:**

    * Fixed bug [GHSA-w8qr-v226-r27w](https://github.com/php/php-src/security/advisories/GHSA-w8qr-v226-r27w)
    (Filter bypass in filter_var FILTER_VALIDATE_URL). (**CVE-2024-5458**) (nielsdos)

    **FPM:**

    * Fix bug [GH-14175](https://github.com/php/php-src/issues/14175) (Show decimal number instead of
    scientific notation in systemd status). (Benjamin Cremer)

    **Hash:**

    * ext/hash: Swap the checking order of `__has_builtin` and `__GNUC__` (Saki Takamachi)

    **Intl:**

    * Fixed build regression on systems without C++17 compilers. (Calvin Buckley, Peter Kokot)

    **Ini:**

    * Fixed bug [GH-14100](https://github.com/php/php-src/issues/14100) (Corrected spelling mistake in php.ini
    files). (Marcus Xavier)

    **MySQLnd:**

    * Fix bug [GH-14255](https://github.com/php/php-src/issues/14255) (mysqli_fetch_assoc reports error from
    nested query). (Kamil Tekiela)

    **Opcache:**

    * Fixed bug [GH-14109](https://github.com/php/php-src/issues/14109) (Fix accidental persisting of internal
    class constant in shm). (ilutov)

    **OpenSSL:**

    * The openssl_private_decrypt function in PHP, when using PKCS1 padding (OPENSSL_PKCS1_PADDING, which is
    the default), is vulnerable to the Marvin Attack unless it is used with an OpenSSL version that includes
    the changes from this pull request: https://github.com/openssl/openssl/pull/13817
    (rsa_pkcs1_implicit_rejection). These changes are part of OpenSSL 3.2 and have also been backported to
    stable versions of various Linux distributions, as well as to the PHP builds provided for Windows since
    the previous release. All distributors and builders should ensure that this version is used to prevent PHP
    from being vulnerable. (**CVE-2024-2408**)

    **Standard:**

    * Fixed bug [GHSA-9fcc-425m-g385](https://github.com/php/php-src/security/advisories/GHSA-9fcc-425m-g385)
    (Bypass of CVE-2024-1874). (CVE-2024-5585) (nielsdos)

    **XML:**

    * Fixed bug [GH-14124](https://github.com/php/php-src/issues/14124) (Segmentation fault with XML extension
    under certain memory limit). (nielsdos)

    **XMLReader:**

    * Fixed bug [GH-14183](https://github.com/php/php-src/issues/14183) (XMLReader::open() can't be
    overridden). (nielsdos)



Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-52c23ef1ec");
  script_set_attribute(attribute:"solution", value:
"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1823");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-4577");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP CGI Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^39([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 39', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'php-8.2.20-1.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php');
}
