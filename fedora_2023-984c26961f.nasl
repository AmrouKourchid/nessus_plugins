#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-984c26961f
#

include('compat.inc');

if (description)
{
  script_id(179716);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id("CVE-2023-3823", "CVE-2023-3824");
  script_xref(name:"FEDORA", value:"2023-984c26961f");
  script_xref(name:"IAVA", value:"2023-A-0423-S");

  script_name(english:"Fedora 38 : php (2023-984c26961f)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-984c26961f advisory.

    **PHP version 8.2.9** (03 Aug 2023)

    **Build:**

    * Fixed bug [GH-11522](https://github.com/php/php-src/issues/11522) (PHP version check fails with '-'
    separator). (SVGAnimate)

    **CLI:**

    * Fix interrupted CLI output causing the process to exit. (nielsdos)

    **Core:**

    * Fixed oss-fuzz php#60011 (Mis-compilation of by-reference nullsafe operator). (ilutov)
    * Fixed line number of JMP instruction over else block. (ilutov)
    * Fixed use-of-uninitialized-value with ??= on assert. (ilutov)
    * Fixed oss-fuzz php#60411 (Fix double-compilation of arrow-functions). (ilutov)
    * Fixed build for FreeBSD before the 11.0 releases. (David Carlier)

    **Curl:**

    * Fix crash when an invalid callback function is passed to CURLMOPT_PUSHFUNCTION. (nielsdos)

    **Date:**

    * Fixed bug [GH-11368](https://github.com/php/php-src/issues/11368) (Date modify returns invalid
    datetime). (Derick)
    * Fixed bug [GH-11600](https://github.com/php/php-src/issues/11600) (Can't parse time strings which
    include (narrow) non-breaking space characters). (Derick)
    * Fixed bug [GH-11854](https://github.com/php/php-src/issues/11854) (DateTime:createFromFormat stopped
    parsing datetime with extra space). (nielsdos, Derick)

    **DOM:**

    * Fixed bug [GH-11625](https://github.com/php/php-src/issues/11625) (DOMElement::replaceWith() doesn't
    replace node with DOMDocumentFragment but just deletes node or causes wrapping <></> depending on libxml2
    version). (nielsdos)

    **Fileinfo:**

    * Fixed bug [GH-11298](https://github.com/php/php-src/issues/11298) (finfo returns wrong mime type for xz
    files). (Anatol)

    **FTP:**

    * Fix context option check for overwrite. (JonasQuinten)
    * Fixed bug [GH-10562](https://github.com/php/php-src/issues/10562) (Memory leak and invalid state with
    consecutive ftp_nb_fget). (nielsdos)

    **GD:**

    * Fix most of the external libgd test failures. (Michael Orlitzky)

    **Intl:**

    * Fix memory leak in MessageFormatter::format() on failure. (Girgias)

    **Libxml:**

    * Fixed bug [GHSA-3qrf-m4j2-pcrr](https://github.com/php/php-src/security/advisories/GHSA-3qrf-m4j2-pcrr)
    (Security issue with external entity loading in XML without enabling it). (**CVE-2023-3823**) (nielsdos,
    ilutov)

    **MBString:**

    * Fix [GH-11300](https://github.com/php/php-src/issues/11300) (license issue: restricted unicode license
    headers). (nielsdos)

    **Opcache:**

    * Fixed bug [GH-10914](https://github.com/php/php-src/issues/10914) (OPCache with Enum and Callback
    functions results in segmentation fault). (nielsdos)
    * Prevent potential deadlock if accelerated globals cannot be allocated. (nielsdos)

    **PCNTL:**

    * Fixed bug [GH-11498](https://github.com/php/php-src/issues/11498) (SIGCHLD is not always returned from
    proc_open). (nielsdos)

    **PDO:**

    * Fix   [GH-11587](https://github.com/php/php-src/issues/11587) (After php8.1, when
    PDO::ATTR_EMULATE_PREPARES is true and PDO::ATTR_STRINGIFY_FETCHES is true, decimal zeros are no longer
    filled). (SakiTakamachi)

    **PDO SQLite:**

    * Fix [GH-11492](https://github.com/php/php-src/issues/11492) (Make test failure:
    ext/pdo_sqlite/tests/bug_42589.phpt). (KapitanOczywisty, CViniciusSDias)

    **Phar:**

    * Add missing check on EVP_VerifyUpdate() in phar util. (nielsdos)
    * Fixed bug [GHSA-jqcx-ccgc-xwhv](https://github.com/php/php-src/security/advisories/GHSA-jqcx-ccgc-xwhv)
    (Buffer mismanagement in phar_dir_read()). (**CVE-2023-3824**) (nielsdos)

    **PHPDBG:**

    * Fixed bug [GH-9669](https://github.com/php/php-src/issues/9669) (phpdbg -h options doesn't list the -z
    option). (adsr)

    **Session:**

    * Removed broken url support for transferring session ID. (ilutov)

    **Standard:**

    * Fix serialization of RC1 objects appearing in object graph twice. (ilutov) **Streams:**

    * Fixed bug [GH-11735](https://github.com/php/php-src/issues/11735) (Use-after-free when unregistering
    user stream wrapper from itself). (ilutov)

    **SQLite3:**

    * Fix replaced error handling in SQLite3Stmt::__construct. (nielsdos)

    **XMLReader:**

    * Fix [GH-11548](https://github.com/php/php-src/issues/11548) (Argument corruption when calling
    XMLReader::open or XMLReader::XML non-statically with observer active). (Bob)



Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-984c26961f");
  script_set_attribute(attribute:"solution", value:
"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3824");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'php-8.2.9-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE}
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
