#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-e0d390d35b
#

include('compat.inc');

if (description)
{
  script_id(211950);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id(
    "CVE-2024-8929",
    "CVE-2024-8932",
    "CVE-2024-11233",
    "CVE-2024-11234",
    "CVE-2024-11236"
  );
  script_xref(name:"FEDORA", value:"2024-e0d390d35b");
  script_xref(name:"IAVA", value:"2024-A-0763-S");

  script_name(english:"Fedora 40 : php (2024-e0d390d35b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2024-e0d390d35b advisory.

    **PHP version 8.3.14** (21 Nov 2024)

    **CLI:**

    * Fixed bug [GH-16373](https://github.com/php/php-src/issues/16373) (Shebang is not skipped for router
    script in cli-server started through shebang). (ilutov)
    * Fixed bug [GHSA-4w77-75f9-2c8w](https://github.com/php/php-src/security/advisories/GHSA-4w77-75f9-2c8w)
    (Heap-Use-After-Free in sapi_read_post_data Processing in CLI SAPI Interface). (nielsdos)

    **COM:**

    * Fixed out of bound writes to SafeArray data. (cmb)

    **Core:**

    * Fixed bug [GH-16168](https://github.com/php/php-src/issues/16168) (php 8.1 and earlier crash immediately
    when compiled with Xcode 16 clang on macOS 15). (nielsdos)
    * Fixed bug [GH-16371](https://github.com/php/php-src/issues/16371) (Assertion failure in
    Zend/zend_weakrefs.c:646). (Arnaud)
    * Fixed bug [GH-16515](https://github.com/php/php-src/issues/16515) (Incorrect propagation of
    ZEND_ACC_RETURN_REFERENCE for call trampoline). (ilutov)
    * Fixed bug [GH-16509](https://github.com/php/php-src/issues/16509) (Incorrect line number in function
    redeclaration error). (ilutov)
    * Fixed bug [GH-16508](https://github.com/php/php-src/issues/16508) (Incorrect line number in inheritance
    errors of delayed early bound classes). (ilutov)
    * Fixed bug [GH-16648](https://github.com/php/php-src/issues/16648) (Use-after-free during array sorting).
    (ilutov)

    **Curl:**

    * Fixed bug [GH-16302](https://github.com/php/php-src/issues/16302) (CurlMultiHandle holds a reference to
    CurlHandle if curl_multi_add_handle fails). (timwolla)

    **Date:**

    * Fixed bug [GH-16454](https://github.com/php/php-src/issues/16454) (Unhandled INF in date_sunset() with
    tiny $utcOffset). (cmb)
    * Fixed bug [GH-14732](https://github.com/php/php-src/issues/14732) (date_sun_info() fails for non-finite
    values). (cmb)

    **DBA:**

    * Fixed bug [GH-16390](https://github.com/php/php-src/issues/16390) (dba_open() can segfault for
    pathless streams). (cmb)

    **DOM:**

    * Fixed bug [GH-16316](https://github.com/php/php-src/issues/16316) (DOMXPath breaks when not initialized
    properly). (nielsdos)
    * Add missing hierarchy checks to replaceChild. (nielsdos)
    * Fixed bug [GH-16336](https://github.com/php/php-src/issues/16336) (Attribute intern document
    mismanagement). (nielsdos)
    * Fixed bug [GH-16338](https://github.com/php/php-src/issues/16338) (Null-dereference in ext/dom/node.c).
    (nielsdos)
    * Fixed bug [GH-16473](https://github.com/php/php-src/issues/16473) (dom_import_simplexml stub is wrong).
    (nielsdos)
    * Fixed bug [GH-16533](https://github.com/php/php-src/issues/16533) (Segfault when adding attribute to
    parent that is not an element). (nielsdos)
    * Fixed bug [GH-16535](https://github.com/php/php-src/issues/16535) (UAF when using document as a child).
    (nielsdos)
    * Fixed bug [GH-16593](https://github.com/php/php-src/issues/16593) (Assertion failure in
    DOM->replaceChild). (nielsdos)
    * Fixed bug [GH-16595](https://github.com/php/php-src/issues/16595) (Another UAF in DOM -> cloneNode).
    (nielsdos)

    **EXIF:**

    * Fixed bug [GH-16409](https://github.com/php/php-src/issues/16409) (Segfault in exif_thumbnail when not
    dealing with a real file). (nielsdos, cmb)

    **FFI:**

    * Fixed bug [GH-16397](https://github.com/php/php-src/issues/16397) (Segmentation fault when comparing FFI
    object). (nielsdos)

    **Filter:**

    * Fixed bug [GH-16523](https://github.com/php/php-src/issues/16523) (FILTER_FLAG_HOSTNAME accepts ending
    hyphen). (cmb)

    **FPM:**

    * Fixed bug [GH-16628](https://github.com/php/php-src/issues/16628) (FPM logs are getting corrupted with
    this log statement). (nielsdos)

    **GD:**

    * Fixed bug [GH-16334](https://github.com/php/php-src/issues/16334) (imageaffine overflow on matrix
    elements). (David Carlier)
    * Fixed bug [GH-16427](https://github.com/php/php-src/issues/16427) (Unchecked libavif return values).
    (cmb)
    * Fixed bug [GH-16559](https://github.com/php/php-src/issues/16559) (UBSan abort in
    ext/gd/libgd/gd_interpolation.c:1007). (nielsdos)

    **GMP:**

    * Fixed floating point exception bug with gmp_pow when using large exposant values. (David Carlier).
    * Fixed bug [GH-16411](https://github.com/php/php-src/issues/16411) (gmp_export() can cause overflow).
    (cmb)
    * Fixed bug [GH-16501](https://github.com/php/php-src/issues/16501) (gmp_random_bits() can cause
    overflow). (David Carlier)
    * Fixed gmp_pow() overflow bug with large base/exponents. (David Carlier)
    * Fixed segfaults and other issues related to operator overloading with GMP objects. (Girgias)

    **LDAP:**

    * Fixed bug [GHSA-g665-fm4p-vhff](https://github.com/php/php-src/security/advisories/GHSA-g665-fm4p-vhff)
    (OOB access in ldap_escape). (**CVE-2024-8932**) (nielsdos)

    **MBstring:**

    * Fixed bug [GH-16361](https://github.com/php/php-src/issues/16361) (mb_substr overflow on start/length
    arguments). (David Carlier)

    **MySQLnd:**

    * Fixed bug [GHSA-h35g-vwh6-m678](https://github.com/php/php-src/security/advisories/GHSA-h35g-vwh6-m678)
    (Leak partial content of the heap through heap buffer over-read). (**CVE-2024-8929**) (Jakub Zelenka)

    **Opcache:**

    * Fixed bug [GH-16408](https://github.com/php/php-src/issues/16408) (Array to string conversion warning
    emitted in optimizer). (ilutov)

    **OpenSSL:**

    * Fixed bug [GH-16357](https://github.com/php/php-src/issues/16357) (openssl may modify member types of
    certificate arrays). (cmb)
    * Fixed bug [GH-16433](https://github.com/php/php-src/issues/16433) (Large values for openssl_csr_sign()
    $days overflow). (cmb)
    * Fix various memory leaks on error conditions in openssl_x509_parse(). (nielsdos)

    **PDO DBLIB:**

    * Fixed bug [GHSA-5hqh-c84r-qjcv](https://github.com/php/php-src/security/advisories/GHSA-5hqh-c84r-qjcv)
    (Integer overflow in the dblib quoter causing OOB writes). (**CVE-2024-11236**) (nielsdos)

    **PDO Firebird:**

    * Fixed bug [GHSA-5hqh-c84r-qjcv](https://github.com/php/php-src/security/advisories/GHSA-5hqh-c84r-qjcv)
    (Integer overflow in the firebird quoter causing OOB writes). (**CVE-2024-11236**) (nielsdos)

    **PDO ODBC:**

    * Fixed bug [GH-16450](https://github.com/php/php-src/issues/16450) (PDO_ODBC can inject garbage into
    field values). (cmb)

    **Phar:**

    * Fixed bug [GH-16406](https://github.com/php/php-src/issues/16406) (Assertion failure in
    ext/phar/phar.c:2808). (nielsdos)

    **PHPDBG:**

    * Fixed bug [GH-16174](https://github.com/php/php-src/issues/16174) (Empty string is an invalid expression
    for ev). (cmb)

    **Reflection:**

    * Fixed bug [GH-16601](https://github.com/php/php-src/issues/16601) (Memory leak in Reflection
    constructors). (nielsdos)

    **Session:**

    * Fixed bug [GH-16385](https://github.com/php/php-src/issues/16385) (Unexpected null returned by
    session_set_cookie_params). (nielsdos)
    * Fixed bug [GH-16290](https://github.com/php/php-src/issues/16290) (overflow on cookie_lifetime ini
    value). (David Carlier)

    **SOAP:**

    * Fixed bug [GH-16318](https://github.com/php/php-src/issues/16318) (Recursive array segfaults soap
    encoding). (nielsdos)
    * Fixed bug [GH-16429](https://github.com/php/php-src/issues/16429) (Segmentation fault access null
    pointer in SoapClient). (nielsdos)

    **Sockets:**

    * Fixed bug with overflow socket_recvfrom $length argument. (David Carlier)

    **SPL:**

    * Fixed bug [GH-16337](https://github.com/php/php-src/issues/16337) (Use-after-free in SplHeap).
    (nielsdos)
    * Fixed bug [GH-16464](https://github.com/php/php-src/issues/16464) (Use-after-free in
    SplDoublyLinkedList::offsetSet()). (ilutov)
    * Fixed bug [GH-16479](https://github.com/php/php-src/issues/16479) (Use-after-free in
    SplObjectStorage::setInfo()). (ilutov)
    * Fixed bug [GH-16478](https://github.com/php/php-src/issues/16478) (Use-after-free in
    SplFixedArray::unset()). (ilutov)
    * Fixed bug [GH-16588](https://github.com/php/php-src/issues/16588) (UAF in Observer->serialize).
    (nielsdos)
    * Fix [GH-16477](https://github.com/php/php-src/issues/16477) (Segmentation fault when calling
    __debugInfo() after failed SplFileObject::__constructor). (Girgias)
    * Fixed bug [GH-16589](https://github.com/php/php-src/issues/16589) (UAF in SplDoublyLinked->serialize()).
    (nielsdos)
    * Fixed bug [GH-14687](https://github.com/php/php-src/issues/14687) (segfault on SplObjectIterator
    instance). (David Carlier)
    * Fixed bug [GH-16604](https://github.com/php/php-src/issues/16604) (Memory leaks in SPL constructors).
    (nielsdos)
    * Fixed bug [GH-16646](https://github.com/php/php-src/issues/16646) (UAF in ArrayObject::unset() and
    ArrayObject::exchangeArray()). (ilutov)

    **Standard:**

    * Fixed bug [GH-16293](https://github.com/php/php-src/issues/16293) (Failed assertion when throwing in
    assert() callback with bail enabled). (ilutov)

    **Streams:**

    * Fixed bug [GHSA-c5f2-jwm7-mmq2](https://github.com/php/php-src/security/advisories/GHSA-c5f2-jwm7-mmq2)
    (Configuring a proxy in a stream context might allow for CRLF injection in URIs). (**CVE-2024-11234**)
    (Jakub Zelenka)
    * Fixed bug [GHSA-r977-prxv-hc43](https://github.com/php/php-src/security/advisories/GHSA-r977-prxv-hc43)
    (Single byte overread with convert.quoted-printable-decode filter). (**CVE-2024-11233**) (nielsdos)

    **SysVMsg:**

    * Fixed bug [GH-16592](https://github.com/php/php-src/issues/16592) (msg_send() crashes when a type does
    not properly serialized). (David Carlier / cmb)

    **SysVShm:**

    * Fixed bug [GH-16591](https://github.com/php/php-src/issues/16591) (Assertion error in shm_put_var).
    (nielsdos, cmb)

    **XMLReader:**

    * Fixed bug [GH-16292](https://github.com/php/php-src/issues/16292) (Segmentation fault in
    ext/xmlreader/php_xmlreader.c). (nielsdos)

    **Zlib:**

    * Fixed bug [GH-16326](https://github.com/php/php-src/issues/16326) (Memory management is broken for bad
    dictionaries.) (cmb)






Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-e0d390d35b");
  script_set_attribute(attribute:"solution", value:
"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-11236");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^40([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 40', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'php-8.3.14-1.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE}
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
