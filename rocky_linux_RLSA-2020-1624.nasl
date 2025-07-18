#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2020:1624.
##

include('compat.inc');

if (description)
{
  script_id(184778);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/06");

  script_cve_id(
    "CVE-2018-20783",
    "CVE-2019-9020",
    "CVE-2019-9021",
    "CVE-2019-9022",
    "CVE-2019-9023",
    "CVE-2019-9024",
    "CVE-2019-9637",
    "CVE-2019-9638",
    "CVE-2019-9639",
    "CVE-2019-9640",
    "CVE-2019-11034",
    "CVE-2019-11035",
    "CVE-2019-11036",
    "CVE-2019-11039",
    "CVE-2019-11040",
    "CVE-2019-11041",
    "CVE-2019-11042"
  );
  script_xref(name:"IAVA", value:"2019-A-0437-S");
  script_xref(name:"IAVB", value:"2018-B-0157-S");
  script_xref(name:"IAVB", value:"2019-B-0020-S");
  script_xref(name:"IAVB", value:"2019-B-0030-S");
  script_xref(name:"IAVB", value:"2019-B-0033-S");
  script_xref(name:"IAVB", value:"2019-B-0045-S");
  script_xref(name:"IAVB", value:"2019-B-0070-S");
  script_xref(name:"RLSA", value:"2020:1624");

  script_name(english:"Rocky Linux 8 : php:7.2 (RLSA-2020:1624)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2020:1624 advisory.

  - In PHP before 5.6.39, 7.x before 7.0.33, 7.1.x before 7.1.25, and 7.2.x before 7.2.13, a buffer over-read
    in PHAR reading functions may allow an attacker to read allocated or unallocated memory past the actual
    data when trying to parse a .phar file. This is related to phar_parse_pharfile in ext/phar/phar.c.
    (CVE-2018-20783)

  - When processing certain files, PHP EXIF extension in versions 7.1.x below 7.1.28, 7.2.x below 7.2.17 and
    7.3.x below 7.3.4 can be caused to read past allocated buffer in exif_process_IFD_TAG function. This may
    lead to information disclosure or crash. (CVE-2019-11034)

  - When processing certain files, PHP EXIF extension in versions 7.1.x below 7.1.28, 7.2.x below 7.2.17 and
    7.3.x below 7.3.4 can be caused to read past allocated buffer in exif_iif_add_value function. This may
    lead to information disclosure or crash. (CVE-2019-11035)

  - When processing certain files, PHP EXIF extension in versions 7.1.x below 7.1.29, 7.2.x below 7.2.18 and
    7.3.x below 7.3.5 can be caused to read past allocated buffer in exif_process_IFD_TAG function. This may
    lead to information disclosure or crash. (CVE-2019-11036)

  - Function iconv_mime_decode_headers() in PHP versions 7.1.x below 7.1.30, 7.2.x below 7.2.19 and 7.3.x
    below 7.3.6 may perform out-of-buffer read due to integer overflow when parsing MIME headers. This may
    lead to information disclosure or crash. (CVE-2019-11039)

  - When PHP EXIF extension is parsing EXIF information from an image, e.g. via exif_read_data() function, in
    PHP versions 7.1.x below 7.1.30, 7.2.x below 7.2.19 and 7.3.x below 7.3.6 it is possible to supply it with
    data what will cause it to read past the allocated buffer. This may lead to information disclosure or
    crash. (CVE-2019-11040)

  - When PHP EXIF extension is parsing EXIF information from an image, e.g. via exif_read_data() function, in
    PHP versions 7.1.x below 7.1.31, 7.2.x below 7.2.21 and 7.3.x below 7.3.8 it is possible to supply it with
    data what will cause it to read past the allocated buffer. This may lead to information disclosure or
    crash. (CVE-2019-11041, CVE-2019-11042)

  - An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. Invalid input to the function xmlrpc_decode() can lead to an invalid memory access (heap out of
    bounds read or read after free). This is related to xml_elem_parse_buf in
    ext/xmlrpc/libxmlrpc/xml_element.c. (CVE-2019-9020)

  - An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. A heap-based buffer over-read in PHAR reading functions in the PHAR extension may allow an attacker
    to read allocated or unallocated memory past the actual data when trying to parse the file name, a
    different vulnerability than CVE-2018-20783. This is related to phar_detect_phar_fname_ext in
    ext/phar/phar.c. (CVE-2019-9021)

  - An issue was discovered in PHP 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before 7.3.2.
    dns_get_record misparses a DNS response, which can allow a hostile DNS server to cause PHP to misuse
    memcpy, leading to read operations going past the buffer allocated for DNS data. This affects php_parserr
    in ext/standard/dns.c for DNS_CAA and DNS_ANY queries. (CVE-2019-9022)

  - An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. A number of heap-based buffer over-read instances are present in mbstring regular expression
    functions when supplied with invalid multibyte data. These occur in ext/mbstring/oniguruma/regcomp.c,
    ext/mbstring/oniguruma/regexec.c, ext/mbstring/oniguruma/regparse.c, ext/mbstring/oniguruma/enc/unicode.c,
    and ext/mbstring/oniguruma/src/utf32_be.c when a multibyte regular expression pattern contains invalid
    multibyte sequences. (CVE-2019-9023)

  - An issue was discovered in PHP before 5.6.40, 7.x before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. xmlrpc_decode() can allow a hostile XMLRPC server to cause PHP to read memory outside of allocated
    areas in base64_decode_xmlrpc in ext/xmlrpc/libxmlrpc/base64.c. (CVE-2019-9024)

  - An issue was discovered in PHP before 7.1.27, 7.2.x before 7.2.16, and 7.3.x before 7.3.3. Due to the way
    rename() across filesystems is implemented, it is possible that file being renamed is briefly available
    with wrong permissions while the rename is ongoing, thus enabling unauthorized users to access the data.
    (CVE-2019-9637)

  - An issue was discovered in the EXIF component in PHP before 7.1.27, 7.2.x before 7.2.16, and 7.3.x before
    7.3.3. There is an uninitialized read in exif_process_IFD_in_MAKERNOTE because of mishandling the
    maker_note->offset relationship to value_len. (CVE-2019-9638)

  - An issue was discovered in the EXIF component in PHP before 7.1.27, 7.2.x before 7.2.16, and 7.3.x before
    7.3.3. There is an uninitialized read in exif_process_IFD_in_MAKERNOTE because of mishandling the data_len
    variable. (CVE-2019-9639)

  - An issue was discovered in the EXIF component in PHP before 7.1.27, 7.2.x before 7.2.16, and 7.3.x before
    7.3.3. There is an Invalid Read in exif_process_SOFn. (CVE-2019-9640)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2020:1624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1680545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1685123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1685132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1685398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1685404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1685412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1688897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1688922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1688934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1688939");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1707299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1724152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1724154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1739459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1739465");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:apcu-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libzip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libzip-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libzip-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libzip-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libzip-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-cli-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-dbg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-embedded-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-mysqlnd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-opcache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-apcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-apcu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-apcu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-apcu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-zip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pecl-zip-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-process-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-recode-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-xml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:php-xmlrpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var module_ver = get_kb_item('Host/RockyLinux/appstream/php');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.2');
if ('7.2' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module php:' + module_ver);

var appstreams = {
    'php:7.2': [
      {'reference':'apcu-panel-5.1.12-2.module+el8.4.0+413+c9202dda', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-1.5.1-2.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-1.5.1-2.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-debuginfo-1.5.1-2.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-debuginfo-1.5.1-2.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-debugsource-1.5.1-2.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-debugsource-1.5.1-2.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-devel-1.5.1-2.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-devel-1.5.1-2.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-tools-1.5.1-2.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-tools-1.5.1-2.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-tools-debuginfo-1.5.1-2.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libzip-tools-debuginfo-1.5.1-2.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dbg-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-debugsource-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-debugsource-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-fpm-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gmp-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-json-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-json-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-json-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-json-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysqlnd-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-opcache-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pear-1.10.5-9.module+el8.4.0+413+c9202dda', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'php-pecl-apcu-5.1.12-2.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-5.1.12-2.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-debuginfo-5.1.12-2.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-debuginfo-5.1.12-2.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-debugsource-5.1.12-2.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-debugsource-5.1.12-2.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.12-2.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-apcu-devel-5.1.12-2.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.15.3-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-1.15.3-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-debuginfo-1.15.3-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-debuginfo-1.15.3-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-debugsource-1.15.3-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pecl-zip-debugsource-1.15.3-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-debuginfo-7.2.24-1.module+el8.4.0+413+c9202dda', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RockyLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module php:7.2');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apcu-panel / libzip / libzip-debuginfo / libzip-debugsource / etc');
}
