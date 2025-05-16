#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:2519. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194152);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id(
    "CVE-2016-10166",
    "CVE-2017-9118",
    "CVE-2017-9120",
    "CVE-2017-12932",
    "CVE-2017-16642",
    "CVE-2018-5711",
    "CVE-2018-5712",
    "CVE-2018-7584",
    "CVE-2018-10545",
    "CVE-2018-10546",
    "CVE-2018-10547",
    "CVE-2018-10548",
    "CVE-2018-10549",
    "CVE-2018-14851",
    "CVE-2018-14884",
    "CVE-2018-17082",
    "CVE-2018-20783",
    "CVE-2019-6977",
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
    "CVE-2019-11038",
    "CVE-2019-11039",
    "CVE-2019-11040"
  );
  script_xref(name:"RHSA", value:"2019:2519");

  script_name(english:"RHEL 7 : rh-php71-php (RHSA-2019:2519)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2019:2519 advisory.

    PHP is an HTML-embedded scripting language commonly used with the Apache HTTP Server.

    The following packages have been upgraded to a later upstream version: rh-php71-php (7.1.30). (BZ#1631672)

    Security Fix(es):

    * gd: Unsigned integer underflow _gdContributionsAlloc() (CVE-2016-10166)

    * php: Out of bounds access in php_pcre.c:php_pcre_replace_impl() (CVE-2017-9118)

    * php: Integer overflow in mysqli_api.c:mysqli_real_escape_string() (CVE-2017-9120)

    * php: Heap use after free in ext/standard/var_unserializer.re (CVE-2017-12932)

    * php: Reflected XSS in .phar 404 page (CVE-2018-5712)

    * php: Stack-based buffer under-read in php_stream_url_wrap_http_ex() in http_fopen_wrapper.c when parsing
    HTTP response (CVE-2018-7584)

    * php: Infinite loop in ext/iconv/iconv.c when using stream filter with convert.incov on invalid sequence
    leads to denial-of-service (CVE-2018-10546)

    * php: Reflected XSS vulnerability on PHAR 403 and 404 error pages (CVE-2018-10547)

    * php: NULL pointer dereference due to mishandling of ldap_get_dn return value allows DoS via malicious
    LDAP server reply (CVE-2018-10548)

    * php: Mishandled http_header_value in an atoi() call in http_fopen_wrapper.c (CVE-2018-14884)

    * php: Cross-site scripting (XSS) flaw in Apache2 component via body of 'Transfer-Encoding: chunked'
    request (CVE-2018-17082)

    * gd: Heap based buffer overflow in gdImageColorMatch() in gd_color_match.c (CVE-2019-6977)

    * php: Invalid memory access in function xmlrpc_decode() (CVE-2019-9020)

    * php: File rename across filesystems may allow unwanted access during processing (CVE-2019-9637)

    * php: Uninitialized read in exif_process_IFD_in_MAKERNOTE (CVE-2019-9638)

    * php: Uninitialized read in exif_process_IFD_in_MAKERNOTE (CVE-2019-9639)

    * php: Invalid read in exif_process_SOFn() (CVE-2019-9640)

    * php: Out-of-bounds read due to integer overflow in iconv_mime_decode_headers() (CVE-2019-11039)

    * php: Buffer over-read in exif_read_data() (CVE-2019-11040)

    * php: Out-of-bound read in timelib_meridian() (CVE-2017-16642)

    * gd: Infinite loop in gdImageCreateFromGifCtx() in gd_gif_in.c (CVE-2018-5711)

    * php: Dumpable FPM child processes allow bypassing opcache access controls (CVE-2018-10545)

    * php: Out-of-bounds read in ext/exif/exif.c:exif_read_data() when reading crafted JPEG data
    (CVE-2018-10549)

    * php: exif: Buffer over-read in exif_process_IFD_in_MAKERNOTE() (CVE-2018-14851)

    * php: Buffer over-read in PHAR reading functions (CVE-2018-20783)

    * php: Heap-based buffer over-read in PHAR reading functions (CVE-2019-9021)

    * php: memcpy with negative length via crafted DNS response (CVE-2019-9022)

    * php: Heap-based buffer over-read in mbstring regular expression functions (CVE-2019-9023)

    * php: Out-of-bounds read in base64_decode_xmlrpc in ext/xmlrpc/libxmlrpc/base64.c (CVE-2019-9024)

    * php: Heap buffer overflow in function exif_process_IFD_TAG() (CVE-2019-11034)

    * php: Heap buffer overflow in function exif_iif_add_value() (CVE-2019-11035)

    * php: Buffer over-read in exif_process_IFD_TAG() leading to information disclosure (CVE-2019-11036)

    * gd: Information disclosure in gdImageCreateFromXbm() (CVE-2019-11038)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_2519.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?961b0f7d");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1418983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1484837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1512057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1535246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1535251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1551039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1563858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1573797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1573802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1573805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1573814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1609642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1611890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1611898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1612362");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1629552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1672207");
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1724149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1724152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1724154");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:2519");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 119, 122, 125, 190, 200, 266, 287, 400, 416, 476, 665, 835);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-php71-php-zip");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/rhscl/1/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/rhscl/1/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/rhscl/1/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhscl/1/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/debug',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/os',
      'content/dist/rhel/power/7/7Server/ppc64/rhscl/1/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhscl/1/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/os',
      'content/dist/rhel/system-z/7/7Server/s390x/rhscl/1/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/power-le/7/7.2/ppc64le/rhscl/1/debug',
      'content/eus/rhel/power-le/7/7.2/ppc64le/rhscl/1/os',
      'content/eus/rhel/power-le/7/7.2/ppc64le/rhscl/1/source/SRPMS',
      'content/eus/rhel/power-le/7/7.3/ppc64le/rhscl/1/debug',
      'content/eus/rhel/power-le/7/7.3/ppc64le/rhscl/1/os',
      'content/eus/rhel/power-le/7/7.3/ppc64le/rhscl/1/source/SRPMS',
      'content/eus/rhel/power-le/7/7.4/ppc64le/rhscl/1/debug',
      'content/eus/rhel/power-le/7/7.4/ppc64le/rhscl/1/os',
      'content/eus/rhel/power-le/7/7.4/ppc64le/rhscl/1/source/SRPMS',
      'content/eus/rhel/power-le/7/7.5/ppc64le/rhscl/1/debug',
      'content/eus/rhel/power-le/7/7.5/ppc64le/rhscl/1/os',
      'content/eus/rhel/power-le/7/7.5/ppc64le/rhscl/1/source/SRPMS',
      'content/eus/rhel/power-le/7/7.6/ppc64le/rhscl/1/debug',
      'content/eus/rhel/power-le/7/7.6/ppc64le/rhscl/1/os',
      'content/eus/rhel/power-le/7/7.6/ppc64le/rhscl/1/source/SRPMS',
      'content/eus/rhel/power-le/7/7.7/ppc64le/rhscl/1/debug',
      'content/eus/rhel/power-le/7/7.7/ppc64le/rhscl/1/os',
      'content/eus/rhel/power-le/7/7.7/ppc64le/rhscl/1/source/SRPMS',
      'content/eus/rhel/power/7/7.2/ppc64/rhscl/1/debug',
      'content/eus/rhel/power/7/7.2/ppc64/rhscl/1/os',
      'content/eus/rhel/power/7/7.2/ppc64/rhscl/1/source/SRPMS',
      'content/eus/rhel/power/7/7.3/ppc64/rhscl/1/debug',
      'content/eus/rhel/power/7/7.3/ppc64/rhscl/1/os',
      'content/eus/rhel/power/7/7.3/ppc64/rhscl/1/source/SRPMS',
      'content/eus/rhel/power/7/7.4/ppc64/rhscl/1/debug',
      'content/eus/rhel/power/7/7.4/ppc64/rhscl/1/os',
      'content/eus/rhel/power/7/7.4/ppc64/rhscl/1/source/SRPMS',
      'content/eus/rhel/power/7/7.5/ppc64/rhscl/1/debug',
      'content/eus/rhel/power/7/7.5/ppc64/rhscl/1/os',
      'content/eus/rhel/power/7/7.5/ppc64/rhscl/1/source/SRPMS',
      'content/eus/rhel/power/7/7.6/ppc64/rhscl/1/debug',
      'content/eus/rhel/power/7/7.6/ppc64/rhscl/1/os',
      'content/eus/rhel/power/7/7.6/ppc64/rhscl/1/source/SRPMS',
      'content/eus/rhel/power/7/7.7/ppc64/rhscl/1/debug',
      'content/eus/rhel/power/7/7.7/ppc64/rhscl/1/os',
      'content/eus/rhel/power/7/7.7/ppc64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.1/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.1/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.1/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.2/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.2/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.2/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.3/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.3/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.3/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.4/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.4/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.4/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.5/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.5/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.5/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.6/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.6/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.6/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/server/7/7.7/x86_64/rhscl/1/debug',
      'content/eus/rhel/server/7/7.7/x86_64/rhscl/1/os',
      'content/eus/rhel/server/7/7.7/x86_64/rhscl/1/source/SRPMS',
      'content/eus/rhel/system-z/7/7.2/s390x/rhscl/1/debug',
      'content/eus/rhel/system-z/7/7.2/s390x/rhscl/1/os',
      'content/eus/rhel/system-z/7/7.2/s390x/rhscl/1/source/SRPMS',
      'content/eus/rhel/system-z/7/7.3/s390x/rhscl/1/debug',
      'content/eus/rhel/system-z/7/7.3/s390x/rhscl/1/os',
      'content/eus/rhel/system-z/7/7.3/s390x/rhscl/1/source/SRPMS',
      'content/eus/rhel/system-z/7/7.4/s390x/rhscl/1/debug',
      'content/eus/rhel/system-z/7/7.4/s390x/rhscl/1/os',
      'content/eus/rhel/system-z/7/7.4/s390x/rhscl/1/source/SRPMS',
      'content/eus/rhel/system-z/7/7.5/s390x/rhscl/1/debug',
      'content/eus/rhel/system-z/7/7.5/s390x/rhscl/1/os',
      'content/eus/rhel/system-z/7/7.5/s390x/rhscl/1/source/SRPMS',
      'content/eus/rhel/system-z/7/7.6/s390x/rhscl/1/debug',
      'content/eus/rhel/system-z/7/7.6/s390x/rhscl/1/os',
      'content/eus/rhel/system-z/7/7.6/s390x/rhscl/1/source/SRPMS',
      'content/eus/rhel/system-z/7/7.7/s390x/rhscl/1/debug',
      'content/eus/rhel/system-z/7/7.7/s390x/rhscl/1/os',
      'content/eus/rhel/system-z/7/7.7/s390x/rhscl/1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rh-php71-php-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-bcmath-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-cli-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-common-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-dba-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-dbg-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-devel-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-embedded-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-enchant-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-fpm-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-gd-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-gmp-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-intl-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-json-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-ldap-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-mbstring-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-mysqlnd-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-odbc-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-opcache-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-pdo-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-pgsql-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-process-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-pspell-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-recode-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-snmp-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-soap-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-xml-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-xmlrpc-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rh-php71-php-zip-7.1.30-1.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    var cves = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rh-php71-php / rh-php71-php-bcmath / rh-php71-php-cli / etc');
}
