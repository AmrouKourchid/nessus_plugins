#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1423. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56699);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id(
    "CVE-2011-0708",
    "CVE-2011-1148",
    "CVE-2011-1466",
    "CVE-2011-1468",
    "CVE-2011-1469",
    "CVE-2011-1471",
    "CVE-2011-1938",
    "CVE-2011-2202",
    "CVE-2011-2483"
  );
  script_bugtraq_id(
    46365,
    46843,
    46967,
    46970,
    46975,
    46977,
    47950,
    48259,
    49241
  );
  script_xref(name:"RHSA", value:"2011:1423");

  script_name(english:"RHEL 6 : php53 and php (RHSA-2011:1423)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for php53 / php.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2011:1423 advisory.

    PHP is an HTML-embedded scripting language commonly used with the Apache
    HTTP Server.

    A signedness issue was found in the way the PHP crypt() function handled
    8-bit characters in passwords when using Blowfish hashing. Up to three
    characters immediately preceding a non-ASCII character (one with the high
    bit set) had no effect on the hash result, thus shortening the effective
    password length. This made brute-force guessing more efficient as several
    different passwords were hashed to the same value. (CVE-2011-2483)

    Note: Due to the CVE-2011-2483 fix, after installing this update some users
    may not be able to log in to PHP applications that hash passwords with
    Blowfish using the PHP crypt() function. Refer to the upstream
    CRYPT_BLOWFISH security fix details document, linked to in the
    References, for details.

    An insufficient input validation flaw, leading to a buffer over-read, was
    found in the PHP exif extension. A specially-crafted image file could cause
    the PHP interpreter to crash when a PHP script tries to extract
    Exchangeable image file format (Exif) metadata from the image file.
    (CVE-2011-0708)

    An integer overflow flaw was found in the PHP calendar extension. A remote
    attacker able to make a PHP script call SdnToJulian() with a large value
    could cause the PHP interpreter to crash. (CVE-2011-1466)

    Multiple memory leak flaws were found in the PHP OpenSSL extension. A
    remote attacker able to make a PHP script use openssl_encrypt() or
    openssl_decrypt() repeatedly could cause the PHP interpreter to use an
    excessive amount of memory. (CVE-2011-1468)

    A use-after-free flaw was found in the PHP substr_replace() function. If a
    PHP script used the same variable as multiple function arguments, a remote
    attacker could possibly use this to crash the PHP interpreter or, possibly,
    execute arbitrary code. (CVE-2011-1148)

    A bug in the PHP Streams component caused the PHP interpreter to crash if
    an FTP wrapper connection was made through an HTTP proxy. A remote attacker
    could possibly trigger this issue if a PHP script accepted an untrusted URL
    to connect to. (CVE-2011-1469)

    An integer signedness issue was found in the PHP zip extension. An attacker
    could use a specially-crafted ZIP archive to cause the PHP interpreter to
    use an excessive amount of CPU time until the script execution time limit
    is reached. (CVE-2011-1471)

    A stack-based buffer overflow flaw was found in the way the PHP socket
    extension handled long AF_UNIX socket addresses. An attacker able to make a
    PHP script connect to a long AF_UNIX socket address could use this flaw to
    crash the PHP interpreter. (CVE-2011-1938)

    An off-by-one flaw was found in PHP. If an attacker uploaded a file with a
    specially-crafted file name it could cause a PHP script to attempt to write
    a file to the root (/) directory. By default, PHP runs as the apache
    user, preventing it from writing to the root directory. (CVE-2011-2202)

    All php53 and php users should upgrade to these updated packages, which
    contain backported patches to resolve these issues. After installing the
    updated packages, the httpd daemon must be restarted for the update to take
    effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2011/rhsa-2011_1423.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4a59215");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=680972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=688958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=689386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=690899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=690905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=690915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=709067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=713194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=715025");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/security/crypt_blowfish.php");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2011:1423");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL php53 / php packages based on the guidance in RHSA-2011:1423.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-1938");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2011-2483");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(121, 401, 416);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-zts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php53-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redhat_repos.nasl", "ssh_get_info.nasl");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/power/6/6Server/ppc64/debug',
      'content/dist/rhel/power/6/6Server/ppc64/optional/debug',
      'content/dist/rhel/power/6/6Server/ppc64/optional/os',
      'content/dist/rhel/power/6/6Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/os',
      'content/dist/rhel/power/6/6Server/ppc64/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/os',
      'content/dist/rhel/server/6/6Server/i386/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/optional/debug',
      'content/dist/rhel/server/6/6Server/i386/optional/os',
      'content/dist/rhel/server/6/6Server/i386/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/os',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/optional/debug',
      'content/dist/rhel/server/6/6Server/x86_64/optional/os',
      'content/dist/rhel/server/6/6Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/os',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/os',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/os',
      'content/dist/rhel/system-z/6/6Server/s390x/source/SRPMS',
      'content/fastrack/rhel/power/6/ppc64/debug',
      'content/fastrack/rhel/power/6/ppc64/optional/debug',
      'content/fastrack/rhel/power/6/ppc64/optional/os',
      'content/fastrack/rhel/power/6/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/6/ppc64/os',
      'content/fastrack/rhel/power/6/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/os',
      'content/fastrack/rhel/server/6/i386/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/loadbalancer/debug',
      'content/fastrack/rhel/server/6/i386/loadbalancer/os',
      'content/fastrack/rhel/server/6/i386/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/optional/debug',
      'content/fastrack/rhel/server/6/i386/optional/os',
      'content/fastrack/rhel/server/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/debug',
      'content/fastrack/rhel/server/6/i386/resilientstorage/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/os',
      'content/fastrack/rhel/server/6/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/debug',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/os',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/optional/debug',
      'content/fastrack/rhel/server/6/x86_64/optional/os',
      'content/fastrack/rhel/server/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/6/s390x/debug',
      'content/fastrack/rhel/system-z/6/s390x/optional/debug',
      'content/fastrack/rhel/system-z/6/s390x/optional/os',
      'content/fastrack/rhel/system-z/6/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/6/s390x/os',
      'content/fastrack/rhel/system-z/6/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'php-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-bcmath-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-cli-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-common-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-dba-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-devel-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-embedded-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-enchant-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-gd-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-imap-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-intl-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-ldap-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mbstring-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-mysql-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-odbc-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pdo-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pgsql-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-process-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-pspell-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-recode-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-snmp-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-soap-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-tidy-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xml-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-xmlrpc-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-3.el6_1.3', 'cpu':'i686', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-3.el6_1.3', 'cpu':'ppc64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-3.el6_1.3', 'cpu':'s390x', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'php-zts-5.3.3-3.el6_1.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php / php-bcmath / php-cli / php-common / php-dba / php-devel / etc');
}
