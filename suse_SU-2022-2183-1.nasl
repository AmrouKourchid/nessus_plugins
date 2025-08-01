##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:2183-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(162546);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/13");

  script_cve_id("CVE-2022-31625", "CVE-2022-31626");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:2183-1");

  script_name(english:"SUSE SLES12 Security Update : php72 (SUSE-SU-2022:2183-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 / SLES_SAP12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2022:2183-1 advisory.

  - In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when using Postgres
    database extension, supplying invalid parameters to the parametrized query may lead to PHP attempting to
    free memory using uninitialized data as pointers. This could lead to RCE vulnerability or denial of
    service. (CVE-2022-31625)

  - In PHP versions 7.4.x below 7.4.30, 8.0.x below 8.0.20, and 8.1.x below 8.1.7, when pdo_mysql extension
    with mysqlnd driver, if the third party is allowed to supply host to connect to and the password for the
    connection, password of excessive length can trigger a buffer overflow in PHP, which can lead to a remote
    code execution vulnerability. (CVE-2022-31626)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200645");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31625");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31626");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-June/011358.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?600dbcad");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31625");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-31626");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php72");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pear-Archive_Tar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sodium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php72-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP0/3/4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(0|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP0/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'apache2-mod_php72-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'apache2-mod_php72-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'apache2-mod_php72-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'apache2-mod_php72-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-bcmath-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-bcmath-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-bcmath-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-bcmath-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-bz2-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-bz2-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-bz2-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-bz2-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-calendar-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-calendar-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-calendar-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-calendar-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-ctype-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-ctype-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-ctype-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-ctype-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-curl-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-curl-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-curl-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-curl-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-dba-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-dba-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-dba-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-dba-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-dom-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-dom-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-dom-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-dom-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-enchant-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-enchant-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-enchant-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-enchant-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-exif-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-exif-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-exif-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-exif-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-fastcgi-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-fastcgi-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-fastcgi-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-fastcgi-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-fileinfo-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-fileinfo-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-fileinfo-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-fileinfo-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-fpm-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-fpm-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-fpm-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-fpm-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-ftp-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-ftp-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-ftp-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-ftp-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-gd-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-gd-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-gd-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-gd-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-gettext-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-gettext-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-gettext-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-gettext-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-gmp-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-gmp-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-gmp-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-gmp-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-iconv-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-iconv-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-iconv-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-iconv-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-imap-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-imap-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-imap-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-imap-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-intl-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-intl-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-intl-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-intl-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-json-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-json-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-json-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-json-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-ldap-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-ldap-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-ldap-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-ldap-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-mbstring-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-mbstring-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-mbstring-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-mbstring-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-mysql-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-mysql-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-mysql-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-mysql-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-odbc-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-odbc-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-odbc-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-odbc-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-opcache-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-opcache-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-opcache-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-opcache-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-openssl-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-openssl-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-openssl-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-openssl-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pcntl-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pcntl-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pcntl-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pcntl-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pdo-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pdo-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pdo-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pdo-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pear-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pear-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pear-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pear-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pear-Archive_Tar-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pear-Archive_Tar-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pear-Archive_Tar-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pear-Archive_Tar-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pgsql-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pgsql-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pgsql-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pgsql-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-phar-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-phar-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-phar-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-phar-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-posix-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-posix-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-posix-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-posix-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pspell-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pspell-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pspell-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-pspell-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-readline-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-readline-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-readline-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-readline-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-shmop-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-shmop-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-shmop-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-shmop-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-snmp-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-snmp-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-snmp-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-snmp-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-soap-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-soap-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-soap-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-soap-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sockets-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sockets-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sockets-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sockets-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sodium-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sodium-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sodium-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sodium-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sqlite-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sqlite-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sqlite-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sqlite-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sysvmsg-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sysvmsg-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sysvmsg-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sysvmsg-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sysvsem-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sysvsem-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sysvsem-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sysvsem-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sysvshm-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sysvshm-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sysvshm-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-sysvshm-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-tidy-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-tidy-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-tidy-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-tidy-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-tokenizer-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-tokenizer-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-tokenizer-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-tokenizer-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-wddx-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-wddx-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-wddx-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-wddx-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xmlreader-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xmlreader-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xmlreader-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xmlreader-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xmlrpc-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xmlrpc-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xmlrpc-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xmlrpc-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xmlwriter-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xmlwriter-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xmlwriter-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xmlwriter-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xsl-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xsl-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xsl-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-xsl-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-zip-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-zip-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-zip-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-zip-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-zlib-7.2.5-1.81.1', 'sp':'0', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-zlib-7.2.5-1.81.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-zlib-7.2.5-1.81.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'php72-zlib-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE-HPC-release-12', 'sle-module-web-scripting-release-12-0', 'sles-release-12', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'apache2-mod_php72-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'apache2-mod_php72-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'apache2-mod_php72-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'apache2-mod_php72-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-bcmath-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-bcmath-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-bcmath-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-bcmath-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-bz2-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-bz2-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-bz2-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-bz2-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-calendar-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-calendar-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-calendar-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-calendar-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-ctype-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-ctype-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-ctype-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-ctype-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-curl-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-curl-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-curl-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-curl-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-dba-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-dba-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-dba-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-dba-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-dom-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-dom-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-dom-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-dom-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-enchant-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-enchant-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-enchant-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-enchant-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-exif-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-exif-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-exif-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-exif-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-fastcgi-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-fastcgi-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-fastcgi-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-fastcgi-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-fileinfo-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-fileinfo-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-fileinfo-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-fileinfo-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-fpm-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-fpm-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-fpm-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-fpm-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-ftp-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-ftp-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-ftp-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-ftp-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-gd-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-gd-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-gd-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-gd-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-gettext-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-gettext-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-gettext-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-gettext-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-gmp-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-gmp-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-gmp-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-gmp-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-iconv-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-iconv-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-iconv-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-iconv-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-imap-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-imap-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-imap-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-imap-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-intl-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-intl-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-intl-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-intl-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-json-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-json-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-json-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-json-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-ldap-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-ldap-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-ldap-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-ldap-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-mbstring-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-mbstring-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-mbstring-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-mbstring-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-mysql-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-mysql-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-mysql-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-mysql-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-odbc-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-odbc-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-odbc-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-odbc-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-opcache-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-opcache-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-opcache-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-opcache-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-openssl-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-openssl-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-openssl-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-openssl-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pcntl-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pcntl-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pcntl-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pcntl-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pdo-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pdo-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pdo-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pdo-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pear-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pear-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pear-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pear-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pear-Archive_Tar-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pear-Archive_Tar-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pear-Archive_Tar-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pear-Archive_Tar-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pgsql-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pgsql-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pgsql-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pgsql-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-phar-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-phar-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-phar-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-phar-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-posix-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-posix-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-posix-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-posix-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pspell-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pspell-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pspell-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-pspell-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-readline-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-readline-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-readline-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-readline-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-shmop-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-shmop-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-shmop-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-shmop-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-snmp-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-snmp-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-snmp-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-snmp-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-soap-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-soap-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-soap-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-soap-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sockets-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sockets-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sockets-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sockets-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sodium-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sodium-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sodium-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sodium-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sqlite-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sqlite-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sqlite-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sqlite-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sysvmsg-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sysvmsg-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sysvmsg-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sysvmsg-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sysvsem-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sysvsem-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sysvsem-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sysvsem-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sysvshm-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sysvshm-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sysvshm-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-sysvshm-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-tidy-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-tidy-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-tidy-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-tidy-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-tokenizer-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-tokenizer-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-tokenizer-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-tokenizer-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-wddx-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-wddx-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-wddx-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-wddx-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xmlreader-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xmlreader-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xmlreader-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xmlreader-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xmlrpc-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xmlrpc-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xmlrpc-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xmlrpc-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xmlwriter-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xmlwriter-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xmlwriter-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xmlwriter-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xsl-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xsl-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xsl-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-xsl-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-zip-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-zip-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-zip-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-zip-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-zlib-7.2.5-1.81.1', 'sp':'0', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-zlib-7.2.5-1.81.1', 'sp':'3', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-zlib-7.2.5-1.81.1', 'sp':'4', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-zlib-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5']},
    {'reference':'php72-devel-7.2.5-1.81.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'php72-devel-7.2.5-1.81.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'apache2-mod_php72 / php72 / php72-bcmath / php72-bz2 / etc');
}
