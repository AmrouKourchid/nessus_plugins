#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-80.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(133133);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/29");

  script_cve_id(
    "CVE-2019-11045",
    "CVE-2019-11046",
    "CVE-2019-11047",
    "CVE-2019-11050"
  );

  script_name(english:"openSUSE Security Update : php7 (openSUSE-2020-80)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for php7 fixes the following issues :

  - CVE-2019-11045: Fixed an issue with improper input
    validation in the filename handling of the
    DirectoryIterator class (bsc#1159923).

  - CVE-2019-11046: Fixed an information leak in
    bc_shift_addsub() (bsc#1159924).

  - CVE-2019-11047, CVE-2019-11050: Fixed multiple
    information leaks in exif_read_data() (bsc#1159922,
    bsc#1159927).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159927");
  script_set_attribute(attribute:"solution", value:
"Update the affected php7 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11050");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_php7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-bcmath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-bz2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-calendar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ctype-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-dba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-dom-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-embed-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-enchant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-exif-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fastcgi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fileinfo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-firebird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-fpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ftp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gettext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-gmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-iconv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-intl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-json-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-mbstring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-opcache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pcntl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pdo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pear-Archive_Tar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-pgsql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-phar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-phar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-posix-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-readline-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-shmop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-snmp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-soap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sockets-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sodium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sodium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvmsg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvsem-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-sysvshm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-tidy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-tokenizer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-wddx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlreader-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlrpc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xmlwriter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-xsl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-zip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php7-zlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"apache2-mod_php7-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-mod_php7-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-bcmath-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-bcmath-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-bz2-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-bz2-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-calendar-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-calendar-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-ctype-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-ctype-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-curl-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-curl-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-dba-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-dba-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-debugsource-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-devel-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-dom-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-dom-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-embed-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-embed-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-enchant-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-enchant-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-exif-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-exif-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-fastcgi-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-fastcgi-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-fileinfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-fileinfo-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-firebird-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-firebird-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-fpm-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-fpm-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-ftp-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-ftp-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-gd-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-gd-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-gettext-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-gettext-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-gmp-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-gmp-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-iconv-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-iconv-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-intl-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-intl-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-json-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-json-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-ldap-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-ldap-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-mbstring-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-mbstring-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-mysql-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-mysql-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-odbc-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-odbc-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-opcache-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-opcache-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-openssl-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-openssl-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-pcntl-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-pcntl-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-pdo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-pdo-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-pear-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-pear-Archive_Tar-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-pgsql-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-pgsql-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-phar-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-phar-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-posix-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-posix-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-readline-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-readline-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-shmop-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-shmop-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-snmp-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-snmp-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-soap-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-soap-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-sockets-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-sockets-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-sodium-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-sodium-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-sqlite-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-sqlite-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-sysvmsg-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-sysvmsg-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-sysvsem-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-sysvsem-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-sysvshm-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-sysvshm-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-test-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-tidy-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-tidy-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-tokenizer-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-tokenizer-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-wddx-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-wddx-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-xmlreader-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-xmlreader-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-xmlrpc-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-xmlrpc-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-xmlwriter-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-xmlwriter-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-xsl-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-xsl-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-zip-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-zip-debuginfo-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-zlib-7.2.5-lp151.6.19.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"php7-zlib-debuginfo-7.2.5-lp151.6.19.2") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-mod_php7 / apache2-mod_php7-debuginfo / php7 / php7-bcmath / etc");
}
