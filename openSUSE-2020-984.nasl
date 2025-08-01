#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-984.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(138748);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/29");

  script_cve_id(
    "CVE-2020-10730",
    "CVE-2020-10745",
    "CVE-2020-10760",
    "CVE-2020-14303"
  );

  script_name(english:"openSUSE Security Update : samba (openSUSE-2020-984)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for samba fixes the following issues :

  - CVE-2020-10745: Fixed an issue which parsing and packing
    of NBT and DNS packets containing dots could potentially
    have consumed excessive CPU (bsc#1173160).

  - CVE-2020-14303: Fixed an endless loop when receiving at
    AD DC empty UDP packets (bsc#1173359).

  - CVE-2020-10730: Fixed a null de-reference in AD DC LDAP
    server when ASQ and VLV combined (bsc#1173159).

  - CVE-2020-10760: Fixed a use-after-free in AD DC Global
    Catalog LDAP server with paged_result or VLV
    (bsc#1173161).

  - Added libnetapi-devel to baselibs conf, for wine usage
    (bsc#1172307).

  - Fixed an installing issue where samba -
    samba-ad-dc.service did not exist and unit was not found
    (bsc#1171437).

This update was imported from the SUSE:SLE-15-SP1:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172307");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173159");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173359");
  script_set_attribute(attribute:"solution", value:
"Update the affected samba packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10745");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14303");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-pcp-pmda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-pcp-pmda-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy-python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy-python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-python3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ad-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ad-dc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ad-dc-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ad-dc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ceph-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-dsdb-modules-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo");
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

if ( rpm_check(release:"SUSE15.1", reference:"ctdb-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ctdb-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ctdb-pcp-pmda-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ctdb-pcp-pmda-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ctdb-tests-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ctdb-tests-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdcerpc-binding0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdcerpc-binding0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdcerpc-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdcerpc-samr-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdcerpc-samr0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdcerpc-samr0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdcerpc0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libdcerpc0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libndr-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libndr-krb5pac-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libndr-krb5pac0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libndr-krb5pac0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libndr-nbt-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libndr-nbt0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libndr-nbt0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libndr-standard-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libndr-standard0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libndr-standard0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libndr0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libndr0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libnetapi-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libnetapi0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libnetapi0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-credentials-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-credentials0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-credentials0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-errors-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-errors0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-errors0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-hostconfig-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-hostconfig0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-hostconfig0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-passdb-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-passdb0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-passdb0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-policy-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-policy-python-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-policy-python3-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-policy0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-policy0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-policy0-python3-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-policy0-python3-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-util-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-util0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamba-util0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamdb-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamdb0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsamdb0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsmbclient-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsmbclient0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsmbclient0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsmbconf-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsmbconf0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsmbconf0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsmbldap-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsmbldap2-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsmbldap2-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libtevent-util-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libtevent-util0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libtevent-util0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwbclient-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwbclient0-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwbclient0-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-ad-dc-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-ad-dc-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-client-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-client-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-core-devel-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-debugsource-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-dsdb-modules-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-dsdb-modules-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-libs-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-libs-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-libs-python-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-libs-python-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-libs-python3-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-libs-python3-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-pidl-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-python-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-python-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-python3-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-python3-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-test-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-test-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-winbind-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"samba-winbind-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libdcerpc-samr0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libdcerpc-samr0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libdcerpc0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libdcerpc0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libndr-nbt0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libndr-standard0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libndr-standard0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libndr0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libndr0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libnetapi-devel-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libnetapi0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libnetapi0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamba-credentials0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamba-errors0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamba-errors0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamba-passdb0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamba-policy0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamba-policy0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamba-policy0-python3-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamba-policy0-python3-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamba-util0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamba-util0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamdb0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsamdb0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsmbclient0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsmbclient0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsmbconf0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsmbconf0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsmbldap2-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsmbldap2-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libtevent-util0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libtevent-util0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libwbclient0-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libwbclient0-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"samba-ad-dc-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"samba-ad-dc-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"samba-ceph-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"samba-ceph-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"samba-client-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"samba-client-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"samba-libs-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"samba-libs-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"samba-libs-python-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"samba-libs-python-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"samba-libs-python3-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"samba-libs-python3-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"samba-winbind-32bit-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"samba-winbind-32bit-debuginfo-4.9.5+git.343.4bc358522a9-lp151.2.27.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-debuginfo / ctdb-pcp-pmda / ctdb-pcp-pmda-debuginfo / etc");
}
