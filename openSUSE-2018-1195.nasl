#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1195.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118196);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/30");

  script_cve_id("CVE-2018-10919");

  script_name(english:"openSUSE Security Update : samba (openSUSE-2018-1195)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Samba was updated to 4.6.15, bringing bug and security fixes.
(bsc#1110943)

Following security issues were fixed :

  - CVE-2018-10919: Fix unauthorized attribute access via
    searches. (bsc#1095057);

Non-security bugs fixed :

  - Fix ctdb_mutex_ceph_rados_helper deadlock (bsc#1102230).

  - Allow idmap_rid to have primary group other than 'Domain
    Users' (bsc#1087931).

  - winbind: avoid using fstrcpy in _dual_init_connection.

  - Fix ntlm authentications with 'winbind use default
    domain = yes' (bsc#1068059).

This update was imported from the SUSE:SLE-12-SP3:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110943");
  script_set_attribute(attribute:"solution", value:
"Update the affected samba packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10919");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-binding0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc-samr0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdcerpc0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-krb5pac0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-nbt0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr-standard0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libndr0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnetapi0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-credentials0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-errors0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-hostconfig0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-passdb0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-policy0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamba-util0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsamdb0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbclient0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbconf0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmbldap0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtevent-util0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwbclient0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-ceph-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-client-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:samba-winbind-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"ctdb-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ctdb-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ctdb-tests-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ctdb-tests-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libdcerpc-binding0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libdcerpc-binding0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libdcerpc-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libdcerpc-samr-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libdcerpc-samr0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libdcerpc-samr0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libdcerpc0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libdcerpc0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libndr-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libndr-krb5pac-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libndr-krb5pac0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libndr-krb5pac0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libndr-nbt-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libndr-nbt0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libndr-nbt0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libndr-standard-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libndr-standard0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libndr-standard0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libndr0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libndr0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libnetapi-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libnetapi0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libnetapi0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-credentials-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-credentials0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-credentials0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-errors-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-errors0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-errors0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-hostconfig-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-hostconfig0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-hostconfig0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-passdb-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-passdb0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-passdb0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-policy-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-policy0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-policy0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-util-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-util0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamba-util0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamdb-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamdb0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsamdb0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsmbclient-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsmbclient0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsmbclient0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsmbconf-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsmbconf0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsmbconf0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsmbldap-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsmbldap0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libsmbldap0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtevent-util-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtevent-util0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libtevent-util0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libwbclient-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libwbclient0-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libwbclient0-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-client-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-client-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-core-devel-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-debugsource-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-libs-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-libs-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-pidl-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-python-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-python-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-test-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-test-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-winbind-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"samba-winbind-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libdcerpc-samr0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libdcerpc-samr0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libdcerpc0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libndr-standard0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libndr0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libnetapi0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsamba-errors0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsamba-errors0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsamba-policy0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsamba-policy0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsamba-util0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsamdb0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsmbclient0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsmbconf0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsmbldap0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtevent-util0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libwbclient0-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"samba-ceph-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"samba-ceph-debuginfo-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"samba-client-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"samba-libs-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"samba-winbind-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.6.16+git.124.aee309c5c18-21.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb / ctdb-debuginfo / ctdb-tests / ctdb-tests-debuginfo / etc");
}
