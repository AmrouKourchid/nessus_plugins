#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:4066-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(120184);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/09");

  script_cve_id(
    "CVE-2018-14629",
    "CVE-2018-16841",
    "CVE-2018-16851",
    "CVE-2018-16853"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : samba (SUSE-SU-2018:4066-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for samba fixes the following issues :

Update to samba version 4.7.11.

Security issues fixed :

CVE-2018-14629: Fixed CNAME loops in Samba AD DC DNS server
(bsc#1116319).

CVE-2018-16841: Fixed segfault on PKINIT when mis-matching principal
(bsc#1116320).

CVE-2018-16851: Fixed NULL pointer de-reference in Samba AD DC LDAP
server (bsc#1116322).

CVE-2018-16853: Mark MIT support for the AD DC experimental
(bsc#1116324).

Non-security issues fixed: Fixed do not take over stderr when there is
no log file (bsc#1101499).

Fixed ctdb_mutex_ceph_rados_helper deadlock; (bsc#1102230).

Fixed ntlm authentications with 'winbind use default domain = yes';
(bsc#1068059).

Fixed idmap_rid to have primary group other than 'Domain Users';
(bsc#1087931).

Fixed windows domain with one way trust that was not working
(bsc#1087303).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1068059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1087303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1087931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1101499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1102230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1116319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1116320");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1116322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1116324");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14629/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16841/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16851/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16853/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20184066-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d47dd622");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Packagehub Subpackages 15:zypper in
-t patch SUSE-SLE-Module-Packagehub-Subpackages-15-2018-2888=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2018-2888=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2018-2888=1

SUSE Linux Enterprise High Availability 15:zypper in -t patch
SUSE-SLE-Product-HA-15-2018-2888=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16853");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-16851");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb-pcp-pmda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb-pcp-pmda-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"ctdb-pcp-pmda-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ctdb-pcp-pmda-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ctdb-tests-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ctdb-tests-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-binding0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-binding0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-samr-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-samr0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-samr0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-krb5pac-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-krb5pac0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-krb5pac0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-nbt-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-nbt0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-nbt0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-standard-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-standard0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-standard0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnetapi-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnetapi0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnetapi0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-credentials-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-credentials0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-credentials0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-errors-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-errors0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-errors0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-hostconfig-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-hostconfig0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-hostconfig0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-passdb-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-passdb0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-passdb0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-policy-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-policy0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-util-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-util0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-util0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamdb-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamdb0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamdb0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbclient-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbclient0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbclient0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbconf-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbconf0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbconf0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbldap-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbldap2-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbldap2-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtevent-util-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtevent-util0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtevent-util0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwbclient-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwbclient0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwbclient0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-client-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-client-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-core-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-debugsource-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-libs-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-libs-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-python-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-test-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-test-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-winbind-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-winbind-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ctdb-pcp-pmda-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ctdb-pcp-pmda-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ctdb-tests-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ctdb-tests-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-binding0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-binding0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-samr-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-samr0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-samr0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-krb5pac-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-krb5pac0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-krb5pac0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-nbt-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-nbt0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-nbt0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-standard-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-standard0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-standard0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnetapi-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnetapi0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnetapi0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-credentials-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-credentials0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-credentials0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-errors-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-errors0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-errors0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-hostconfig-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-hostconfig0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-hostconfig0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-passdb-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-passdb0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-passdb0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-policy-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-policy0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-util-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-util0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-util0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamdb-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamdb0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamdb0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbclient-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbclient0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbclient0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbconf-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbconf0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbconf0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbldap-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbldap2-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbldap2-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtevent-util-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtevent-util0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtevent-util0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwbclient-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwbclient0-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwbclient0-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-client-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-client-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-core-devel-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-debugsource-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-libs-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-libs-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-python-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-test-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-test-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-winbind-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-winbind-debuginfo-4.7.11+git.140.6bd0e5b30d8-4.21.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
