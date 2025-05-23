#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0069-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(132853);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/01");

  script_cve_id("CVE-2019-1551");
  script_xref(name:"IAVA", value:"2019-A-0303-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : openssl-1_1 (SUSE-SU-2020:0069-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for openssl-1_1 fixes the following issues :

Security issue fixed :

CVE-2019-1551: Fixed an overflow bug in the x64_64 Montgomery squaring
procedure used in exponentiation with 512-bit moduli (bsc#1158809).

Various FIPS related improvements were done: FIPS: Backport SSH KDF to
openssl (jsc#SLE-8789, bsc#1157775).

Port FIPS patches from SLE-12 (bsc#1158101).

Use SHA-2 in the RSA pairwise consistency check (bsc#1155346).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1155346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1157775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158809");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1551/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200069-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd8516eb");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-69=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2020-69=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1551");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl-1_1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_1-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-1_1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-1_1-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libopenssl-1_1-devel-32bit-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libopenssl1_1-32bit-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libopenssl1_1-32bit-debuginfo-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libopenssl1_1-hmac-32bit-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libopenssl-1_1-devel-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libopenssl1_1-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libopenssl1_1-debuginfo-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libopenssl1_1-hmac-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openssl-1_1-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openssl-1_1-debuginfo-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"openssl-1_1-debugsource-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libopenssl-1_1-devel-32bit-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libopenssl1_1-32bit-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libopenssl1_1-32bit-debuginfo-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libopenssl1_1-hmac-32bit-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libopenssl-1_1-devel-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libopenssl1_1-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libopenssl1_1-debuginfo-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libopenssl1_1-hmac-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openssl-1_1-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openssl-1_1-debuginfo-1.1.0i-14.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"openssl-1_1-debugsource-1.1.0i-14.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl-1_1");
}
