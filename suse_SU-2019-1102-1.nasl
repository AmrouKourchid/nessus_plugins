#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1102-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(124451);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/30");

  script_cve_id("CVE-2009-5155", "CVE-2016-10739", "CVE-2019-9169");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : glibc (SUSE-SU-2019:1102-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for glibc fixes the following issues :

Security issues fixed :

CVE-2019-9169: regex: fix read overrun (bsc#1127308, BZ #24114)

CVE-2016-10739: Fully parse IPv4 address strings (bsc#1122729, BZ
#20018)

CVE-2009-5155: ERE '0|()0|\1|0' causes regexec undefined behavior
(bsc#1127223, BZ #18986)

Non-security issues fixed: Enable TLE only if GLIBC_ELISION_ENABLE=yes
is defined (bsc#1131994, fate#322271)

Add more checks for valid ld.so.cache file (bsc#1110661, BZ #18093)

Added cfi information for start routines in order to stop unwinding
(bsc#1128574)

ja_JP locale: Add entry for the new Japanese era (bsc#1100396,
fate#325570, BZ #22964)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1100396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1110661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1122729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1127223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1127308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1128574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1131994");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2009-5155/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-10739/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9169/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191102-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?894a9df5");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-1102=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-1102=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-1102=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP4", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-32bit-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-debuginfo-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-debuginfo-32bit-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-debugsource-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-devel-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-devel-32bit-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-devel-debuginfo-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-devel-debuginfo-32bit-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-locale-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-locale-32bit-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-locale-debuginfo-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-locale-debuginfo-32bit-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-profile-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"glibc-profile-32bit-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"nscd-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"nscd-debuginfo-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glibc-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glibc-32bit-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glibc-debuginfo-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glibc-debuginfo-32bit-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glibc-debugsource-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glibc-devel-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glibc-devel-32bit-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glibc-devel-debuginfo-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glibc-devel-debuginfo-32bit-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glibc-locale-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glibc-locale-32bit-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glibc-locale-debuginfo-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"glibc-locale-debuginfo-32bit-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"nscd-2.22-100.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"nscd-debuginfo-2.22-100.8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
