#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:4193-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(120192);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/09");

  script_cve_id("CVE-2018-16869");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libnettle (SUSE-SU-2018:4193-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for libnettle fixes the following issues :

Security issues fixed :

CVE-2018-16869: Fixed a leaky data conversion exposing a manager
oracle (bsc#1118086)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1118086");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16869/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20184193-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55d7350c");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2018-2986=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2018-2986=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2018-2986=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16869");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhogweed4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhogweed4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhogweed4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nettle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nettle-debuginfo");
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
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libhogweed4-32bit-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libhogweed4-32bit-debuginfo-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libnettle6-32bit-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libnettle6-32bit-debuginfo-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libhogweed4-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libhogweed4-debuginfo-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnettle-debugsource-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnettle-devel-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnettle6-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnettle6-debuginfo-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nettle-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nettle-debuginfo-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libhogweed4-32bit-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libhogweed4-32bit-debuginfo-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libnettle6-32bit-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libnettle6-32bit-debuginfo-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libhogweed4-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libhogweed4-debuginfo-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnettle-debugsource-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnettle-devel-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnettle6-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnettle6-debuginfo-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nettle-3.4-4.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nettle-debuginfo-3.4-4.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnettle");
}
