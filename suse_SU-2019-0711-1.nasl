#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0711-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(123067);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/12");

  script_cve_id("CVE-2018-1152", "CVE-2018-11813", "CVE-2018-14498");
  script_xref(name:"TRA", value:"TRA-2018-17");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libjpeg-turbo (SUSE-SU-2019:0711-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for libjpeg-turbo fixes the following issues :

The following security vulnerabilities were addressed :

CVE-2018-14498: Fixed a heap-based buffer over read in get_8bit_row
function which could allow to an attacker to cause denial of service
(bsc#1128712).

CVE-2018-11813: Fixed the end-of-file mishandling in read_pixel in
rdtarga.c, which allowed remote attackers to cause a denial-of-service
via crafted JPG files due to a large loop (bsc#1096209)

CVE-2018-1152: Fixed a denial of service in start_input_bmp() rdbmp.c
caused by a divide by zero when processing a crafted BMP image
(bsc#1098155)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1096209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1098155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1128712");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1152/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-11813/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14498/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190711-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26a25d05");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2018-17");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Packagehub Subpackages 15:zypper in
-t patch SUSE-SLE-Module-Packagehub-Subpackages-15-2019-711=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-711=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-711=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-711=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11813");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjpeg-turbo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjpeg-turbo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjpeg-turbo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjpeg62");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjpeg62-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjpeg62-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjpeg62-turbo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjpeg62-turbo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjpeg8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjpeg8-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjpeg8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libjpeg8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libturbojpeg0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libturbojpeg0-debuginfo");
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
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libjpeg8-32bit-8.1.2-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libjpeg8-32bit-debuginfo-8.1.2-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libjpeg-turbo-1.5.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libjpeg-turbo-debuginfo-1.5.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libjpeg-turbo-debugsource-1.5.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libjpeg62-62.2.0-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libjpeg62-debuginfo-62.2.0-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libjpeg62-devel-62.2.0-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libjpeg62-turbo-1.5.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libjpeg62-turbo-debugsource-1.5.3-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libjpeg8-8.1.2-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libjpeg8-debuginfo-8.1.2-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libjpeg8-devel-8.1.2-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libturbojpeg0-8.1.2-5.7.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libturbojpeg0-debuginfo-8.1.2-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libjpeg8-32bit-8.1.2-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libjpeg8-32bit-debuginfo-8.1.2-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libjpeg-turbo-1.5.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libjpeg-turbo-debuginfo-1.5.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libjpeg-turbo-debugsource-1.5.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libjpeg62-62.2.0-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libjpeg62-debuginfo-62.2.0-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libjpeg62-devel-62.2.0-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libjpeg62-turbo-1.5.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libjpeg62-turbo-debugsource-1.5.3-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libjpeg8-8.1.2-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libjpeg8-debuginfo-8.1.2-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libjpeg8-devel-8.1.2-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libturbojpeg0-8.1.2-5.7.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libturbojpeg0-debuginfo-8.1.2-5.7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjpeg-turbo");
}
