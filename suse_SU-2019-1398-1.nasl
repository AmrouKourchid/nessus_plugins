#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1398-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(125677);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/17");

  script_cve_id("CVE-2018-13785", "CVE-2019-7317");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libpng16 (SUSE-SU-2019:1398-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for libpng16 fixes the following issues :

Security issues fixed :

CVE-2019-7317: Fixed a use-after-free vulnerability, triggered when
png_image_free() was called under png_safe_execute (bsc#1124211).

CVE-2018-13785: Fixed a wrong calculation of row_factor in the
png_check_chunk_length function in pngrutil.c, which could haved
triggered and integer overflow and result in an divide-by-zero while
processing a crafted PNG file, leading to a denial of service
(bsc#1100687)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1100687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1121624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1124211");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-13785/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-7317/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191398-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34fb46c1");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-1398=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-1398=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13785");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpng16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpng16-16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpng16-16-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpng16-16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpng16-compat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpng16-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpng16-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpng16-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpng16-tools-debuginfo");
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
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libpng16-16-32bit-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libpng16-16-32bit-debuginfo-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpng16-16-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpng16-16-debuginfo-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpng16-compat-devel-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpng16-debugsource-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpng16-devel-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpng16-tools-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libpng16-tools-debuginfo-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libpng16-16-32bit-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libpng16-16-32bit-debuginfo-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpng16-16-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpng16-16-debuginfo-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpng16-compat-devel-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpng16-debugsource-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpng16-devel-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpng16-tools-1.6.34-3.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libpng16-tools-debuginfo-1.6.34-3.9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng16");
}
