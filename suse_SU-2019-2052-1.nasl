#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2052-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(127767);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/06");

  script_cve_id("CVE-2019-1010006");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : evince (SUSE-SU-2019:2052-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for evince fixes the following issues :

CVE-2019-1010006: Fixed a buffer overflow in
backend/tiff/tiff-document.c (bsc#1141619).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1141619");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1010006/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192052-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ced62d67");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2052=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-2052=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1:zypper in
-t patch SUSE-SLE-Module-Desktop-Applications-15-SP1-2019-2052=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-2052=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1010006");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-comicsdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-comicsdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-djvudocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-djvudocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-dvidocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-dvidocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-pdfdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-pdfdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-psdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-psdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-tiffdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-tiffdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-xpsdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:evince-plugin-xpsdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libevdocument3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libevdocument3-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libevview3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libevview3-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nautilus-evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nautilus-evince-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-EvinceDocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-EvinceView");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-debugsource-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-devel-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-plugin-comicsdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-plugin-comicsdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-plugin-djvudocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-plugin-djvudocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-plugin-dvidocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-plugin-dvidocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-plugin-pdfdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-plugin-pdfdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-plugin-psdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-plugin-psdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-plugin-tiffdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-plugin-tiffdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-plugin-xpsdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"evince-plugin-xpsdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libevdocument3-4-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libevdocument3-4-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libevview3-3-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libevview3-3-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nautilus-evince-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nautilus-evince-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-EvinceDocument-3_0-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"typelib-1_0-EvinceView-3_0-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-debugsource-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-devel-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-plugin-comicsdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-plugin-comicsdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-plugin-djvudocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-plugin-djvudocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-plugin-dvidocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-plugin-dvidocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-plugin-pdfdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-plugin-pdfdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-plugin-psdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-plugin-psdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-plugin-tiffdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-plugin-tiffdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-plugin-xpsdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"evince-plugin-xpsdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libevdocument3-4-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libevdocument3-4-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libevview3-3-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libevview3-3-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nautilus-evince-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nautilus-evince-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"typelib-1_0-EvinceDocument-3_0-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"typelib-1_0-EvinceView-3_0-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-debugsource-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-devel-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-plugin-comicsdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-plugin-comicsdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-plugin-djvudocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-plugin-djvudocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-plugin-dvidocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-plugin-dvidocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-plugin-pdfdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-plugin-pdfdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-plugin-psdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-plugin-psdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-plugin-tiffdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-plugin-tiffdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-plugin-xpsdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"evince-plugin-xpsdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libevdocument3-4-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libevdocument3-4-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libevview3-3-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libevview3-3-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nautilus-evince-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"nautilus-evince-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"typelib-1_0-EvinceDocument-3_0-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"typelib-1_0-EvinceView-3_0-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-debugsource-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-devel-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-plugin-comicsdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-plugin-comicsdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-plugin-djvudocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-plugin-djvudocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-plugin-dvidocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-plugin-dvidocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-plugin-pdfdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-plugin-pdfdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-plugin-psdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-plugin-psdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-plugin-tiffdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-plugin-tiffdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-plugin-xpsdocument-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"evince-plugin-xpsdocument-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libevdocument3-4-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libevdocument3-4-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libevview3-3-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libevview3-3-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nautilus-evince-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nautilus-evince-debuginfo-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"typelib-1_0-EvinceDocument-3_0-3.26.0+20180128.1bd86963-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"typelib-1_0-EvinceView-3_0-3.26.0+20180128.1bd86963-4.10.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evince");
}
