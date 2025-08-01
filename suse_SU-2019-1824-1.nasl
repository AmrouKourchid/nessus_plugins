#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1824-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(126689);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/10");

  script_cve_id("CVE-2019-13012");

  script_name(english:"SUSE SLES12 Security Update : glib2 (SUSE-SU-2019:1824-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for glib2 fixes the following issues :

Security issue fixed :

CVE-2019-13012: Fixed improper restriction of file permissions when
creating directories (bsc#1139959).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1139959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-13012/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191824-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0e1f5fb");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2019-1824=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2019-1824=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2019-1824=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13012");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glib2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glib2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glib2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgio-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgio-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgio-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libglib-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libglib-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libglib-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgmodule-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgmodule-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgmodule-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgobject-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgobject-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgobject-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgthread-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgthread-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgthread-2_0-0-debuginfo");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"glib2-debugsource-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glib2-tools-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glib2-tools-debuginfo-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgio-2_0-0-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgio-2_0-0-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgio-2_0-0-debuginfo-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgio-2_0-0-debuginfo-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libglib-2_0-0-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libglib-2_0-0-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libglib-2_0-0-debuginfo-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libglib-2_0-0-debuginfo-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgmodule-2_0-0-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgmodule-2_0-0-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgmodule-2_0-0-debuginfo-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgmodule-2_0-0-debuginfo-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgobject-2_0-0-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgobject-2_0-0-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgobject-2_0-0-debuginfo-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgobject-2_0-0-debuginfo-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgthread-2_0-0-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgthread-2_0-0-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgthread-2_0-0-debuginfo-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgthread-2_0-0-debuginfo-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glib2-debugsource-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glib2-tools-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glib2-tools-debuginfo-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgio-2_0-0-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgio-2_0-0-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgio-2_0-0-debuginfo-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgio-2_0-0-debuginfo-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libglib-2_0-0-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libglib-2_0-0-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libglib-2_0-0-debuginfo-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libglib-2_0-0-debuginfo-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgmodule-2_0-0-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgmodule-2_0-0-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgmodule-2_0-0-debuginfo-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgmodule-2_0-0-debuginfo-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgobject-2_0-0-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgobject-2_0-0-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgobject-2_0-0-debuginfo-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgobject-2_0-0-debuginfo-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgthread-2_0-0-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgthread-2_0-0-32bit-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgthread-2_0-0-debuginfo-2.38.2-7.12.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgthread-2_0-0-debuginfo-32bit-2.38.2-7.12.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glib2");
}
