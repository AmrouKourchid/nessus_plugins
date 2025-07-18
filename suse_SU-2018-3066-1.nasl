#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3066-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(117993);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/31");

  script_cve_id(
    "CVE-2017-11624",
    "CVE-2017-11625",
    "CVE-2017-11626",
    "CVE-2017-11627",
    "CVE-2017-12595",
    "CVE-2017-9208",
    "CVE-2017-9209",
    "CVE-2017-9210"
  );

  script_name(english:"SUSE SLED12 / SLES12 Security Update : qpdf (SUSE-SU-2018:3066-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for qpdf fixes the following issues :

qpdf was updated to 7.1.1.

Security issues fixed :

CVE-2017-11627: A stack-consumption vulnerability which allows
attackers to cause DoS (bsc#1050577).

CVE-2017-11625: A stack-consumption vulnerability which allows
attackers to cause DoS (bsc#1050579).

CVE-2017-11626: A stack-consumption vulnerability which allows
attackers to cause DoS (bsc#1050578).

CVE-2017-11624: A stack-consumption vulnerability which allows
attackers to cause DoS (bsc#1050581).

CVE-2017-12595: Stack overflow when processing deeply nested arrays
and dictionaries (bsc#1055960).

CVE-2017-9209: Remote attackers can cause a denial of service
(infinite recursion and stack consumption) via a crafted PDF document
(bsc#1040312).

CVE-2017-9210: Remote attackers can cause a denial of service
(infinite recursion and stack consumption) via a crafted PDF document
(bsc#1040313).

CVE-2017-9208: Remote attackers can cause a denial of service
(infinite recursion and stack consumption) via a crafted PDF document
(bsc#1040311).

  - Check release notes for detailed bug fixes.

  - http://qpdf.sourceforge.net/files/qpdf-manual.html#ref.release-notes

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"http://qpdf.sourceforge.net/files/qpdf-manual.html#ref.release-notes");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1040311");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1040312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1040313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1050577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1050578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1050579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1050581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1055960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-11624/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-11625/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-11626/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-11627/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12595/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-9208/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-9209/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-9210/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183066-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?787b25b4");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-2169=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-2169=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-2169=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-2169=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-2169=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-2169=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-2169=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-2169=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-2169=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-2169=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12595");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-cups-browsed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-cups-browsed-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-foomatic-rip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-foomatic-rip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-filters-ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqpdf18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libqpdf18-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qpdf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qpdf-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1|2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"cups-filters-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"cups-filters-cups-browsed-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"cups-filters-cups-browsed-debuginfo-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"cups-filters-debuginfo-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"cups-filters-debugsource-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"cups-filters-foomatic-rip-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"cups-filters-foomatic-rip-debuginfo-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"cups-filters-ghostscript-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"cups-filters-ghostscript-debuginfo-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libqpdf18-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libqpdf18-debuginfo-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qpdf-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qpdf-debuginfo-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qpdf-debugsource-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-cups-browsed-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-cups-browsed-debuginfo-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-debuginfo-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-debugsource-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-foomatic-rip-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-foomatic-rip-debuginfo-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-ghostscript-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cups-filters-ghostscript-debuginfo-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqpdf18-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libqpdf18-debuginfo-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qpdf-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qpdf-debuginfo-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"qpdf-debugsource-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"cups-filters-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"cups-filters-cups-browsed-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"cups-filters-cups-browsed-debuginfo-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"cups-filters-debuginfo-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"cups-filters-debugsource-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"cups-filters-foomatic-rip-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"cups-filters-foomatic-rip-debuginfo-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"cups-filters-ghostscript-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"cups-filters-ghostscript-debuginfo-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqpdf18-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libqpdf18-debuginfo-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qpdf-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qpdf-debuginfo-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"qpdf-debugsource-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"cups-filters-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"cups-filters-cups-browsed-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"cups-filters-cups-browsed-debuginfo-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"cups-filters-debuginfo-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"cups-filters-debugsource-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"cups-filters-foomatic-rip-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"cups-filters-foomatic-rip-debuginfo-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"cups-filters-ghostscript-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"cups-filters-ghostscript-debuginfo-1.0.58-15.2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libqpdf18-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libqpdf18-debuginfo-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qpdf-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qpdf-debuginfo-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"qpdf-debugsource-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"cups-filters-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"cups-filters-cups-browsed-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"cups-filters-cups-browsed-debuginfo-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"cups-filters-debuginfo-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"cups-filters-debugsource-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"cups-filters-foomatic-rip-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"cups-filters-foomatic-rip-debuginfo-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"cups-filters-ghostscript-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"cups-filters-ghostscript-debuginfo-1.0.58-19.2.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqpdf18-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libqpdf18-debuginfo-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"qpdf-debuginfo-7.1.1-3.3.4")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"qpdf-debugsource-7.1.1-3.3.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qpdf");
}
