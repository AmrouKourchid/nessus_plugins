#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1972-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(111150);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/04");

  script_cve_id(
    "CVE-2018-12015",
    "CVE-2018-6797",
    "CVE-2018-6798",
    "CVE-2018-6913"
  );
  script_xref(name:"IAVA", value:"2018-A-0407-S");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : perl (SUSE-SU-2018:1972-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for perl fixes the following issues: These security issue
were fixed :

  - CVE-2018-6913: Fixed space calculation issues in
    pp_pack.c (bsc#1082216).

  - CVE-2018-6798: Fixed heap buffer overflow in regexec.c
    (bsc#1082233).

  - CVE-2018-6797: Fixed sharp-s regexp overflow
    (bsc#1082234).

  - CVE-2018-12015: The Archive::Tar module allowed remote
    attackers to bypass a directory-traversal protection
    mechanism and overwrite arbitrary files (bsc#1096718)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1068565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082234");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1096718");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-12015/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-6797/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-6798/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-6913/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181972-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?665bd71d");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-1328=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-1328=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-1328=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-1328=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-1328=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-1328=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-1328=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-1328=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-1328=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2018-1328=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6913");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (rpm_check(release:"SLES12", sp:"1", reference:"perl-32bit-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"perl-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"perl-base-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"perl-base-debuginfo-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"perl-debuginfo-32bit-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"perl-debuginfo-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"perl-debugsource-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"perl-32bit-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"perl-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"perl-base-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"perl-base-debuginfo-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"perl-debuginfo-32bit-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"perl-debuginfo-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"perl-debugsource-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-32bit-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-base-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-base-debuginfo-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-debuginfo-32bit-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-debuginfo-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-debugsource-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-32bit-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-base-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-base-debuginfo-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-debuginfo-32bit-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-debuginfo-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-debugsource-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"perl-32bit-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"perl-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"perl-base-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"perl-base-debuginfo-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"perl-debuginfo-32bit-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"perl-debuginfo-5.18.2-12.14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"perl-debugsource-5.18.2-12.14.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl");
}
