#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0776-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(147786);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/09");

  script_cve_id("CVE-2021-25316");

  script_name(english:"SUSE SLES12 Security Update : s390-tools (SUSE-SU-2021:0776-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for s390-tools fixes the following issues :

Fixed an issue where IPL was not working when bootloader was installed
on a SCSI disk with 4k physical blocksize without using a devicemapper
target (bsc#1183041).

CVE-2021-25316: Do not use predictable temporary file names
(bsc#1182777).

Made the name of the temporary configuration file in /tmp/
unpredictable (bsc#1182876).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1183041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25316/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210776-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd8078e4");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2021-776=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25316");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:osasnmpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:osasnmpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:s390-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:s390-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:s390-tools-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:s390-tools-hmcdrvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:s390-tools-hmcdrvfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:s390-tools-zdsfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:s390-tools-zdsfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (cpu >!< "s390x") audit(AUDIT_ARCH_NOT, "s390x", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"5", cpu:"s390x", reference:"osasnmpd-2.1.0-18.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"s390x", reference:"osasnmpd-debuginfo-2.1.0-18.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"s390x", reference:"s390-tools-2.1.0-18.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"s390x", reference:"s390-tools-debuginfo-2.1.0-18.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"s390x", reference:"s390-tools-debugsource-2.1.0-18.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"s390x", reference:"s390-tools-hmcdrvfs-2.1.0-18.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"s390x", reference:"s390-tools-hmcdrvfs-debuginfo-2.1.0-18.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"s390x", reference:"s390-tools-zdsfs-2.1.0-18.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", cpu:"s390x", reference:"s390-tools-zdsfs-debuginfo-2.1.0-18.29.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "s390-tools");
}
