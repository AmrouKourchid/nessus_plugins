#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2730-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(130145);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/17");

  script_cve_id(
    "CVE-2018-1122",
    "CVE-2018-1123",
    "CVE-2018-1124",
    "CVE-2018-1125",
    "CVE-2018-1126"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : procps (SUSE-SU-2019:2730-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for procps fixes the following issues :

procps was updated to 3.3.15. (bsc#1092100)

Following security issues were fixed :

CVE-2018-1122: Prevent local privilege escalation in top. If a user
ran top with HOME unset in an attacker-controlled directory, the
attacker could have achieved privilege escalation by exploiting one of
several vulnerabilities in the config_file() function (bsc#1092100).

CVE-2018-1123: Prevent denial of service in ps via mmap buffer
overflow. Inbuilt protection in ps maped a guard page at the end of
the overflowed buffer, ensuring that the impact of this flaw is
limited to a crash (temporary denial of service) (bsc#1092100).

CVE-2018-1124: Prevent multiple integer overflows leading to a heap
corruption in file2strvec function. This allowed a privilege
escalation for a local attacker who can create entries in procfs by
starting processes, which could result in crashes or arbitrary code
execution in proc utilities run by other users (bsc#1092100).

CVE-2018-1125: Prevent stack-based buffer overflow in pgrep. This
vulnerability was mitigated by FORTIFY limiting the impact to a crash
(bsc#1092100).

CVE-2018-1126: Ensure correct integer size in proc/alloc.* to prevent
truncation/integer overflow issues (bsc#1092100).

Also 

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1092100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1121753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1122/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1123/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1124/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1125/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1126/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192730-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6d6148b");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-2730=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-2730=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1126");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libprocps7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libprocps7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:procps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:procps-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:procps-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:procps-devel");
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
if (rpm_check(release:"SLES15", sp:"1", reference:"libprocps7-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libprocps7-debuginfo-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"procps-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"procps-debuginfo-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"procps-debugsource-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"procps-devel-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libprocps7-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libprocps7-debuginfo-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"procps-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"procps-debuginfo-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"procps-debugsource-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"procps-devel-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libprocps7-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libprocps7-debuginfo-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"procps-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"procps-debuginfo-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"procps-debugsource-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"procps-devel-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libprocps7-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libprocps7-debuginfo-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"procps-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"procps-debuginfo-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"procps-debugsource-3.3.15-7.7.26")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"procps-devel-3.3.15-7.7.26")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "procps");
}
