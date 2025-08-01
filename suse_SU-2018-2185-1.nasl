#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2185-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(111546);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/26");

  script_cve_id(
    "CVE-2017-12132",
    "CVE-2017-15670",
    "CVE-2017-15671",
    "CVE-2017-15804",
    "CVE-2018-11236"
  );

  script_name(english:"SUSE SLES12 Security Update : glibc (SUSE-SU-2018:2185-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for glibc fixes the following issues: Security issues
fixed :

  - CVE-2017-15804: Fix buffer overflow during unescaping of
    user names in the glob function in glob.c (bsc#1064580).

  - CVE-2017-15670: Fix buffer overflow in glob with
    GLOB_TILDE (bsc#1064583).

  - CVE-2017-15671: Fix memory leak in glob with GLOB_TILDE
    (bsc#1064569).

  - CVE-2018-11236: Fix 32bit arch integer overflow in
    stdlib/canonicalize.c when processing very long pathname
    arguments (bsc#1094161).

  - CVE-2017-12132: Reduce advertised EDNS0 buffer size to
    guard against fragmentation attacks (bsc#1051791).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1051791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1064569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1064580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1064583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1094161");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12132/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-15670/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-15671/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-15804/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-11236/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182185-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34ad4f10");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2018-1482=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-1482=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11236");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/06");

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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-32bit-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-debuginfo-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-debuginfo-32bit-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-debugsource-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-devel-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-devel-32bit-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-devel-debuginfo-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-devel-debuginfo-32bit-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-locale-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-locale-32bit-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-locale-debuginfo-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-locale-debuginfo-32bit-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-profile-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-profile-32bit-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"nscd-2.19-40.16.950")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"nscd-debuginfo-2.19-40.16.950")) flag++;


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
