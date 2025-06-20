#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1645-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(126168);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2017-2579", "CVE-2017-2580", "CVE-2018-8975");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : netpbm (SUSE-SU-2019:1645-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for netpbm fixes the following issues :

Security issues fixed :

CVE-2018-8975: The pm_mallocarray2 function allowed remote attackers
to cause a denial of service (heap-based buffer over-read) via a
crafted image file (bsc#1086777).

CVE-2017-2579: Fixed out-of-bounds read in expandCodeOntoStack()
(bsc#1024288).

CVE-2017-2580: Fixed out-of-bounds write of heap data in
addPixelToRaster() function (bsc#1024291).

create netpbm-vulnerable subpackage and move pstopnm there
(bsc#1136936)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1024288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1024291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1086777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1136936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-2579/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-2580/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-8975/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191645-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?843dad7f");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-1645=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2019-1645=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-1645=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-1645=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-1645=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2019-1645=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2580");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetpbm11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetpbm11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netpbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netpbm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:netpbm-debugsource");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3/4", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnetpbm11-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnetpbm11-32bit-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnetpbm11-debuginfo-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libnetpbm11-debuginfo-32bit-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"netpbm-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"netpbm-debuginfo-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"netpbm-debugsource-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetpbm11-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetpbm11-32bit-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetpbm11-debuginfo-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetpbm11-debuginfo-32bit-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"netpbm-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"netpbm-debuginfo-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"netpbm-debugsource-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libnetpbm11-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libnetpbm11-32bit-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libnetpbm11-debuginfo-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libnetpbm11-debuginfo-32bit-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"netpbm-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"netpbm-debuginfo-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"netpbm-debugsource-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libnetpbm11-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libnetpbm11-32bit-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libnetpbm11-debuginfo-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libnetpbm11-debuginfo-32bit-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"netpbm-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"netpbm-debuginfo-10.66.3-8.7.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"netpbm-debugsource-10.66.3-8.7.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "netpbm");
}
