#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0143-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(133141);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/29");

  script_cve_id(
    "CVE-2019-2126",
    "CVE-2019-9232",
    "CVE-2019-9325",
    "CVE-2019-9371",
    "CVE-2019-9433"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libvpx (SUSE-SU-2020:0143-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for libvpx fixes the following issues :

CVE-2019-2126: Fixed a double free in ParseContentEncodingEntry()
(bsc#1160611).

CVE-2019-9325: Fixed an out-of-bounds read (bsc#1160612).

CVE-2019-9232: Fixed an out-of-bounds memory access on fuzzed data
(bsc#1160613).

CVE-2019-9433: Fixed a use-after-free in vp8_deblock() (bsc#1160614).

CVE-2019-9371: Fixed a resource exhaustion after memory leak
(bsc#1160615).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1160611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1160612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1160613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1160614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1160615");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-2126/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9232/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9325/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9371/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9433/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200143-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f480294");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-143=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-143=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-2020-143=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-143=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15 :

zypper in -t patch SUSE-SLE-Module-Development-Tools-OBS-15-2020-143=1

SUSE Linux Enterprise Module for Desktop Applications 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Desktop-Applications-15-SP1-2020-143=1

SUSE Linux Enterprise Module for Desktop Applications 15 :

zypper in -t patch SUSE-SLE-Module-Desktop-Applications-15-2020-143=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-143=1

SUSE Linux Enterprise Module for Basesystem 15 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-2020-143=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-143=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-143=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2126");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvpx-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvpx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvpx4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvpx4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvpx4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:vpx-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:vpx-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libvpx4-32bit-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libvpx4-32bit-debuginfo-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libvpx-debugsource-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libvpx-devel-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libvpx4-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libvpx4-debuginfo-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"vpx-tools-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"vpx-tools-debuginfo-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libvpx4-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"libvpx4-debuginfo-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvpx-debugsource-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libvpx-devel-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"vpx-tools-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"vpx-tools-debuginfo-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libvpx4-32bit-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libvpx4-32bit-debuginfo-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libvpx-debugsource-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libvpx-devel-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libvpx4-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libvpx4-debuginfo-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"vpx-tools-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"vpx-tools-debuginfo-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libvpx-debugsource-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libvpx-devel-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"vpx-tools-1.6.1-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"vpx-tools-debuginfo-1.6.1-6.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvpx");
}
