#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0786-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(123497);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/07");

  script_cve_id(
    "CVE-2018-17000",
    "CVE-2018-19210",
    "CVE-2019-6128",
    "CVE-2019-7663"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : tiff (SUSE-SU-2019:0786-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for tiff fixes the following issues :

Security issues fixed :

CVE-2018-19210: Fixed a NULL pointer dereference in
TIFFWriteDirectorySec function (bsc#1115717).

CVE-2018-17000: Fixed a NULL pointer dereference in the _TIFFmemcmp
function (bsc#1108606).

CVE-2019-6128: Fixed a memory leak in the TIFFFdOpen function in
tif_unix.c (bsc#1121626).

CVE-2019-7663: Fixed an invalid address dereference in the
TIFFWriteDirectoryTagTransfer function in libtiff/tif_dirwrite.c
(bsc#1125113)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1108606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1115717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1121626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1125113");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-17000/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19210/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-6128/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-7663/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190786-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38159a81");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Packagehub Subpackages 15:zypper in
-t patch SUSE-SLE-Module-Packagehub-Subpackages-15-2019-786=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-786=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-786=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-786=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6128");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtiff5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tiff-debugsource");
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
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtiff5-32bit-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtiff5-32bit-debuginfo-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtiff-devel-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtiff5-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtiff5-debuginfo-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tiff-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tiff-debuginfo-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tiff-debugsource-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtiff5-32bit-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtiff5-32bit-debuginfo-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtiff-devel-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtiff5-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtiff5-debuginfo-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tiff-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tiff-debuginfo-4.0.9-5.27.5")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tiff-debugsource-4.0.9-5.27.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tiff");
}
