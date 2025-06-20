#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0770-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(123446);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/07");

  script_cve_id(
    "CVE-2018-20544",
    "CVE-2018-20545",
    "CVE-2018-20546",
    "CVE-2018-20547",
    "CVE-2018-20548",
    "CVE-2018-20549"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libcaca (SUSE-SU-2019:0770-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for libcaca fixes the following issues :

Security issues fixed :

CVE-2018-20544: Fixed a floating point exception at caca/dither.c
(bsc#1120502)

CVE-2018-20545: Fixed a WRITE memory access in the load_image function
at common-image.c for 4bpp (bsc#1120584)

CVE-2018-20546: Fixed a READ memory access in the get_rgba_default
function at caca/dither.c for bpp (bsc#1120503)

CVE-2018-20547: Fixed a READ memory access in the get_rgba_default
function at caca/dither.c for 24bpp (bsc#1120504)

CVE-2018-20548: Fixed a WRITE memory access in the load_image function
at common-image.c for 1bpp (bsc#1120589)

CVE-2018-20549: Fixed a WRITE memory access in the caca_file_read
function at caca/file.c (bsc#1120470)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1120470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1120502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1120503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1120504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1120584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1120589");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20544/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20545/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20546/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20547/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20548/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20549/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190770-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d42d236");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15:zypper in -t
patch SUSE-SLE-Module-Server-Applications-15-2019-770=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-770=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20549");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:caca-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:caca-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcaca-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcaca-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcaca-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcaca-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcaca0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcaca0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcaca0-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcaca0-plugins-debuginfo");
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
if (rpm_check(release:"SLES15", sp:"0", reference:"caca-utils-0.99.beta19.git20171003-3.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"caca-utils-debuginfo-0.99.beta19.git20171003-3.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcaca-debugsource-0.99.beta19.git20171003-3.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcaca-devel-0.99.beta19.git20171003-3.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcaca-ruby-0.99.beta19.git20171003-3.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcaca-ruby-debuginfo-0.99.beta19.git20171003-3.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcaca0-0.99.beta19.git20171003-3.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcaca0-debuginfo-0.99.beta19.git20171003-3.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcaca0-plugins-0.99.beta19.git20171003-3.3.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcaca0-plugins-debuginfo-0.99.beta19.git20171003-3.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"caca-utils-0.99.beta19.git20171003-3.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"caca-utils-debuginfo-0.99.beta19.git20171003-3.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcaca-debugsource-0.99.beta19.git20171003-3.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcaca-ruby-0.99.beta19.git20171003-3.3.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcaca-ruby-debuginfo-0.99.beta19.git20171003-3.3.7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcaca");
}
