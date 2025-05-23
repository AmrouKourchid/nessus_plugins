#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2236-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(120073);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/11");

  script_cve_id("CVE-2017-18199", "CVE-2017-18201");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : libcdio (SUSE-SU-2018:2236-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for libcdio fixes the following issues: The following
security vulnerabilities were addressed :

  - CVE-2017-18199: Fixed a NULL pointer dereference in
    realloc_symlink in rock.c (bsc#1082821)

  - CVE-2017-18201: Fixed a double free vulnerability in
    get_cdtext_generic() in _cdio_generic.c (bsc#1082877)

  - Fixed several memory leaks (bsc#1082821)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082877");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-18199/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-18201/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182236-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65aeacdc");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2018-1512=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18201");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcdio++0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcdio++0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcdio-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcdio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcdio16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcdio16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libiso9660");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libiso9660-10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libudf0-debuginfo");
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
if (rpm_check(release:"SLES15", sp:"0", reference:"libcdio++0-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcdio++0-debuginfo-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcdio-debugsource-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcdio-devel-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcdio16-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcdio16-debuginfo-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libiso9660-10-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libiso9660-10-debuginfo-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudf0-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libudf0-debuginfo-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcdio++0-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcdio++0-debuginfo-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcdio-debugsource-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcdio-devel-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcdio16-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcdio16-debuginfo-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libiso9660-10-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libiso9660-10-debuginfo-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudf0-0.94-6.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libudf0-debuginfo-0.94-6.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcdio");
}
