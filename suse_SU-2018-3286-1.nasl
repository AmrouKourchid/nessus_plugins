#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3286-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(118319);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/29");

  script_cve_id("CVE-2017-7500", "CVE-2017-7501");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : rpm (SUSE-SU-2018:3286-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for rpm fixes the following issues :

These security issues were fixed :

CVE-2017-7500: rpm did not properly handle RPM installations when a
destination path was a symbolic link to a directory, possibly changing
ownership and permissions of an arbitrary directory, and RPM files
being placed in an arbitrary destination (bsc#943457).

CVE-2017-7501: rpm used temporary files with predictable names when
installing an RPM. An attacker with ability to write in a directory
where files will be installed could create symbolic links to an
arbitrary location and modify content, and possibly permissions to
arbitrary files, which could be used for denial of service or possibly
privilege escalation (bsc#943457)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1077692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=943457");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-7500/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-7501/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183286-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dad02b1f");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-2373=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-2373=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-2373=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2018-2373=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7500");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-7501");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rpm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rpm-build-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rpm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rpm-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rpm-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rpm-python-debugsource");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"python3-rpm-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python3-rpm-debuginfo-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python3-rpm-debugsource-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"rpm-32bit-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"rpm-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"rpm-build-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"rpm-build-debuginfo-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"rpm-debuginfo-32bit-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"rpm-debuginfo-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"rpm-debugsource-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"rpm-python-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"rpm-python-debuginfo-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"rpm-python-debugsource-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"rpm-32bit-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"rpm-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"rpm-build-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"rpm-build-debuginfo-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"rpm-debuginfo-32bit-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"rpm-debuginfo-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"rpm-debugsource-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"rpm-python-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"rpm-python-debuginfo-4.11.2-16.16.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"rpm-python-debugsource-4.11.2-16.16.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rpm");
}
