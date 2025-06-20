#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2265-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(128472);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/30");

  script_cve_id("CVE-2018-20532", "CVE-2018-20533", "CVE-2018-20534");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libsolv, libzypp, zypper (SUSE-SU-2019:2265-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for libsolv, libzypp and zypper fixes the following 
issues :

libsolv was updated to version 0.6.36 and fixes the following issues :

Security issues fixed :

CVE-2018-20532: Fixed a NULL pointer dereference in testcase_read()
(bsc#1120629).

CVE-2018-20533: Fixed a NULL pointer dereference in
testcase_str2dep_complex() (bsc#1120630).

CVE-2018-20534: Fixed a NULL pointer dereference in
pool_whatprovides() (bsc#1120631).

Non-security issues fixed: Made cleandeps jobs on patterns work
(bsc#1137977).

Fixed an issue multiversion packages that obsolete their own name
(bsc#1127155).

Keep consistent package name if there are multiple alternatives
(bsc#1131823).

Fixes for libzypp: Fixes a bug where locking the kernel was not
possible (bsc#1113296)

Fixes a file descriptor leak (bsc#1116995)

Will now run file conflict check on dry-run (best with download-only)
(bsc#1140039)

Fixes for zypper: Fixes a bug where the wrong exit code was set when
refreshing repos if

--root was used (bsc#1134226)

Improved the displaying of locks (bsc#1112911)

Fixes an issue where `https` repository urls caused an error prompt to
appear twice (bsc#1110542)

zypper will now always warn when no repositories are defined
(bsc#1109893)

Fixes bash completion option detection (bsc#1049825)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1049825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1109893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1110542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1111319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1112911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1113296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1116995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1120629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1120630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1120631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1127155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1131823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1134226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1137977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1140039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1145521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20532/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20533/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20534/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192265-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3353e05c");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8:zypper in -t patch
SUSE-OpenStack-Cloud-Crowbar-8-2019-2265=1

SUSE OpenStack Cloud 8:zypper in -t patch
SUSE-OpenStack-Cloud-8-2019-2265=1

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2019-2265=1

SUSE Linux Enterprise Server for SAP 12-SP3:zypper in -t patch
SUSE-SLE-SAP-12-SP3-2019-2265=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-2265=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-2265=1

SUSE Linux Enterprise Server 12-SP3-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-2265=1

SUSE Linux Enterprise Server 12-SP3-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-BCL-2019-2265=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-2265=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-2265=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-2265=1

SUSE Enterprise Storage 5:zypper in -t patch
SUSE-Storage-5-2019-2265=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2019-2265=1

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

HPE Helion Openstack 8:zypper in -t patch
HPE-Helion-OpenStack-8-2019-2265=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20534");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsolv-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libzypp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:zypper-debugsource");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsolv-debugsource-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsolv-tools-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsolv-tools-debuginfo-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libzypp-16.20.2-27.60.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libzypp-debuginfo-16.20.2-27.60.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libzypp-debugsource-16.20.2-27.60.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"perl-solv-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"perl-solv-debuginfo-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-solv-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-solv-debuginfo-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"zypper-1.13.54-18.40.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"zypper-debuginfo-1.13.54-18.40.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"zypper-debugsource-1.13.54-18.40.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsolv-debugsource-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsolv-tools-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsolv-tools-debuginfo-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libzypp-16.20.2-27.60.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libzypp-debuginfo-16.20.2-27.60.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libzypp-debugsource-16.20.2-27.60.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-solv-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-solv-debuginfo-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-solv-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-solv-debuginfo-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"zypper-1.13.54-18.40.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"zypper-debuginfo-1.13.54-18.40.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"zypper-debugsource-1.13.54-18.40.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsolv-debugsource-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsolv-tools-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libsolv-tools-debuginfo-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libzypp-16.20.2-27.60.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libzypp-debuginfo-16.20.2-27.60.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libzypp-debugsource-16.20.2-27.60.4")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-solv-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-solv-debuginfo-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-solv-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-solv-debuginfo-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"zypper-1.13.54-18.40.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"zypper-debuginfo-1.13.54-18.40.2")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"zypper-debugsource-1.13.54-18.40.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsolv-debugsource-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsolv-tools-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsolv-tools-debuginfo-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libzypp-16.20.2-27.60.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libzypp-debuginfo-16.20.2-27.60.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libzypp-debugsource-16.20.2-27.60.4")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-solv-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-solv-debuginfo-0.6.36-2.27.19.8")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"zypper-1.13.54-18.40.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"zypper-debuginfo-1.13.54-18.40.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"zypper-debugsource-1.13.54-18.40.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsolv / libzypp / zypper");
}
