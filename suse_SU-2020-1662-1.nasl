#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1662-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(138271);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/01");

  script_cve_id("CVE-2020-10543", "CVE-2020-10878", "CVE-2020-12723");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"SUSE SLES12 Security Update : perl (SUSE-SU-2020:1662-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for perl fixes the following issues :

CVE-2020-10543: Fixed a heap buffer overflow in regular expression
compiler which could have allowed overwriting of allocated memory with
attacker's data (bsc#1171863).

CVE-2020-10878: Fixed multiple integer overflows which could have
allowed the insertion of instructions into the compiled form of Perl
regular expression (bsc#1171864).

CVE-2020-12723: Fixed an attacker's corruption of the intermediate
language state of a compiled regular expression (bsc#1171866).

Fixed utf8 handling in perldoc by useing 'term' instead of 'man'
(bsc#1170601).

Some packages make assumptions about the date and time they are built.
This update will solve the issues caused by calling the perl function
timelocal expressing the year with two digit only instead of four
digits. (bsc#1102840) (bsc#1160039)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1102840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1160039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1170601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1171866");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10543/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10878/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12723/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201662-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e9f5f6e");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8 :

zypper in -t patch SUSE-OpenStack-Cloud-Crowbar-8-2020-1662=1

SUSE OpenStack Cloud 8 :

zypper in -t patch SUSE-OpenStack-Cloud-8-2020-1662=1

SUSE OpenStack Cloud 7 :

zypper in -t patch SUSE-OpenStack-Cloud-7-2020-1662=1

SUSE Linux Enterprise Server for SAP 12-SP3 :

zypper in -t patch SUSE-SLE-SAP-12-SP3-2020-1662=1

SUSE Linux Enterprise Server for SAP 12-SP2 :

zypper in -t patch SUSE-SLE-SAP-12-SP2-2020-1662=1

SUSE Linux Enterprise Server 12-SP5 :

zypper in -t patch SUSE-SLE-SERVER-12-SP5-2020-1662=1

SUSE Linux Enterprise Server 12-SP4 :

zypper in -t patch SUSE-SLE-SERVER-12-SP4-2020-1662=1

SUSE Linux Enterprise Server 12-SP3-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-2020-1662=1

SUSE Linux Enterprise Server 12-SP3-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP3-BCL-2020-1662=1

SUSE Linux Enterprise Server 12-SP2-LTSS :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-2020-1662=1

SUSE Linux Enterprise Server 12-SP2-BCL :

zypper in -t patch SUSE-SLE-SERVER-12-SP2-BCL-2020-1662=1

SUSE Enterprise Storage 5 :

zypper in -t patch SUSE-Storage-5-2020-1662=1

HPE Helion Openstack 8 :

zypper in -t patch HPE-Helion-OpenStack-8-2020-1662=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10878");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"perl-32bit-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"perl-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"perl-base-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"perl-base-debuginfo-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"perl-debuginfo-32bit-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"perl-debuginfo-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"perl-debugsource-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-32bit-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-base-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-base-debuginfo-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-debuginfo-32bit-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-debuginfo-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"perl-debugsource-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-32bit-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-base-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-base-debuginfo-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-debuginfo-32bit-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-debuginfo-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"perl-debugsource-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"perl-32bit-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"perl-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"perl-base-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"perl-base-debuginfo-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"perl-debuginfo-32bit-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"perl-debuginfo-5.18.2-12.23.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"perl-debugsource-5.18.2-12.23.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl");
}
