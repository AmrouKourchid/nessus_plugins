#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0482-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(122446);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/18");

  script_cve_id("CVE-2018-14647", "CVE-2019-5010");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : python (SUSE-SU-2019:0482-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for python fixes the following issues :

Security issues fixed :

CVE-2019-5010: Fixed a denial-of-service vulnerability in the X509
certificate parser (bsc#1122191).

CVE-2018-14647: Fixed a denial-of-service vulnerability in Expat
(bsc#1109847).

Non-security issue fixed: Fixed a bug where PyWeakReference struct was
not initialized correctly leading to a crash (bsc#1073748).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1073748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1109847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1122191");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14647/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-5010/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190482-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d7e1e60");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2019-482=1

SUSE Linux Enterprise Workstation Extension 12-SP4:zypper in -t patch
SUSE-SLE-WE-12-SP4-2019-482=1

SUSE Linux Enterprise Workstation Extension 12-SP3:zypper in -t patch
SUSE-SLE-WE-12-SP3-2019-482=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-482=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2019-482=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-482=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-482=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-482=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-482=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-482=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2019-482=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-482=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2019-482=1

SUSE Enterprise Storage 5:zypper in -t patch SUSE-Storage-5-2019-482=1

SUSE Enterprise Storage 4:zypper in -t patch SUSE-Storage-4-2019-482=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2019-482=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5010");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython2_7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython2_7-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpython2_7-1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-base-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-gdbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-gdbm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-xml-debuginfo");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(1|2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2/3/4", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython2_7-1_0-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython2_7-1_0-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython2_7-1_0-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-base-debugsource-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-curses-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-curses-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-debugsource-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-demo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-devel-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-gdbm-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-gdbm-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-idle-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-tk-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-tk-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-xml-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"python-xml-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpython2_7-1_0-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpython2_7-1_0-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpython2_7-1_0-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-base-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-base-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-base-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-base-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-base-debugsource-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-curses-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-curses-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-debugsource-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-demo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-gdbm-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-gdbm-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-idle-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-tk-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-tk-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-xml-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-xml-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpython2_7-1_0-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpython2_7-1_0-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpython2_7-1_0-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-base-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-base-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-base-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-base-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-base-debugsource-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-curses-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-curses-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-debugsource-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-demo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-gdbm-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-gdbm-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-idle-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-tk-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-tk-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-xml-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-xml-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpython2_7-1_0-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpython2_7-1_0-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpython2_7-1_0-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-base-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-base-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-base-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-base-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-base-debugsource-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-curses-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-curses-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-debugsource-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-demo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-gdbm-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-gdbm-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-idle-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-tk-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-tk-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-xml-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"python-xml-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libpython2_7-1_0-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libpython2_7-1_0-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libpython2_7-1_0-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-base-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-base-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-base-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-base-debugsource-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-curses-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-curses-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-debugsource-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-devel-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-tk-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-tk-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-xml-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-xml-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpython2_7-1_0-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpython2_7-1_0-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpython2_7-1_0-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libpython2_7-1_0-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-base-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-base-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-base-debuginfo-32bit-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-base-debugsource-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-curses-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-curses-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-debugsource-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-devel-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-tk-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-tk-debuginfo-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-xml-2.7.13-28.21.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-xml-debuginfo-2.7.13-28.21.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");
}
