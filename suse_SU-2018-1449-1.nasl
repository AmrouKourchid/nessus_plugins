#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1449-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110187);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/30");

  script_cve_id("CVE-2015-3152", "CVE-2017-10788", "CVE-2017-10789");
  script_bugtraq_id(74398);

  script_name(english:"SUSE SLES11 Security Update : perl-DBD-mysql (SUSE-SU-2018:1449-1) (BACKRONYM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for perl-DBD-mysql fixes the following issues :

  - CVE-2017-10789: The DBD::mysql module when with
    mysql_ssl=1 setting enabled, means that SSL is optional
    (even though this setting's documentation has a \'your
    communication with the server will be encrypted\'
    statement), which could lead man-in-the-middle attackers
    to spoof servers via a cleartext-downgrade attack, a
    related issue to CVE-2015-3152. (bsc#1047059)

  - CVE-2017-10788: The DBD::mysql module through 4.043 for
    Perl allows remote attackers to cause a denial of
    service (use-after-free and application crash) or
    possibly have unspecified other impact by triggering (1)
    certain error responses from a MySQL server or (2) a
    loss of a network connection to a MySQL server. The
    use-after-free defect was introduced by relying on
    incorrect Oracle mysql_stmt_close documentation and code
    examples. (bsc#1047095)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1047059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1047095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-10788/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-10789/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181449-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62c15af6");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-perl-DBD-mysql-13625=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-perl-DBD-mysql-13625=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-perl-DBD-mysql-13625=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10788");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-DBD-mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"perl-DBD-mysql-4.008-10.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-DBD-mysql");
}
