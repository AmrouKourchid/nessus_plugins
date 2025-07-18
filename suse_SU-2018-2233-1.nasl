#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2233-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111592);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/23");

  script_cve_id(
    "CVE-2018-4180",
    "CVE-2018-4181",
    "CVE-2018-4182",
    "CVE-2018-4183"
  );

  script_name(english:"SUSE SLES11 Security Update : cups (SUSE-SU-2018:2233-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for cups fixes the following issues: Security issues 
fixed :

  - CVE-2018-4180: Fix local privilege escalation to root in
    dnssd backend (bsc#1096405).

  - CVE-2018-4181: Limited local file reads as root via
    cupsd.conf include directive (bsc#1096406).

  - CVE-2018-4182: Fix cups-exec sandbox bypass due to
    insecure error handling (bsc#1096407).

  - CVE-2018-4183: Fix cups-exec sandbox bypass due to
    profile misconfiguration (bsc#1096408).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1096405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1096406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1096407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1096408");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-4180/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-4181/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-4182/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-4183/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182233-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92f6927b");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-cups-13718=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-cups-13718=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-cups-13718=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-libs");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"cups-libs-32bit-1.3.9-8.46.56.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"cups-libs-32bit-1.3.9-8.46.56.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"cups-1.3.9-8.46.56.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"cups-client-1.3.9-8.46.56.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"cups-libs-1.3.9-8.46.56.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups");
}
