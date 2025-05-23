#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1465-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91651);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_name(english:"SUSE SLES11 Security Update : Recommended update for NetworkManager-kde4 (SUSE-SU-2016:1465-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This NetworkManager-kde4 update fixes the following security and non
security issues :

  - Fixed a long standing security issue. This makes
    knetworkmanager probe the RADIUS server for a CA
    certificate subject and hash if no CA certificate is
    specified. knetworkmanager then stores this data and
    send it to NetworkManager for it to do a network
    validation in the absence of a real certificate
    (bsc#726349)

  - Disabled the loading by default of the NetworkManager
    plasma applet since it doesn't work.

  - Fixed a crash due to the use of an uninitialized
    variable in the plasma applet in case someone runs it
    manually (bsc#663413)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=663413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=726349");
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161465-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f39df6aa");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-NetworkManager-kde4-12590=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-NetworkManager-kde4-12590=1

To bring your system up-to-date, use 'zypper patch'.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:NetworkManager-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:NetworkManager-kde4-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:NetworkManager-kde4-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:NetworkManager-openvpn-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:NetworkManager-pptp-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:plasmoid-networkmanagement");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"NetworkManager-kde4-0.9.svn1043876-1.3.15")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"NetworkManager-kde4-lang-0.9.svn1043876-1.3.15")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"NetworkManager-kde4-libs-0.9.svn1043876-1.3.15")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"NetworkManager-openvpn-kde4-0.9.svn1043876-1.3.15")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"NetworkManager-pptp-kde4-0.9.svn1043876-1.3.15")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"plasmoid-networkmanagement-0.9.svn1043876-1.3.15")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"NetworkManager-kde4-0.9.svn1043876-1.3.15")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"NetworkManager-kde4-lang-0.9.svn1043876-1.3.15")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"NetworkManager-kde4-libs-0.9.svn1043876-1.3.15")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"NetworkManager-openvpn-kde4-0.9.svn1043876-1.3.15")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"NetworkManager-pptp-kde4-0.9.svn1043876-1.3.15")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"plasmoid-networkmanagement-0.9.svn1043876-1.3.15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Recommended update for NetworkManager-kde4");
}
