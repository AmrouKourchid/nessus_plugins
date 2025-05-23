#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2872-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117803);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/01");

  script_cve_id("CVE-2018-16056", "CVE-2018-16057", "CVE-2018-16058");

  script_name(english:"SUSE SLES11 Security Update : wireshark (SUSE-SU-2018:2872-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for wireshark fixes the following issues :

Update wireshark to version 2.2.17 (bsc#1106514) :

Security issues fixed :

CVE-2018-16058: Bluetooth AVDTP dissector crash (wnpa-sec-2018-44)

CVE-2018-16056: Bluetooth Attribute Protocol dissector crash
(wnpa-sec-2018-45)

CVE-2018-16057: Radiotap dissector crash (wnpa-sec-2018-46)

Further bug fixes and updated protocol support as listed in:
https://www.wireshark.org/docs/relnotes/wireshark-2.2.17.html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1106514");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16056/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16057/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16058/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182872-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e697c513");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.2.17.html");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-wireshark-13792=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-wireshark-13792=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-wireshark-13792=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16058");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwscodecs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-gtk");
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
if (rpm_check(release:"SLES11", sp:"4", reference:"libwireshark8-2.2.17-40.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwiretap6-2.2.17-40.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwscodecs1-2.2.17-40.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libwsutil7-2.2.17-40.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"wireshark-2.2.17-40.31.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"wireshark-gtk-2.2.17-40.31.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
