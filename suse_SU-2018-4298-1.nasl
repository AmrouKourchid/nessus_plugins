#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:4298-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(119956);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/12");

  script_cve_id(
    "CVE-2018-19622",
    "CVE-2018-19623",
    "CVE-2018-19624",
    "CVE-2018-19625",
    "CVE-2018-19626",
    "CVE-2018-19627"
  );

  script_name(english:"SUSE SLED12 / SLES12 Security Update : wireshark (SUSE-SU-2018:4298-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for wireshark fixes the following issues :

Update to Wireshark 2.4.11 (bsc#1117740).

Security issues fixed :

CVE-2018-19625: The Wireshark dissection engine could crash
(wnpa-sec-2018-51)

CVE-2018-19626: The DCOM dissector could crash (wnpa-sec-2018-52)

CVE-2018-19623: The LBMPDM dissector could crash (wnpa-sec-2018-53)

CVE-2018-19622: The MMSE dissector could go into an infinite loop
(wnpa-sec-2018-54)

CVE-2018-19627: The IxVeriWave file parser could crash
(wnpa-sec-2018-55)

CVE-2018-19624: The PVFS dissector could crash (wnpa-sec-2018-56)

Further bug fixes and updated protocol support as listed in:
https://www.wireshark.org/docs/relnotes/wireshark-2.4.11.html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1117740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19622/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19623/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19624/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19625/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19626/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19627/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20184298-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ee98540");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.4.11.html");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2018-3067=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-3067=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2018-3067=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-3067=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2018-3067=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-3067=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19627");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwireshark9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwiretap7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwscodecs1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwscodecs1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwsutil8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wireshark-gtk-debuginfo");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3/4", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwireshark9-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwireshark9-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwiretap7-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwiretap7-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwscodecs1-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwscodecs1-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwsutil8-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libwsutil8-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"wireshark-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"wireshark-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"wireshark-debugsource-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"wireshark-gtk-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"wireshark-gtk-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwireshark9-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwireshark9-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwiretap7-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwiretap7-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwscodecs1-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwscodecs1-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwsutil8-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwsutil8-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"wireshark-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"wireshark-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"wireshark-debugsource-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"wireshark-gtk-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"wireshark-gtk-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libwireshark9-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libwireshark9-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libwiretap7-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libwiretap7-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libwscodecs1-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libwscodecs1-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libwsutil8-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libwsutil8-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"wireshark-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"wireshark-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"wireshark-debugsource-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"wireshark-gtk-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"wireshark-gtk-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwireshark9-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwireshark9-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwiretap7-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwiretap7-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwscodecs1-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwscodecs1-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwsutil8-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwsutil8-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"wireshark-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"wireshark-debuginfo-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"wireshark-debugsource-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"wireshark-gtk-2.4.11-48.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"wireshark-gtk-debuginfo-2.4.11-48.35.1")) flag++;


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
