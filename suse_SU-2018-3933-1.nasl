#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3933-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(119285);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/18");

  script_cve_id(
    "CVE-2018-13785",
    "CVE-2018-3136",
    "CVE-2018-3139",
    "CVE-2018-3149",
    "CVE-2018-3169",
    "CVE-2018-3180",
    "CVE-2018-3214"
  );

  script_name(english:"SUSE SLES12 Security Update : java-1_7_1-ibm (SUSE-SU-2018:3933-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"java-1_7_1-ibm was updated to Java 7.1 Service Refresh 4 Fix Pack 35
(bsc#1116574) :

Consumability

  - IJ10515 AIX JAVA 7.1.3.10 GENERAL PROTECTION FAULT WHEN
    ATTEMPTING TO USE HEALTH CENTER API Class Libraries

  - IJ10934 CVE-2018-13785

  - IJ10935 CVE-2018-3136

  - IJ10895 CVE-2018-3139

  - IJ10932 CVE-2018-3149

  - IJ10894 CVE-2018-3180

  - IJ10933 CVE-2018-3214

  - IJ09315 FLOATING POINT EXCEPTION FROM
    JAVA.TEXT.DECIMALFORMAT. FORMAT

  - IJ09088 INTRODUCING A NEW PROPERTY FOR TURKEY TIMEZONE
    FOR PRODUCTS NOT IDENTIFYING TRT

  - IJ08569 JAVA.IO.IOEXCEPTION OCCURS WHEN A FILECHANNEL IS
    BIGGER THAN 2GB ON AIX PLATFORM

  - IJ10800 REMOVE EXPIRING ROOT CERTIFICATES IN IBM
    JDK&Atilde;&cent;&Acirc;&#128;&Acirc;&#153;S CACERTS.
    Java Virtual Machine

  - IJ10931 CVE-2018-3169

  - IV91132 SOME CORE PATTERN SPECIFIERS ARE NOT HANDLED BY
    THE JVM ON LINUX JIT Compiler

  - IJ08205 CRASH WHILE COMPILING

  - IJ07886 INCORRECT CALUCATIONS WHEN USING
    NUMBERFORMAT.FORMAT() AND BIGDECIMAL.{FLOAT/DOUBLE
    }VALUE() ORB

  - IX90187 CLIENTREQUESTIMPL.REINVO KE FAILS WITH
    JAVA.LANG.INDEXOUTOFBOUN DSEXCEPTION Security

  - IJ10492 'EC KEYSIZE z/OS Extentions

  - PH01244 OUTPUT BUFFER TOO SHORT FOR GCM MODE ENCRYPTION
    USING IBMJCEHYBRID

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1116574");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-13785/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-3136/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-3139/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-3149/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-3169/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-3180/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-3214/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183933-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07f4967b");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-2802=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2018-2802=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-2802=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-2802=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2018-2802=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-2802=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-2802=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2018-2802=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2018-2802=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-2802=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-2802=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3180");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-3169");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_1-ibm-plugin");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1|2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2/3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"java-1_7_1-ibm-alsa-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"java-1_7_1-ibm-plugin-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_1-ibm-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_1-ibm-devel-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_1-ibm-jdbc-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"java-1_7_1-ibm-alsa-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", cpu:"x86_64", reference:"java-1_7_1-ibm-plugin-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_7_1-ibm-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"java-1_7_1-ibm-jdbc-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"java-1_7_1-ibm-alsa-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"java-1_7_1-ibm-plugin-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_1-ibm-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_1-ibm-devel-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_1-ibm-jdbc-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"java-1_7_1-ibm-alsa-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", cpu:"x86_64", reference:"java-1_7_1-ibm-plugin-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_1-ibm-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"java-1_7_1-ibm-jdbc-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_1-ibm-alsa-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_1-ibm-plugin-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_1-ibm-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_1-ibm-devel-1.7.1_sr4.35-38.29.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"java-1_7_1-ibm-jdbc-1.7.1_sr4.35-38.29.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_1-ibm");
}
