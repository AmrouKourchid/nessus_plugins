#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0653-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(146903);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/18");

  script_cve_id(
    "CVE-2019-25013",
    "CVE-2020-27618",
    "CVE-2020-29562",
    "CVE-2020-29573",
    "CVE-2021-3326"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : glibc (SUSE-SU-2021:0653-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for glibc fixes the following issues :

Fix buffer overrun in EUC-KR conversion module (CVE-2019-25013,
bsc#1182117, BZ #24973)

x86: Harden printf against non-normal long double values
(CVE-2020-29573, bsc#1179721, BZ #26649)

gconv: Fix assertion failure in ISO-2022-JP-3 module (CVE-2021-3326,
bsc#1181505, BZ #27256)

iconv: Accept redundant shift sequences in IBM1364 (CVE-2020-27618,
bsc#1178386, BZ #26224)

iconv: Fix incorrect UCS4 inner loop bounds (CVE-2020-29562,
bsc#1179694, BZ #26923)

Fix parsing of /sys/devices/system/cpu/online (bsc#1180038, BZ #25859)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182117");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-25013/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27618/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29562/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29573/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3326/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210653-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?538c9175");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Manager Server 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Server-4.0-2021-653=1

SUSE Manager Retail Branch Server 4.0 :

zypper in -t patch
SUSE-SLE-Product-SUSE-Manager-Retail-Branch-Server-4.0-2021-653=1

SUSE Manager Proxy 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Proxy-4.0-2021-653=1

SUSE Linux Enterprise Server for SAP 15-SP1 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-SP1-2021-653=1

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2021-653=1

SUSE Linux Enterprise Server 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-LTSS-2021-653=1

SUSE Linux Enterprise Server 15-SP1-BCL :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-BCL-2021-653=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2021-653=1

SUSE Linux Enterprise Module for Development Tools 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Development-Tools-15-SP2-2021-653=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-653=1

SUSE Linux Enterprise High Performance Computing 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-LTSS-2021-653=1

SUSE Linux Enterprise High Performance Computing 15-SP1-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-ESPOS-2021-653=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-653=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2021-653=1

SUSE Enterprise Storage 6 :

zypper in -t patch SUSE-Storage-6-2021-653=1

SUSE CaaS Platform 4.0 :

To install this update, use the SUSE CaaS Platform 'skuba' tool. I
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-25013");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3326");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale-base-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-utils-src-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-32bit-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-devel-32bit-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-devel-32bit-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-locale-base-32bit-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"glibc-locale-base-32bit-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-debugsource-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-devel-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-devel-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-devel-static-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-extra-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-extra-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-locale-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-locale-base-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-locale-base-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-profile-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-utils-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-utils-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"glibc-utils-src-debugsource-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nscd-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"nscd-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-debugsource-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-devel-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-devel-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-devel-static-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-extra-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-extra-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-locale-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-locale-base-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-locale-base-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-profile-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-utils-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-utils-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"glibc-utils-src-debugsource-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"nscd-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"nscd-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"glibc-32bit-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"glibc-devel-32bit-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"glibc-devel-32bit-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"glibc-locale-base-32bit-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"glibc-locale-base-32bit-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-debugsource-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-devel-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-devel-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-devel-static-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-extra-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-extra-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-locale-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-locale-base-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-locale-base-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-profile-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-utils-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-utils-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"glibc-utils-src-debugsource-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"nscd-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"nscd-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"glibc-32bit-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"glibc-devel-32bit-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"glibc-devel-32bit-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"glibc-locale-base-32bit-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"glibc-locale-base-32bit-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-debugsource-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-devel-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-devel-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-devel-static-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-extra-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-extra-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-locale-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-locale-base-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-locale-base-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-profile-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-utils-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-utils-debuginfo-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"glibc-utils-src-debugsource-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"nscd-2.26-13.56.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"nscd-debuginfo-2.26-13.56.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
