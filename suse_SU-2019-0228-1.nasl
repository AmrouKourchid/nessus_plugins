#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0228-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(121610);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/24");

  script_cve_id(
    "CVE-2018-19198",
    "CVE-2018-19199",
    "CVE-2018-19200",
    "CVE-2018-20721"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : uriparser (SUSE-SU-2019:0228-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for uriparser fixes the following issues :

Security issues fixed :

CVE-2018-20721: Fixed an out-of-bounds read for incomplete URIs with
IPv6 addresses with embedded IPv4 address (bsc#1122193).

CVE-2018-19198: Fixed an out-of-bounds write that was possible via the
uriComposeQuery* or uriComposeQueryEx* function (bsc#1115722).

CVE-2018-19199: Fixed an integer overflow caused by an unchecked
multiplication via the uriComposeQuery* or uriComposeQueryEx* function
(bsc#1115723).

CVE-2018-19200: Fixed a operation attempted on NULL input via a
uriResetUri* function (bsc#1115724).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1115722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1115723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1115724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1122193");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19198/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19199/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-19200/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20721/");
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190228-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95018665");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-228=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20721");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liburiparser1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liburiparser1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uriparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uriparser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uriparser-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uriparser-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"liburiparser1-0.8.5-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"liburiparser1-debuginfo-0.8.5-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"uriparser-0.8.5-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"uriparser-debuginfo-0.8.5-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"uriparser-debugsource-0.8.5-3.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"uriparser-devel-0.8.5-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"liburiparser1-0.8.5-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"liburiparser1-debuginfo-0.8.5-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"uriparser-0.8.5-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"uriparser-debuginfo-0.8.5-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"uriparser-debugsource-0.8.5-3.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"uriparser-devel-0.8.5-3.5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "uriparser");
}
