#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:1762-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150014);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/28");

  script_cve_id("CVE-2021-22898");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : curl (SUSE-SU-2021:1762-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for curl fixes the following issues :

CVE-2021-22898: Fixed curl TELNET stack contents disclosure
(bsc#1186114).

Allow partial chain verification [jsc#SLE-17956]

  - Have intermediate certificates in the trust store be
    treated as trust-anchors, in the same way as self-signed
    root CA certificates are. This allows users to verify
    servers using the intermediate cert only, instead of
    needing the whole chain.

  - Set FLAG_TRUSTED_FIRST unconditionally.

  - Do not check partial chains with CRL check.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1186114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22898/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20211762-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae48bdc4");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE MicroOS 5.0 :

zypper in -t patch SUSE-SUSE-MicroOS-5.0-2021-1762=1

SUSE Linux Enterprise Module for Basesystem 15-SP3 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP3-2021-1762=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2021-1762=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22898");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:curl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcurl4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcurl4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libcurl4-32bit-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", cpu:"x86_64", reference:"libcurl4-32bit-debuginfo-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"curl-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"curl-debuginfo-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"curl-debugsource-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libcurl-devel-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libcurl4-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"3", reference:"libcurl4-debuginfo-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libcurl4-32bit-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"libcurl4-32bit-debuginfo-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"curl-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"curl-debuginfo-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"curl-debugsource-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libcurl-devel-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libcurl4-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libcurl4-debuginfo-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libcurl4-32bit-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", cpu:"x86_64", reference:"libcurl4-32bit-debuginfo-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"curl-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"curl-debuginfo-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"curl-debugsource-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libcurl-devel-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libcurl4-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"3", reference:"libcurl4-debuginfo-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libcurl4-32bit-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"libcurl4-32bit-debuginfo-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"curl-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"curl-debuginfo-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"curl-debugsource-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libcurl-devel-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libcurl4-7.66.0-4.17.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libcurl4-debuginfo-7.66.0-4.17.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl");
}
