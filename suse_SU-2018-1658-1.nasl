#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:1658-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(110509);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/01");

  script_cve_id(
    "CVE-2017-5715",
    "CVE-2017-5753",
    "CVE-2017-5754",
    "CVE-2018-3639"
  );
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"SUSE SLES12 Security Update : xen (SUSE-SU-2018:1658-1) (Meltdown) (Spectre)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for xen fixes several issues. These security issues were
fixed :

  - CVE-2018-3639: Prevent attackers with local user access
    from extracting information via a side-channel analysis,
    aka Speculative Store Bypass (SSB), Variant 4
    (bsc#1092631).

  - CVE-2017-5753,CVE-2017-5715,CVE-2017-5754: Improved
    Spectre v2 mitigations (bsc#1074562).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1074562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1092631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-5715/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-5753/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-5754/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-3639/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20181658-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e8dccca");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2018-1129=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5754");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-4.4.4_32-22.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-debugsource-4.4.4_32-22.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-doc-html-4.4.4_32-22.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-4.4.4_32_k3.12.61_52.133-22.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.4_32_k3.12.61_52.133-22.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-32bit-4.4.4_32-22.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-4.4.4_32-22.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.4_32-22.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-4.4.4_32-22.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-4.4.4_32-22.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.4_32-22.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-4.4.4_32-22.68.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.4.4_32-22.68.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
