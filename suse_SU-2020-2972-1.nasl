#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:2972-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(143615);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/06");

  script_cve_id("CVE-2020-12351", "CVE-2020-12352", "CVE-2020-25645");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : kernel (SUSE-SU-2020:2972-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The SUSE Linux Enterprise 15 SP1 kernel was updated to receive various
security and bugfixes.

The following security bugs were fixed :

CVE-2020-12351: Fixed a type confusion while processing AMP packets
aka 'BleedingTooth' aka 'BadKarma' (bsc#1177724).

CVE-2020-12352: Fixed an information leak when processing certain AMP
packets aka 'BleedingTooth' aka 'BadChoice' (bsc#1177725).

CVE-2020-25645: Fixed an issue which traffic between two Geneve
endpoints may be unencrypted when IPsec is configured to encrypt
traffic for the specific UDP port used by the GENEVE tunnel allowing
anyone between the two endpoints to read the traffic unencrypted
(bsc#1177511).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1140683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1174748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1175520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1176946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1177725");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12351/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12352/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25645/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20202972-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b825c610");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 15-SP1 :

zypper in -t patch SUSE-SLE-Product-WE-15-SP1-2020-2972=1

SUSE Linux Enterprise Module for Live Patching 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Live-Patching-15-SP1-2020-2972=1

SUSE Linux Enterprise Module for Legacy Software 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Legacy-15-SP1-2020-2972=1

SUSE Linux Enterprise Module for Development Tools 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP1-2020-2972=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-2972=1

SUSE Linux Enterprise High Availability 15-SP1 :

zypper in -t patch SUSE-SLE-Product-HA-15-SP1-2020-2972=1");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12351");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"kernel-default-man-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"kernel-zfcpdump-debugsource-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-base-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-base-debuginfo-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-debuginfo-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-debugsource-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-devel-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-default-devel-debuginfo-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-obs-build-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-obs-build-debugsource-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"kernel-syms-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"reiserfs-kmp-default-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"reiserfs-kmp-default-debuginfo-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"kernel-default-man-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"kernel-zfcpdump-debuginfo-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"kernel-zfcpdump-debugsource-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-base-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-base-debuginfo-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-debuginfo-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-debugsource-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-devel-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-default-devel-debuginfo-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-obs-build-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-obs-build-debugsource-4.12.14-197.64.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"kernel-syms-4.12.14-197.64.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
