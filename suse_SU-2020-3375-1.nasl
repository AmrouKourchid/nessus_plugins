#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3375-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(143731);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/05");

  script_cve_id("CVE-2020-28196");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"SUSE SLES15 Security Update : krb5 (SUSE-SU-2020:3375-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for krb5 fixes the following security issue :

CVE-2020-28196: Fixed an unbounded recursion via an ASN.1-encoded
Kerberos message (bsc#1178512).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178512");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28196/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203375-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d7c954fd");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 15 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-2020-3375=1

SUSE Linux Enterprise Server 15-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-2020-3375=1

SUSE Linux Enterprise High Performance Computing 15-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-3375=1

SUSE Linux Enterprise High Performance Computing 15-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-2020-3375=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28196");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-kdb-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-kdb-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-preauth-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-preauth-otp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-preauth-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-plugin-preauth-pkinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:krb5-server-debuginfo");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "s390x") audit(AUDIT_ARCH_NOT, "s390x", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"krb5-1.15.2-6.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"krb5-client-1.15.2-6.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"krb5-client-debuginfo-1.15.2-6.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"krb5-debuginfo-1.15.2-6.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"krb5-debugsource-1.15.2-6.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"krb5-devel-1.15.2-6.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"krb5-plugin-kdb-ldap-1.15.2-6.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"krb5-plugin-kdb-ldap-debuginfo-1.15.2-6.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"krb5-plugin-preauth-otp-1.15.2-6.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"krb5-plugin-preauth-otp-debuginfo-1.15.2-6.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"krb5-plugin-preauth-pkinit-1.15.2-6.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"krb5-plugin-preauth-pkinit-debuginfo-1.15.2-6.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"krb5-server-1.15.2-6.12.2")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"krb5-server-debuginfo-1.15.2-6.12.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5");
}
