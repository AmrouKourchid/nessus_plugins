#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1018-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(135751);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id("CVE-2019-13456", "CVE-2019-17185");

  script_name(english:"SUSE SLES12 Security Update : freeradius-server (SUSE-SU-2020:1018-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for freeradius-server fixes the following issues :

CVE-2019-13456: Fixed a side-channel password leak in EAP-pwd
(bsc#1144524).

CVE-2019-17185: Fixed a debial of service due to multithreaded BN_CTX
access (bsc#1166847).

Fixed an issue in TLS-EAP where the OCSP verification, when an
intermediate client certificate was not explicitly trusted
(bsc#1146848).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1144524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1146848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1166847");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-13456/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17185/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201018-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6928c583");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8:zypper in -t patch
SUSE-OpenStack-Cloud-Crowbar-8-2020-1018=1

SUSE OpenStack Cloud 8:zypper in -t patch
SUSE-OpenStack-Cloud-8-2020-1018=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2020-1018=1

SUSE Linux Enterprise Server for SAP 12-SP3:zypper in -t patch
SUSE-SLE-SAP-12-SP3-2020-1018=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2020-1018=1

SUSE Linux Enterprise Server 12-SP3-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2020-1018=1

SUSE Linux Enterprise Server 12-SP3-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-BCL-2020-1018=1

SUSE Enterprise Storage 5:zypper in -t patch
SUSE-Storage-5-2020-1018=1

HPE Helion Openstack 8:zypper in -t patch
HPE-Helion-OpenStack-8-2020-1018=1");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13456");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freeradius-server-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-debugsource-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-doc-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-krb5-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-krb5-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-ldap-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-ldap-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-libs-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-libs-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-mysql-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-mysql-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-perl-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-perl-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-postgresql-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-postgresql-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-python-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-python-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-sqlite-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-sqlite-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-utils-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"freeradius-server-utils-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-debugsource-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-doc-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-krb5-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-krb5-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-ldap-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-ldap-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-libs-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-libs-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-mysql-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-mysql-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-perl-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-perl-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-postgresql-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-postgresql-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-python-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-python-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-sqlite-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-sqlite-debuginfo-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-utils-3.0.15-2.14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"freeradius-server-utils-debuginfo-3.0.15-2.14.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius-server");
}
