#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2928-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(117858);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/25");

  script_cve_id("CVE-2018-0737");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : openssl (SUSE-SU-2018:2928-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for openssl fixes the following issues :

These security issues were fixed :

Prevent One&Done side-channel attack on RSA that allowed physically
near attackers to use EM emanations to recover information
(bsc#1104789)

CVE-2018-0737: The RSA Key generation algorithm has been shown to be
vulnerable to a cache timing side channel attack. An attacker with
sufficient access to mount cache timing attacks during the RSA key
generation process could have recovered the private key (bsc#1089039)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1089039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1101246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1101470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1104789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1106197");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=997043");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-0737/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182928-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d6e775f");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-2069=1

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-2069=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-2069=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-2069=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-2069=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-2069=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-2069=1

SUSE CaaS Platform ALL :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2018-2069=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0737");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenssl1_0_0-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libopenssl-devel-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libopenssl1_0_0-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libopenssl1_0_0-32bit-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libopenssl1_0_0-debuginfo-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libopenssl1_0_0-hmac-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libopenssl1_0_0-hmac-32bit-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openssl-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openssl-debuginfo-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"openssl-debugsource-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libopenssl-devel-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libopenssl1_0_0-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libopenssl1_0_0-32bit-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libopenssl1_0_0-debuginfo-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libopenssl1_0_0-hmac-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"libopenssl1_0_0-hmac-32bit-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openssl-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openssl-debuginfo-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"openssl-debugsource-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libopenssl-devel-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libopenssl1_0_0-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libopenssl1_0_0-32bit-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libopenssl1_0_0-debuginfo-32bit-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openssl-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openssl-debuginfo-1.0.2j-60.39.1")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"openssl-debugsource-1.0.2j-60.39.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
