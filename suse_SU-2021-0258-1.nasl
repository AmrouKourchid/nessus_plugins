#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0258-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(146050);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/24");

  script_cve_id("CVE-2020-27827");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : openvswitch (SUSE-SU-2021:0258-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for openvswitch fixes the following issues :

openvswitch was updated to 2.13.2

CVE-2020-27827: Fixed a memory leak when parsing lldp packets
(bsc#1181345)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1117483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181345");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27827/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210258-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17e6b6ff");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Server-Applications-15-SP2-2021-258=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP2-2021-258=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27827");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenvswitch-2_13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libopenvswitch-2_13-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libovn-20_03");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libovn-20_03-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-ipsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvswitch-vtep-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ovn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ovn-central");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ovn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ovn-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ovn-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ovn-vtep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ovs");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", reference:"libopenvswitch-2_13-0-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libopenvswitch-2_13-0-debuginfo-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libovn-20_03-0-20.03.1-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libovn-20_03-0-debuginfo-20.03.1-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvswitch-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvswitch-debuginfo-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvswitch-debugsource-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvswitch-devel-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvswitch-ipsec-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvswitch-pki-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvswitch-test-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvswitch-test-debuginfo-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvswitch-vtep-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"openvswitch-vtep-debuginfo-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ovn-20.03.1-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ovn-central-20.03.1-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ovn-devel-20.03.1-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ovn-docker-20.03.1-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ovn-host-20.03.1-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"ovn-vtep-20.03.1-9.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"python3-ovs-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libopenvswitch-2_13-0-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libopenvswitch-2_13-0-debuginfo-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"openvswitch-debuginfo-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"openvswitch-debugsource-2.13.2-9.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"python3-ovs-2.13.2-9.11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvswitch");
}
