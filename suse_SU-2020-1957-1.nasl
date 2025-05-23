#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1957-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(138791);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/29");

  script_cve_id("CVE-2020-10749");

  script_name(english:"SUSE SLES15 Security Update : cni-plugins (SUSE-SU-2020:1957-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for cni-plugins fixes the following issues :

cni-plugins updated to version 0.8.6

CVE-2020-10749: Fixed a potential Man-in-the-Middle attacks in IPv4
clusters by spoofing IPv6 router advertisements (bsc#1172410).

Release notes:
https://github.com/containernetworking/plugins/releases/tag/v0.8.6

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1172410");
  script_set_attribute(attribute:"see_also", value:"https://github.com/containernetworking/plugins/releases/tag/v0.8.6");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10749/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201957-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?056bdae3");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Public Cloud 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-15-SP1-2020-1957=1

SUSE Linux Enterprise Module for Containers 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Containers-15-SP2-2020-1957=1

SUSE Linux Enterprise Module for Containers 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Containers-15-SP1-2020-1957=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10749");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cni-plugins");
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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"cni-plugins-0.8.6-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"cni-plugins-0.8.6-3.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cni-plugins");
}
