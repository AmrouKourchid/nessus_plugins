#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0044. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(105675);
  script_version("3.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/11");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754");
  script_xref(name:"RHSA", value:"2018:0044");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"IAVA", value:"2018-A-0017-S");

  script_name(english:"RHEL 7 : redhat-virtualization-host (RHSA-2018:0044) (Meltdown) (Spectre)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for redhat-virtualization-host is now available for RHEV 3.X
Hypervisor and Agents for RHEL-7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The ovirt-node-ng packages provide the Red Hat Virtualization Host.
These packages include redhat-release-virtualization-host, ovirt-node,
and rhev-hypervisor. Red Hat Virtualization Hosts (RHVH) are installed
using a special build of Red Hat Enterprise Linux with only the
packages required to host virtual machines. RHVH features a Cockpit
user interface for monitoring the host's resources and performing
administrative tasks.

Security Fix(es) :

An industry-wide issue was found in the way many modern microprocessor
designs have implemented speculative execution of instructions (a
commonly used performance optimization). There are three primary
variants of the issue which differ in the way the speculative
execution can be exploited.

Note: This issue is present in hardware and cannot be fully fixed via
software update. The updated kernel packages provide software
mitigation for this hardware issue at a cost of potential performance
penalty. Please refer to References section for further information
about this issue and the performance impact.

Variant CVE-2017-5753 triggers the speculative execution by performing
a bounds-check bypass. It relies on the presence of a
precisely-defined instruction sequence in the privileged code as well
as the fact that memory accesses may cause allocation into the
microprocessor's data cache even for speculatively executed
instructions that never actually commit (retire). As a result, an
unprivileged attacker could use this flaw to cross the syscall
boundary and read privileged memory by conducting targeted cache
side-channel attacks. (CVE-2017-5753, Important)

Variant CVE-2017-5715 triggers the speculative execution by utilizing
branch target injection. It relies on the presence of a
precisely-defined instruction sequence in the privileged code as well
as the fact that memory accesses may cause allocation into the
microprocessor's data cache even for speculatively executed
instructions that never actually commit (retire). As a result, an
unprivileged attacker could use this flaw to cross the syscall and
guest/host boundaries and read privileged memory by conducting
targeted cache side-channel attacks. (CVE-2017-5715, Important)

Variant CVE-2017-5754 relies on the fact that, on impacted
microprocessors, during speculative execution of instruction
permission faults, exception generation triggered by a faulting access
is suppressed until the retirement of the whole instruction block. In
a combination with the fact that memory accesses may populate the
cache even when the block is being dropped and never committed
(executed), an unprivileged local attacker could use this flaw to read
privileged (kernel space) memory by conducting targeted cache
side-channel attacks. (CVE-2017-5754, Important)

Note: CVE-2017-5754 affects Intel x86-64 microprocessors. AMD x86-64
microprocessors are not affected by this issue.

Red Hat would like to thank Google Project Zero for reporting these
issues.");
  # https://access.redhat.com/security/vulnerabilities/speculativeexecution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?892ef523");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/solutions/3307851");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-5753");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-5715");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-5754");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:0044");
  script_set_attribute(attribute:"solution", value:
"Update the affected redhat-virtualization-host-image-update package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-virtualization-host-image-update");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:0044";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", reference:"redhat-virtualization-host-image-update-3.6-20180103.0.el7_3")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "redhat-virtualization-host-image-update");
  }
}
