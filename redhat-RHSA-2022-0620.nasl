#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:0620. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158266);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2020-0465",
    "CVE-2020-0466",
    "CVE-2021-0920",
    "CVE-2021-3564",
    "CVE-2021-3573",
    "CVE-2021-3752",
    "CVE-2021-4155",
    "CVE-2022-0330",
    "CVE-2022-22942"
  );
  script_xref(name:"RHSA", value:"2022:0620");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"RHEL 7 : kernel (RHSA-2022:0620)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:0620 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: use after free in eventpoll.c may lead to escalation of privilege (CVE-2020-0466)

    * kernel: Use After Free in unix_gc() which could result in a local privilege escalation (CVE-2021-0920)

    * kernel: xfs: raw block device data leak in XFS_IOC_ALLOCSP IOCTL (CVE-2021-4155)

    * kernel: possible privileges escalation due to missing TLB flush (CVE-2022-0330)

    * kernel: failing usercopy allows for use-after-free exploitation (CVE-2022-22942)

    * kernel: out of bounds write in hid-multitouch.c may lead to escalation of privilege (CVE-2020-0465)

    * kernel: double free in bluetooth subsystem when the HCI device initialization fails (CVE-2021-3564)

    * kernel: use-after-free in function hci_sock_bound_ioctl() (CVE-2021-3573)

    * kernel: possible use-after-free in bluetooth module (CVE-2021-3752)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * Kernel with enabled BERT does not decode CPU fatal events correctly (BZ#1950302)

    * RHEL 7.9 - Call trace seen during controller random reset on IB config (BZ#1984070)

    * Infinite loop in blk_set_queue_dying() from blk_queue_for_each_rl() when another CPU races and modifies
    the queue's blkg_list (BZ#2029574)

    * NFS client kernel crash in NFS4 backchannel transmit path - ftrace_raw_event_rpc_task_queued called from
    rpc_run_bc_task (BZ#2039508)

    * SELinux is preventing / from mount access on the filesystem /proc (BZ#2040196)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_0620.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ee21fd9");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:0620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1920471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1920480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1964139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1966578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1999544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2031930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2034813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2042404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2044809");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2022:0620.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3752");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-22942");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vmwgfx Driver File Descriptor Handling Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(131, 281, 362, 415, 416, 787);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-bootwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2022:0620');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/source/SRPMS',
      'content/dist/rhel/client/7/7.9/x86_64/debug',
      'content/dist/rhel/client/7/7.9/x86_64/optional/debug',
      'content/dist/rhel/client/7/7.9/x86_64/optional/os',
      'content/dist/rhel/client/7/7.9/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/7/7.9/x86_64/os',
      'content/dist/rhel/client/7/7.9/x86_64/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/os',
      'content/dist/rhel/client/7/7Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/os',
      'content/dist/rhel/client/7/7Client/x86_64/source/SRPMS',
      'content/dist/rhel/computenode/7/7.9/x86_64/optional/debug',
      'content/dist/rhel/computenode/7/7.9/x86_64/optional/os',
      'content/dist/rhel/computenode/7/7.9/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/source/SRPMS',
      'content/dist/rhel/power-le/7/7.9/ppc64le/debug',
      'content/dist/rhel/power-le/7/7.9/ppc64le/highavailability/debug',
      'content/dist/rhel/power-le/7/7.9/ppc64le/highavailability/os',
      'content/dist/rhel/power-le/7/7.9/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel/power-le/7/7.9/ppc64le/optional/debug',
      'content/dist/rhel/power-le/7/7.9/ppc64le/optional/os',
      'content/dist/rhel/power-le/7/7.9/ppc64le/optional/source/SRPMS',
      'content/dist/rhel/power-le/7/7.9/ppc64le/os',
      'content/dist/rhel/power-le/7/7.9/ppc64le/resilientstorage/debug',
      'content/dist/rhel/power-le/7/7.9/ppc64le/resilientstorage/os',
      'content/dist/rhel/power-le/7/7.9/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel/power-le/7/7.9/ppc64le/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/source/SRPMS',
      'content/dist/rhel/power/7/7.9/ppc64/debug',
      'content/dist/rhel/power/7/7.9/ppc64/optional/debug',
      'content/dist/rhel/power/7/7.9/ppc64/optional/os',
      'content/dist/rhel/power/7/7.9/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/7/7.9/ppc64/os',
      'content/dist/rhel/power/7/7.9/ppc64/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/os',
      'content/dist/rhel/power/7/7Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/os',
      'content/dist/rhel/power/7/7Server/ppc64/source/SRPMS',
      'content/dist/rhel/server/7/7.9/x86_64/debug',
      'content/dist/rhel/server/7/7.9/x86_64/highavailability/debug',
      'content/dist/rhel/server/7/7.9/x86_64/highavailability/os',
      'content/dist/rhel/server/7/7.9/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/7/7.9/x86_64/optional/debug',
      'content/dist/rhel/server/7/7.9/x86_64/optional/os',
      'content/dist/rhel/server/7/7.9/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/7/7.9/x86_64/os',
      'content/dist/rhel/server/7/7.9/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/7/7.9/x86_64/resilientstorage/os',
      'content/dist/rhel/server/7/7.9/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/7/7.9/x86_64/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/os',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/optional/debug',
      'content/dist/rhel/server/7/7Server/x86_64/optional/os',
      'content/dist/rhel/server/7/7Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/source/SRPMS',
      'content/dist/rhel/system-z/7/7.9/s390x/debug',
      'content/dist/rhel/system-z/7/7.9/s390x/highavailability/debug',
      'content/dist/rhel/system-z/7/7.9/s390x/highavailability/os',
      'content/dist/rhel/system-z/7/7.9/s390x/highavailability/source/SRPMS',
      'content/dist/rhel/system-z/7/7.9/s390x/optional/debug',
      'content/dist/rhel/system-z/7/7.9/s390x/optional/os',
      'content/dist/rhel/system-z/7/7.9/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/7/7.9/s390x/os',
      'content/dist/rhel/system-z/7/7.9/s390x/resilientstorage/debug',
      'content/dist/rhel/system-z/7/7.9/s390x/resilientstorage/os',
      'content/dist/rhel/system-z/7/7.9/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel/system-z/7/7.9/s390x/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/os',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/os',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/source/SRPMS',
      'content/dist/rhel/workstation/7/7.9/x86_64/debug',
      'content/dist/rhel/workstation/7/7.9/x86_64/optional/debug',
      'content/dist/rhel/workstation/7/7.9/x86_64/optional/os',
      'content/dist/rhel/workstation/7/7.9/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/7/7.9/x86_64/os',
      'content/dist/rhel/workstation/7/7.9/x86_64/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/os',
      'content/fastrack/rhel/client/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/os',
      'content/fastrack/rhel/client/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/os',
      'content/fastrack/rhel/computenode/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/os',
      'content/fastrack/rhel/computenode/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/os',
      'content/fastrack/rhel/power/7/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/os',
      'content/fastrack/rhel/power/7/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/os',
      'content/fastrack/rhel/server/7/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/optional/debug',
      'content/fastrack/rhel/server/7/x86_64/optional/os',
      'content/fastrack/rhel/server/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/os',
      'content/fastrack/rhel/system-z/7/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/os',
      'content/fastrack/rhel/system-z/7/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/os',
      'content/fastrack/rhel/workstation/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/os',
      'content/fastrack/rhel/workstation/7/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-3.10.0-1160.59.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'bpftool-3.10.0-1160.59.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'bpftool-3.10.0-1160.59.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'bpftool-3.10.0-1160.59.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-3.10.0-1160.59.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-3.10.0-1160.59.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-3.10.0-1160.59.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-3.10.0-1160.59.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-bootwrapper-3.10.0-1160.59.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-bootwrapper-3.10.0-1160.59.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-debug-3.10.0-1160.59.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-debug-3.10.0-1160.59.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-debug-3.10.0-1160.59.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-debug-3.10.0-1160.59.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-debug-devel-3.10.0-1160.59.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-debug-devel-3.10.0-1160.59.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-debug-devel-3.10.0-1160.59.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-debug-devel-3.10.0-1160.59.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-devel-3.10.0-1160.59.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-devel-3.10.0-1160.59.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-devel-3.10.0-1160.59.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-devel-3.10.0-1160.59.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-headers-3.10.0-1160.59.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-0330']},
      {'reference':'kernel-kdump-3.10.0-1160.59.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-kdump-devel-3.10.0-1160.59.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-tools-3.10.0-1160.59.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-tools-3.10.0-1160.59.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-tools-3.10.0-1160.59.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-tools-libs-3.10.0-1160.59.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-tools-libs-3.10.0-1160.59.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-tools-libs-3.10.0-1160.59.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-tools-libs-devel-3.10.0-1160.59.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-tools-libs-devel-3.10.0-1160.59.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'kernel-tools-libs-devel-3.10.0-1160.59.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'perf-3.10.0-1160.59.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'perf-3.10.0-1160.59.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'perf-3.10.0-1160.59.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'perf-3.10.0-1160.59.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'python-perf-3.10.0-1160.59.1.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'python-perf-3.10.0-1160.59.1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'python-perf-3.10.0-1160.59.1.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']},
      {'reference':'python-perf-3.10.0-1160.59.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2020-0465', 'CVE-2020-0466', 'CVE-2021-0920', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3752', 'CVE-2021-4155', 'CVE-2022-0330', 'CVE-2022-22942']}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    var cves = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-bootwrapper / kernel-debug / etc');
}
