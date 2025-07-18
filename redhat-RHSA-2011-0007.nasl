#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0007. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51500);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/14");

  script_cve_id(
    "CVE-2010-2492",
    "CVE-2010-3067",
    "CVE-2010-3078",
    "CVE-2010-3080",
    "CVE-2010-3298",
    "CVE-2010-3477",
    "CVE-2010-3861",
    "CVE-2010-3865",
    "CVE-2010-3874",
    "CVE-2010-3876",
    "CVE-2010-3880",
    "CVE-2010-4072",
    "CVE-2010-4073",
    "CVE-2010-4074",
    "CVE-2010-4075",
    "CVE-2010-4077",
    "CVE-2010-4079",
    "CVE-2010-4080",
    "CVE-2010-4081",
    "CVE-2010-4082",
    "CVE-2010-4083",
    "CVE-2010-4158",
    "CVE-2010-4160",
    "CVE-2010-4162",
    "CVE-2010-4163",
    "CVE-2010-4242",
    "CVE-2010-4248",
    "CVE-2010-4249",
    "CVE-2010-4263",
    "CVE-2010-4525",
    "CVE-2010-4668"
  );
  script_bugtraq_id(
    42237,
    42529,
    43022,
    43062,
    43226,
    43353,
    43806,
    43809,
    43817,
    44427,
    44549,
    44630,
    44661,
    44665,
    44758,
    44762,
    44793,
    45014,
    45028,
    45037,
    45054,
    45058,
    45059,
    45062,
    45063,
    45073,
    45074,
    45208,
    45660,
    45676
  );
  script_xref(name:"RHSA", value:"2011:0007");

  script_name(english:"RHEL 6 : kernel (RHSA-2011:0007)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2011:0007 advisory.

    * Buffer overflow in eCryptfs. When /dev/ecryptfs has world writable
    permissions (which it does not, by default, on Red Hat Enterprise Linux 6),
    a local, unprivileged user could use this flaw to cause a denial of service
    or possibly escalate their privileges. (CVE-2010-2492, Important)

    * Integer overflow in the RDS protocol implementation could allow a local,
    unprivileged user to cause a denial of service or escalate their
    privileges. (CVE-2010-3865, Important)

    * Missing boundary checks in the PPP over L2TP sockets implementation could
    allow a local, unprivileged user to cause a denial of service or escalate
    their privileges. (CVE-2010-4160, Important)

    * NULL pointer dereference in the igb driver. If both Single Root I/O
    Virtualization (SR-IOV) and promiscuous mode were enabled on an interface
    using igb, it could result in a denial of service when a tagged VLAN packet
    is received on that interface. (CVE-2010-4263, Important)

    * Missing initialization flaw in the XFS file system implementation, and in
    the network traffic policing implementation, could allow a local,
    unprivileged user to cause an information leak. (CVE-2010-3078,
    CVE-2010-3477, Moderate)

    * NULL pointer dereference in the Open Sound System compatible sequencer
    driver could allow a local, unprivileged user with access to /dev/sequencer
    to cause a denial of service. /dev/sequencer is only accessible to root and
    users in the audio group by default. (CVE-2010-3080, Moderate)

    * Flaw in the ethtool IOCTL handler could allow a local user to cause an
    information leak. (CVE-2010-3861, Moderate)

    * Flaw in bcm_connect() in the Controller Area Network (CAN) Broadcast
    Manager. On 64-bit systems, writing the socket address may overflow the
    procname character array. (CVE-2010-3874, Moderate)

    * Flaw in the module for monitoring the sockets of INET transport
    protocols could allow a local, unprivileged user to cause a denial of
    service. (CVE-2010-3880, Moderate)

    * Missing boundary checks in the block layer implementation could allow a
    local, unprivileged user to cause a denial of service. (CVE-2010-4162,
    CVE-2010-4163, CVE-2010-4668, Moderate)

    * NULL pointer dereference in the Bluetooth HCI UART driver could allow a
    local, unprivileged user to cause a denial of service. (CVE-2010-4242,
    Moderate)

    * Flaw in the Linux kernel CPU time clocks implementation for the POSIX
    clock interface could allow a local, unprivileged user to cause a denial of
    service. (CVE-2010-4248, Moderate)

    * Flaw in the garbage collector for AF_UNIX sockets could allow a local,
    unprivileged user to trigger a denial of service. (CVE-2010-4249, Moderate)

    * Missing upper bound integer check in the AIO implementation could allow a
    local, unprivileged user to cause an information leak. (CVE-2010-3067, Low)

    * Missing initialization flaws could lead to information leaks.
    (CVE-2010-3298, CVE-2010-3876, CVE-2010-4072, CVE-2010-4073, CVE-2010-4074,
    CVE-2010-4075, CVE-2010-4077, CVE-2010-4079, CVE-2010-4080, CVE-2010-4081,
    CVE-2010-4082, CVE-2010-4083, CVE-2010-4158, Low)

    * Missing initialization flaw in KVM could allow a privileged host user
    with access to /dev/kvm to cause an information leak. (CVE-2010-4525, Low)

    Red Hat would like to thank Andre Osterhues for reporting CVE-2010-2492;
    Thomas Pollet for reporting CVE-2010-3865; Dan Rosenberg for reporting
    CVE-2010-4160, CVE-2010-3078, CVE-2010-3874, CVE-2010-4162, CVE-2010-4163,
    CVE-2010-3298, CVE-2010-4073, CVE-2010-4074, CVE-2010-4075, CVE-2010-4077,
    CVE-2010-4079, CVE-2010-4080, CVE-2010-4081, CVE-2010-4082, CVE-2010-4083,
    and CVE-2010-4158; Kosuke Tatsukawa for reporting CVE-2010-4263; Tavis
    Ormandy for reporting CVE-2010-3080 and CVE-2010-3067; Kees Cook for
    reporting CVE-2010-3861 and CVE-2010-4072; Nelson Elhage for reporting
    CVE-2010-3880; Alan Cox for reporting CVE-2010-4242; Vegard Nossum for
    reporting CVE-2010-4249; Vasiliy Kulikov for reporting CVE-2010-3876; and
    Stephan Mueller of atsec information security for reporting CVE-2010-4525.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=611385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=629441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=630551");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=630804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=633140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=636386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=641410");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=646725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=647391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=647416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=648408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=648656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=648658");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=648659");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=648660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=648663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=648666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=648669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=648670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=648671");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=648673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=649695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=649715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=651264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=651698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=651892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=652529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=652957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=653340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=656264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=656756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=658879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=659611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=660188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=660244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=660591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=665470");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2011/rhsa-2011_0007.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a7c0829");
  # http://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Technical_Notes/ape.html#RHSA-2011-0007
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64c1d5d0");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2011:0007");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2011:0007.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4263");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-2492");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 190, 401);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-bootwrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl", "redhat_repos.nasl");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2010-2492', 'CVE-2010-3067', 'CVE-2010-3078', 'CVE-2010-3080', 'CVE-2010-3298', 'CVE-2010-3477', 'CVE-2010-3861', 'CVE-2010-3865', 'CVE-2010-3874', 'CVE-2010-3876', 'CVE-2010-3880', 'CVE-2010-4072', 'CVE-2010-4073', 'CVE-2010-4074', 'CVE-2010-4075', 'CVE-2010-4077', 'CVE-2010-4079', 'CVE-2010-4080', 'CVE-2010-4081', 'CVE-2010-4082', 'CVE-2010-4083', 'CVE-2010-4158', 'CVE-2010-4160', 'CVE-2010-4162', 'CVE-2010-4163', 'CVE-2010-4242', 'CVE-2010-4248', 'CVE-2010-4249', 'CVE-2010-4263', 'CVE-2010-4525', 'CVE-2010-4668');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2011:0007');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/6/6Client/i386/debug',
      'content/dist/rhel/client/6/6Client/i386/optional/debug',
      'content/dist/rhel/client/6/6Client/i386/optional/os',
      'content/dist/rhel/client/6/6Client/i386/optional/source/SRPMS',
      'content/dist/rhel/client/6/6Client/i386/os',
      'content/dist/rhel/client/6/6Client/i386/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/debug',
      'content/dist/rhel/client/6/6Client/x86_64/optional/debug',
      'content/dist/rhel/client/6/6Client/x86_64/optional/os',
      'content/dist/rhel/client/6/6Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/6/6Client/x86_64/os',
      'content/dist/rhel/client/6/6Client/x86_64/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/os',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/computenode/6/6ComputeNode/x86_64/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/debug',
      'content/dist/rhel/power/6/6Server/ppc64/optional/debug',
      'content/dist/rhel/power/6/6Server/ppc64/optional/os',
      'content/dist/rhel/power/6/6Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/6/6Server/ppc64/os',
      'content/dist/rhel/power/6/6Server/ppc64/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/debug',
      'content/dist/rhel/server/6/6Server/i386/highavailability/os',
      'content/dist/rhel/server/6/6Server/i386/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/i386/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/optional/debug',
      'content/dist/rhel/server/6/6Server/i386/optional/os',
      'content/dist/rhel/server/6/6Server/i386/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/i386/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/i386/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/os',
      'content/dist/rhel/server/6/6Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/debug',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/os',
      'content/dist/rhel/server/6/6Server/x86_64/loadbalancer/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/optional/debug',
      'content/dist/rhel/server/6/6Server/x86_64/optional/os',
      'content/dist/rhel/server/6/6Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/6/6Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/os',
      'content/dist/rhel/server/6/6Server/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/debug',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/os',
      'content/dist/rhel/system-z/6/6Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/6/6Server/s390x/os',
      'content/dist/rhel/system-z/6/6Server/s390x/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/debug',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/optional/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/i386/os',
      'content/dist/rhel/workstation/6/6Workstation/i386/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/scalablefilesystem/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/source/SRPMS',
      'content/fastrack/rhel/client/6/i386/debug',
      'content/fastrack/rhel/client/6/i386/optional/debug',
      'content/fastrack/rhel/client/6/i386/optional/os',
      'content/fastrack/rhel/client/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/client/6/i386/os',
      'content/fastrack/rhel/client/6/i386/source/SRPMS',
      'content/fastrack/rhel/client/6/x86_64/debug',
      'content/fastrack/rhel/client/6/x86_64/optional/debug',
      'content/fastrack/rhel/client/6/x86_64/optional/os',
      'content/fastrack/rhel/client/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/6/x86_64/os',
      'content/fastrack/rhel/client/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/debug',
      'content/fastrack/rhel/computenode/6/x86_64/optional/debug',
      'content/fastrack/rhel/computenode/6/x86_64/optional/os',
      'content/fastrack/rhel/computenode/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/os',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/computenode/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/computenode/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/6/ppc64/debug',
      'content/fastrack/rhel/power/6/ppc64/optional/debug',
      'content/fastrack/rhel/power/6/ppc64/optional/os',
      'content/fastrack/rhel/power/6/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/6/ppc64/os',
      'content/fastrack/rhel/power/6/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/debug',
      'content/fastrack/rhel/server/6/i386/highavailability/os',
      'content/fastrack/rhel/server/6/i386/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/loadbalancer/debug',
      'content/fastrack/rhel/server/6/i386/loadbalancer/os',
      'content/fastrack/rhel/server/6/i386/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/optional/debug',
      'content/fastrack/rhel/server/6/i386/optional/os',
      'content/fastrack/rhel/server/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/debug',
      'content/fastrack/rhel/server/6/i386/resilientstorage/os',
      'content/fastrack/rhel/server/6/i386/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/i386/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/6/x86_64/highavailability/os',
      'content/fastrack/rhel/server/6/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/debug',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/os',
      'content/fastrack/rhel/server/6/x86_64/loadbalancer/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/optional/debug',
      'content/fastrack/rhel/server/6/x86_64/optional/os',
      'content/fastrack/rhel/server/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/6/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/server/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/server/6/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/6/s390x/debug',
      'content/fastrack/rhel/system-z/6/s390x/optional/debug',
      'content/fastrack/rhel/system-z/6/s390x/optional/os',
      'content/fastrack/rhel/system-z/6/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/6/s390x/os',
      'content/fastrack/rhel/system-z/6/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/6/i386/debug',
      'content/fastrack/rhel/workstation/6/i386/optional/debug',
      'content/fastrack/rhel/workstation/6/i386/optional/os',
      'content/fastrack/rhel/workstation/6/i386/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/6/i386/os',
      'content/fastrack/rhel/workstation/6/i386/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/debug',
      'content/fastrack/rhel/workstation/6/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/6/x86_64/optional/os',
      'content/fastrack/rhel/workstation/6/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/os',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/debug',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/os',
      'content/fastrack/rhel/workstation/6/x86_64/scalablefilesystem/source/SRPMS',
      'content/fastrack/rhel/workstation/6/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.32-71.14.1.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.32-71.14.1.el6', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-2.6.32-71.14.1.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-71.14.1.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-71.14.1.el6', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-71.14.1.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-71.14.1.el6', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-71.14.1.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-71.14.1.el6', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-firmware-2.6.32-71.14.1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-71.14.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-71.14.1.el6', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-71.14.1.el6', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-2.6.32-71.14.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-2.6.32-71.14.1.el6', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-2.6.32-71.14.1.el6', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-2.6.32-71.14.1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-bootwrapper / kernel-debug / kernel-debug-devel / etc');
}
