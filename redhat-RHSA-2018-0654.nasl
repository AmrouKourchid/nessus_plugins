#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0654. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108942);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/16");

  script_cve_id(
    "CVE-2017-1000255",
    "CVE-2017-1000410",
    "CVE-2017-11473",
    "CVE-2017-12190",
    "CVE-2017-12192",
    "CVE-2017-15129",
    "CVE-2017-15299",
    "CVE-2017-15306",
    "CVE-2017-16939",
    "CVE-2017-17448",
    "CVE-2017-17449",
    "CVE-2017-5753",
    "CVE-2018-1000004",
    "CVE-2018-6927"
  );
  script_xref(name:"RHSA", value:"2018:0654");

  script_name(english:"RHEL 7 : kernel-alt (RHSA-2018:0654)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2018:0654 advisory.

    The kernel-alt packages provide the Linux kernel version 4.x.

    The following packages have been upgraded to a later upstream version: kernel-alt (4.14.0). (BZ#1492717)

    Security Fix(es):

    * An industry-wide issue was found in the way many modern microprocessor designs have implemented
    speculative execution of instructions (a commonly used performance optimization). There are three primary
    variants of the issue which differ in the way the speculative execution can be exploited.

    Variant CVE-2017-5715 triggers the speculative execution by utilizing branch target injection. It relies
    on the presence of a precisely-defined instruction sequence in the privileged code as well as the fact
    that memory accesses may cause allocation into the microprocessor's data cache even for speculatively
    executed instructions that never actually commit (retire). As a result, an unprivileged attacker could use
    this flaw to cross the syscall and guest/host boundaries and read privileged memory by conducting targeted
    cache side-channel attacks. (CVE-2017-5715, Important, ARM)

    Variant CVE-2017-5753 triggers the speculative execution by performing a bounds-check bypass. It relies on
    the presence of a precisely-defined instruction sequence in the privileged code as well as the fact that
    memory accesses may cause allocation into the microprocessor's data cache even for speculatively executed
    instructions that never actually commit (retire). As a result, an unprivileged attacker could use this
    flaw to cross the syscall boundary and read privileged memory by conducting targeted cache side-channel
    attacks. (CVE-2017-5753, Important, ARM)

    Variant CVE-2017-5754 relies on the fact that, on impacted microprocessors, during speculative execution
    of instruction permission faults, exception generation triggered by a faulting access is suppressed until
    the retirement of the whole instruction block. In a combination with the fact that memory accesses may
    populate the cache even when the block is being dropped and never committed (executed), an unprivileged
    local attacker could use this flaw to read privileged (kernel space) memory by conducting targeted cache
    side-channel attacks. (CVE-2017-5754, Important, ARM)

    * kernel: memory leak when merging buffers in SCSI IO vectors (CVE-2017-12190, Moderate)

    * kernel: net: double-free and memory corruption in get_net_ns_by_id() (CVE-2017-15129, Moderate)

    * kernel: Incorrect updates of uninstantiated keys crash the kernel (CVE-2017-15299, Moderate)

    * kernel: Missing capabilities check in net/netfilter/nfnetlink_cthelper.c allows for unprivileged access
    to systemwide nfnl_cthelper_list structure (CVE-2017-17448, Moderate)

    * kernel: Missing namespace check in net/netlink/af_netlink.c allows for network monitors to observe
    systemwide activity (CVE-2017-17449, Moderate)

    * kernel: Arbitrary stack overwrite causing oops via crafted signal frame (CVE-2017-1000255, Moderate)

    * kernel: Stack information leak in the EFS element (CVE-2017-1000410, Moderate)

    * kernel: Race condition in sound system can lead to denial of service (CVE-2018-1000004, Moderate)

    * kernel: Buffer overflow in mp_override_legacy_irq() (CVE-2017-11473, Low)

    * kernel: Integer overflow in futex.c:futux_requeue can lead to denial of service or unspecified impact
    (CVE-2018-6927, Low)

    For more details about the security issue(s), including the impact, a CVSS score, and other related
    information, refer to the CVE page(s) listed in the References section.

    Red Hat would like to thank Google Project Zero for reporting CVE-2017-5715, CVE-2017-5753, and
    CVE-2017-5754; Vitaly Mayatskih for reporting CVE-2017-12190; Kirill Tkhai for reporting CVE-2017-15129;
    Michael Ellerman, Gustavo Romero, Breno Leitao, Paul Mackerras, and Cyril Bur for reporting
    CVE-2017-1000255; and Armis Labs for reporting CVE-2017-1000410.

    Additional Changes:

    See the Red Hat Enterprise Linux 7.5 Release Notes linked from References.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/7.5_Release_Notes/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74dc8666");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2018/rhsa-2018_0654.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fffe064d");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:0654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1473209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1495089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1498016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1498067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1501794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1519160");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1519778");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1519780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1519781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1525762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1525768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1531174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1535315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1544612");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16939");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-6927");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(190, 200, 284, 362, 400, 416, 476, 787);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-alt");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2017-5753', 'CVE-2017-11473', 'CVE-2017-12190', 'CVE-2017-12192', 'CVE-2017-15129', 'CVE-2017-15299', 'CVE-2017-15306', 'CVE-2017-16939', 'CVE-2017-17448', 'CVE-2017-17449', 'CVE-2017-1000255', 'CVE-2017-1000410', 'CVE-2018-6927', 'CVE-2018-1000004');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2018:0654');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/debug',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/optional/os',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/os',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/source/SRPMS',
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
      'content/fastrack/rhel/power/7/ppc64/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/os',
      'content/fastrack/rhel/power/7/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/os',
      'content/fastrack/rhel/power/7/ppc64/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/os',
      'content/fastrack/rhel/system-z/7/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/os',
      'content/fastrack/rhel/system-z/7/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-4.14.0-49.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.14.0-49.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.14.0-49.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-bootwrapper-4.14.0-49.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.14.0-49.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.14.0-49.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.14.0-49.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.14.0-49.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.14.0-49.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.14.0-49.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.14.0-49.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.14.0-49.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.14.0-49.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.14.0-49.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.14.0-49.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.14.0-49.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-4.14.0-49.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-kdump-devel-4.14.0-49.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.14.0-49.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.14.0-49.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.14.0-49.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.14.0-49.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.14.0-49.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.14.0-49.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.14.0-49.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.14.0-49.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.14.0-49.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-4.14.0-49.el7a', 'cpu':'aarch64', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-4.14.0-49.el7a', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python-perf-4.14.0-49.el7a', 'cpu':'s390x', 'release':'7', 'el_string':'el7a', 'rpm_spec_vers_cmp':TRUE}
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
