#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:3461. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198062);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/24");

  script_cve_id(
    "CVE-2024-26642",
    "CVE-2024-26643",
    "CVE-2024-26673",
    "CVE-2024-26735",
    "CVE-2024-26804",
    "CVE-2024-26828",
    "CVE-2024-26993"
  );
  script_xref(name:"RHSA", value:"2024:3461");

  script_name(english:"RHEL 9 : kernel (RHSA-2024:3461)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for kernel.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:3461 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: netfilter: nf_tables: mark set as dead when unbinding anonymous set with timeout
    (CVE-2024-26643)

    * kernel: netfilter: nf_tables: disallow anonymous set with timeout flag (CVE-2024-26642)

    * kernel: netfilter: nft_ct: sanitize layer 3 and 4 protocol number in custom expectations
    (CVE-2024-26673)

    * kernel: ipv6: sr: fix possible use-after-free and null-ptr-deref (CVE-2024-26735)

    * kernel: net: ip_tunnel: prevent perpetual headroom growth (CVE-2024-26804)

    * kernel: cifs: fix underflow in parse_server_interfaces() (CVE-2024-26828)

    * kernel: fs: sysfs: Fix reference leak in sysfs_break_active_protection() (CVE-2024-26993)

    Bug Fix(es):

    * lan78xx changes for 9.2.z, to fix link speed change exception and other bug fixes (JIRA:RHEL-34926)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2272816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2273423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2275600");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2278314");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_3461.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5218648");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:3461");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL kernel package based on the guidance in RHSA-2024:3461.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26828");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-26673");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(99, 191, 362, 476);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rtla");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '9.2')) audit(AUDIT_OS_NOT, 'Red Hat 9.2', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2024-26642', 'CVE-2024-26643', 'CVE-2024-26673', 'CVE-2024-26735', 'CVE-2024-26804', 'CVE-2024-26828', 'CVE-2024-26993');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2024:3461');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel9/9.2/x86_64/appstream/debug',
      'content/aus/rhel9/9.2/x86_64/appstream/os',
      'content/aus/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/aus/rhel9/9.2/x86_64/baseos/debug',
      'content/aus/rhel9/9.2/x86_64/baseos/os',
      'content/aus/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/aarch64/appstream/debug',
      'content/e4s/rhel9/9.2/aarch64/appstream/os',
      'content/e4s/rhel9/9.2/aarch64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/aarch64/baseos/debug',
      'content/e4s/rhel9/9.2/aarch64/baseos/os',
      'content/e4s/rhel9/9.2/aarch64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/appstream/debug',
      'content/e4s/rhel9/9.2/ppc64le/appstream/os',
      'content/e4s/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/ppc64le/baseos/debug',
      'content/e4s/rhel9/9.2/ppc64le/baseos/os',
      'content/e4s/rhel9/9.2/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/appstream/debug',
      'content/e4s/rhel9/9.2/s390x/appstream/os',
      'content/e4s/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/baseos/debug',
      'content/e4s/rhel9/9.2/s390x/baseos/os',
      'content/e4s/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/appstream/debug',
      'content/e4s/rhel9/9.2/x86_64/appstream/os',
      'content/e4s/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/baseos/debug',
      'content/e4s/rhel9/9.2/x86_64/baseos/os',
      'content/e4s/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/appstream/debug',
      'content/eus/rhel9/9.2/aarch64/appstream/os',
      'content/eus/rhel9/9.2/aarch64/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/baseos/debug',
      'content/eus/rhel9/9.2/aarch64/baseos/os',
      'content/eus/rhel9/9.2/aarch64/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/aarch64/codeready-builder/debug',
      'content/eus/rhel9/9.2/aarch64/codeready-builder/os',
      'content/eus/rhel9/9.2/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/appstream/debug',
      'content/eus/rhel9/9.2/ppc64le/appstream/os',
      'content/eus/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/baseos/debug',
      'content/eus/rhel9/9.2/ppc64le/baseos/os',
      'content/eus/rhel9/9.2/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/debug',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/os',
      'content/eus/rhel9/9.2/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/appstream/debug',
      'content/eus/rhel9/9.2/s390x/appstream/os',
      'content/eus/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/baseos/debug',
      'content/eus/rhel9/9.2/s390x/baseos/os',
      'content/eus/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/codeready-builder/debug',
      'content/eus/rhel9/9.2/s390x/codeready-builder/os',
      'content/eus/rhel9/9.2/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/appstream/debug',
      'content/eus/rhel9/9.2/x86_64/appstream/os',
      'content/eus/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/baseos/debug',
      'content/eus/rhel9/9.2/x86_64/baseos/os',
      'content/eus/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/debug',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/os',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-7.0.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-64k-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-64k-core-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-64k-debug-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-64k-debug-core-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-64k-debug-devel-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-64k-debug-devel-matched-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-64k-debug-modules-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-64k-debug-modules-core-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-64k-debug-modules-extra-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-64k-devel-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-64k-devel-matched-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-64k-modules-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-64k-modules-core-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-64k-modules-extra-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-core-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-core-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-matched-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-core-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-extra-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-uki-virt-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-matched-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-core-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-extra-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-uki-virt-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-core-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-devel-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-devel-matched-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-core-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-extra-5.14.0-284.67.1.el9_2', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-perf-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'rtla-5.14.0-284.67.1.el9_2', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-64k / kernel-64k-core / kernel-64k-debug / etc');
}
