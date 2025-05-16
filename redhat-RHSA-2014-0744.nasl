#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0744. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79030);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2013-4148",
    "CVE-2013-4151",
    "CVE-2013-4535",
    "CVE-2013-4536",
    "CVE-2013-4541",
    "CVE-2013-4542",
    "CVE-2013-6399",
    "CVE-2014-0182",
    "CVE-2014-2894",
    "CVE-2014-3461"
  );
  script_bugtraq_id(
    66932,
    66976,
    67392,
    67394,
    67483
  );
  script_xref(name:"RHSA", value:"2014:0744");

  script_name(english:"RHEL 6 : qemu-kvm-rhev (RHSA-2014:0744)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for qemu-kvm-rhev.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2014:0744 advisory.

    KVM (Kernel-based Virtual Machine) is a full virtualization solution for
    Linux on AMD64 and Intel 64 systems. The qemu-kvm-rhev package provides the
    user-space component for running virtual machines using KVM in environments
    managed by Red Hat Enterprise Virtualization Manager.

    Multiple buffer overflow, input validation, and out-of-bounds write flaws
    were found in the way the virtio, virtio-net, virtio-scsi, and usb drivers
    of QEMU handled state loading after migration. A user able to alter the
    savevm data (either on the disk or over the wire during migration) could
    use either of these flaws to corrupt QEMU process memory on the
    (destination) host, which could potentially result in arbitrary code
    execution on the host with the privileges of the QEMU process.
    (CVE-2013-4148, CVE-2013-4151, CVE-2013-4535, CVE-2013-4536, CVE-2013-4541,
    CVE-2013-4542, CVE-2013-6399, CVE-2014-0182, CVE-2014-3461)

    An out-of-bounds memory access flaw was found in the way QEMU's IDE device
    driver handled the execution of SMART EXECUTE OFFLINE commands.
    A privileged guest user could use this flaw to corrupt QEMU process memory
    on the host, which could potentially result in arbitrary code execution on
    the host with the privileges of the QEMU process. (CVE-2014-2894)

    The CVE-2013-4148, CVE-2013-4151, CVE-2013-4535, CVE-2013-4536,
    CVE-2013-4541, CVE-2013-4542, CVE-2013-6399, CVE-2014-0182, and
    CVE-2014-3461 issues were discovered by Michael S. Tsirkin of Red Hat,
    Anthony Liguori, and Michael Roth.

    All users of qemu-kvm-rhev are advised to upgrade to these updated
    packages, which contain backported patches to correct these issues. After
    installing this update, shut down all running virtual machines. Once all
    virtual machines have shut down, start them again for this update to take
    effect.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2014/rhsa-2014_0744.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9315b103");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:0744");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1066334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1066342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1066361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1066382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1066384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1066401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1087971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1088986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1096821");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL qemu-kvm-rhev package based on the guidance in RHSA-2014:0744.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0182");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-4535");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 122, 787);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redhat_repos.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

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

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/client/6/6Client/x86_64/rhev-agent/3/debug',
      'content/dist/rhel/client/6/6Client/x86_64/rhev-agent/3/os',
      'content/dist/rhel/client/6/6Client/x86_64/rhev-agent/3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-agent/3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-agent/3/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-agent/3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-mgmt-agent/3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-mgmt-agent/3/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhev-mgmt-agent/3/source/SRPMS',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhev-agent/3/debug',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhev-agent/3/os',
      'content/dist/rhel/workstation/6/6Workstation/x86_64/rhev-agent/3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'qemu-img-rhev-0.12.1.2-2.415.el6_5.10', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ovirt-'},
      {'reference':'qemu-kvm-rhev-0.12.1.2-2.415.el6_5.10', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ovirt-'},
      {'reference':'qemu-kvm-rhev-tools-0.12.1.2-2.415.el6_5.10', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ovirt-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu-img-rhev / qemu-kvm-rhev / qemu-kvm-rhev-tools');
}
