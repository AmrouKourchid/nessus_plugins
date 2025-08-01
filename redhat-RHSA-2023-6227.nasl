#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:6227. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184133);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2023-3354");
  script_xref(name:"RHSA", value:"2023:6227");

  script_name(english:"RHEL 9 : qemu-kvm (RHSA-2023:6227)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for qemu-kvm.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2023:6227 advisory.

    Kernel-based Virtual Machine (KVM) is a full virtualization solution for Linux on a variety of
    architectures. The qemu-kvm packages provide the user-space component for running virtual machines that
    use KVM.

    Security Fix(es):

    * QEMU: VNC: improper I/O watch removal in TLS handshake can lead to remote unauthenticated denial of
    service (CVE-2023-3354)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_6227.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef5fab73");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2216478");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:6227");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL qemu-kvm package based on the guidance in RHSA-2023:6227.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3354");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(476);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-audio-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-display-virtio-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-display-virtio-gpu-ccw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-display-virtio-gpu-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-display-virtio-gpu-pci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-display-virtio-gpu-pci-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-display-virtio-vga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-display-virtio-vga-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-usb-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-device-usb-redirect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-ui-egl-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-ui-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-pr-helper");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '9.0')) audit(AUDIT_OS_NOT, 'Red Hat 9.0', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/e4s/rhel9/9.0/aarch64/appstream/debug',
      'content/e4s/rhel9/9.0/aarch64/appstream/os',
      'content/e4s/rhel9/9.0/aarch64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.0/s390x/appstream/debug',
      'content/e4s/rhel9/9.0/s390x/appstream/os',
      'content/e4s/rhel9/9.0/s390x/appstream/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/appstream/debug',
      'content/e4s/rhel9/9.0/x86_64/appstream/os',
      'content/e4s/rhel9/9.0/x86_64/appstream/source/SRPMS',
      'content/eus/rhel9/9.0/aarch64/appstream/debug',
      'content/eus/rhel9/9.0/aarch64/appstream/os',
      'content/eus/rhel9/9.0/aarch64/appstream/source/SRPMS',
      'content/eus/rhel9/9.0/s390x/appstream/debug',
      'content/eus/rhel9/9.0/s390x/appstream/os',
      'content/eus/rhel9/9.0/s390x/appstream/source/SRPMS',
      'content/eus/rhel9/9.0/x86_64/appstream/debug',
      'content/eus/rhel9/9.0/x86_64/appstream/os',
      'content/eus/rhel9/9.0/x86_64/appstream/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'qemu-guest-agent-6.2.0-11.el9_0.8', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-img-6.2.0-11.el9_0.8', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-audio-pa-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-audio-pa-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-audio-pa-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-curl-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-curl-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-curl-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-block-rbd-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-common-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-common-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-common-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-core-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-core-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-core-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-ccw-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-gl-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-gl-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-gl-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-pci-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-pci-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-pci-gl-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-gpu-pci-gl-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-vga-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-display-virtio-vga-gl-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-usb-host-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-usb-host-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-usb-host-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-device-usb-redirect-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-docs-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-docs-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-docs-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-tools-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-tools-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-tools-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-ui-egl-headless-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-kvm-ui-opengl-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-pr-helper-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-pr-helper-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'},
      {'reference':'qemu-pr-helper-6.2.0-11.el9_0.8', 'sp':'0', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'17'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu-guest-agent / qemu-img / qemu-kvm / qemu-kvm-audio-pa / etc');
}
