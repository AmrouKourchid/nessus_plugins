#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:3548. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153405);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2021-3653");
  script_xref(name:"RHSA", value:"2021:3548");

  script_name(english:"RHEL 8 : kernel (RHSA-2021:3548)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2021:3548 advisory.

    The kernel packages contain the Linux kernel, the core of any Linux operating system.

    Security Fix(es):

    * kernel: SVM nested virtualization issue in KVM (AVIC support) (CVE-2021-3653)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * RHEL8.4 Nightly[0308] - HST:STC950:Fleetwood: LPAR crashed during LPM: BUG at lib/locks.c:34!  (using
    ibmvfc) (BZ#1969792)

    * RHEL8.2 - s390/vtime: fix increased steal time accounting (BZ#1988386)

    * [FJ8.4 Bug]: Installation of RHEL8.4 hang up on a Tatlow platform while loading intel_lpss_pci module.
    (BZ#1989560)

    * kernel panic in drm_fb_helper_dirty_work() caused by a race condition qxl driver (BZ#1992839)

    * [RHEL8.4] TIOCGSERIAL ioctl fails on serial device (BZ#1993872)

    * RHEL8.4 Nightly[0208] - kernel panic when executing test case for persistent device configuration (using
    DASD) (BZ#1995206)

    * Killing ceph daemon leaving an unhealthy ocs/ocp cluster (worker node/s NotReady) (BZ#1995862)

    * ceph: potential data corruption in cephfs write_begin codepath (BZ#1996680)

    * libceph: allow addrvecs with a single NONE/blank address (BZ#1996682)

    * [iavf] traffic stops after host sets vf trust on (BZ#1997536)

    * [ice][iavf] hit some call trace and system panic when create-remove-vfs in loop (BZ#1997538)

    * Missing backport of IMA boot aggregate calculation in rhel 8.4 kernel (BZ#1997766)

    * XArray tests broken for single processor (BZ#1997997)

    * [RHEL-8.4] mlock() end up returning -EINVAL instead of -ENOMEM in rewriting the upper address bits.
    (BZ#1997998)

    * Kernel panic at n_tty_set_termios+0x30 (BZ#1997999)

    * [ice]BUG: scheduling while atomic: ifenslave/270215/0x00000200 (BZ#2000129)

    * [ice]port lost connectivity after removing from bonding (BZ#2000130)

    Enhancement(s):

    * [Mellanox 8.5 FEAT] mlx5: drivers update upto Linux v5.12 (BZ#1983681)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa-2021_3548.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d4eff34");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:3548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1983686");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3653");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(862);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','8.4'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2021-3653');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2021:3548');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.4/x86_64/baseos/debug',
      'content/aus/rhel8/8.4/x86_64/baseos/os',
      'content/aus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/aarch64/baseos/debug',
      'content/e4s/rhel8/8.4/aarch64/baseos/os',
      'content/e4s/rhel8/8.4/aarch64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.4/ppc64le/baseos/os',
      'content/e4s/rhel8/8.4/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/s390x/baseos/debug',
      'content/e4s/rhel8/8.4/s390x/baseos/os',
      'content/e4s/rhel8/8.4/s390x/baseos/source/SRPMS',
      'content/e4s/rhel8/8.4/x86_64/baseos/debug',
      'content/e4s/rhel8/8.4/x86_64/baseos/os',
      'content/e4s/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/baseos/debug',
      'content/eus/rhel8/8.4/aarch64/baseos/os',
      'content/eus/rhel8/8.4/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.4/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/baseos/debug',
      'content/eus/rhel8/8.4/ppc64le/baseos/os',
      'content/eus/rhel8/8.4/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.4/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/s390x/baseos/debug',
      'content/eus/rhel8/8.4/s390x/baseos/os',
      'content/eus/rhel8/8.4/s390x/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/s390x/codeready-builder/debug',
      'content/eus/rhel8/8.4/s390x/codeready-builder/os',
      'content/eus/rhel8/8.4/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/baseos/debug',
      'content/eus/rhel8/8.4/x86_64/baseos/os',
      'content/eus/rhel8/8.4/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.4/x86_64/codeready-builder/source/SRPMS',
      'content/tus/rhel8/8.4/x86_64/baseos/debug',
      'content/tus/rhel8/8.4/x86_64/baseos/os',
      'content/tus/rhel8/8.4/x86_64/baseos/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-core-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-cross-headers-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-core-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-extra-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-extra-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-305.19.1.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-305.19.1.el8_4', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-305.19.1.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-305.19.1.el8_4', 'sp':'4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-305.19.1.el8_4', 'sp':'4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-305.19.1.el8_4', 'sp':'4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-4.18.0-305.19.1.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-core-4.18.0-305.19.1.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-devel-4.18.0-305.19.1.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-4.18.0-305.19.1.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-305.19.1.el8_4', 'sp':'4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-perf-4.18.0-305.19.1.el8_4', 'sp':'4', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8.10/aarch64/baseos/debug',
      'content/dist/rhel8/8.10/aarch64/baseos/os',
      'content/dist/rhel8/8.10/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.10/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.10/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.10/ppc64le/baseos/debug',
      'content/dist/rhel8/8.10/ppc64le/baseos/os',
      'content/dist/rhel8/8.10/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.10/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.10/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.10/s390x/baseos/debug',
      'content/dist/rhel8/8.10/s390x/baseos/os',
      'content/dist/rhel8/8.10/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/s390x/codeready-builder/debug',
      'content/dist/rhel8/8.10/s390x/codeready-builder/os',
      'content/dist/rhel8/8.10/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/baseos/debug',
      'content/dist/rhel8/8.10/x86_64/baseos/os',
      'content/dist/rhel8/8.10/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/aarch64/baseos/debug',
      'content/dist/rhel8/8.6/aarch64/baseos/os',
      'content/dist/rhel8/8.6/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/baseos/debug',
      'content/dist/rhel8/8.6/ppc64le/baseos/os',
      'content/dist/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.6/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/s390x/baseos/debug',
      'content/dist/rhel8/8.6/s390x/baseos/os',
      'content/dist/rhel8/8.6/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/s390x/codeready-builder/debug',
      'content/dist/rhel8/8.6/s390x/codeready-builder/os',
      'content/dist/rhel8/8.6/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/baseos/debug',
      'content/dist/rhel8/8.6/x86_64/baseos/os',
      'content/dist/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/aarch64/baseos/debug',
      'content/dist/rhel8/8.8/aarch64/baseos/os',
      'content/dist/rhel8/8.8/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/baseos/debug',
      'content/dist/rhel8/8.8/ppc64le/baseos/os',
      'content/dist/rhel8/8.8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.8/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.8/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/s390x/baseos/debug',
      'content/dist/rhel8/8.8/s390x/baseos/os',
      'content/dist/rhel8/8.8/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/s390x/codeready-builder/debug',
      'content/dist/rhel8/8.8/s390x/codeready-builder/os',
      'content/dist/rhel8/8.8/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/baseos/debug',
      'content/dist/rhel8/8.8/x86_64/baseos/os',
      'content/dist/rhel8/8.8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/aarch64/baseos/debug',
      'content/dist/rhel8/8.9/aarch64/baseos/os',
      'content/dist/rhel8/8.9/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/baseos/debug',
      'content/dist/rhel8/8.9/ppc64le/baseos/os',
      'content/dist/rhel8/8.9/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.9/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.9/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/s390x/baseos/debug',
      'content/dist/rhel8/8.9/s390x/baseos/os',
      'content/dist/rhel8/8.9/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/s390x/codeready-builder/debug',
      'content/dist/rhel8/8.9/s390x/codeready-builder/os',
      'content/dist/rhel8/8.9/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/baseos/debug',
      'content/dist/rhel8/8.9/x86_64/baseos/os',
      'content/dist/rhel8/8.9/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/aarch64/baseos/debug',
      'content/dist/rhel8/8/aarch64/baseos/os',
      'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8/aarch64/codeready-builder/os',
      'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/baseos/debug',
      'content/dist/rhel8/8/ppc64le/baseos/os',
      'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/s390x/baseos/debug',
      'content/dist/rhel8/8/s390x/baseos/os',
      'content/dist/rhel8/8/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8/s390x/codeready-builder/debug',
      'content/dist/rhel8/8/s390x/codeready-builder/os',
      'content/dist/rhel8/8/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/x86_64/baseos/debug',
      'content/dist/rhel8/8/x86_64/baseos/os',
      'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/aarch64/baseos/debug',
      'content/public/ubi/dist/ubi8/8/aarch64/baseos/os',
      'content/public/ubi/dist/ubi8/8/aarch64/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/aarch64/codeready-builder/debug',
      'content/public/ubi/dist/ubi8/8/aarch64/codeready-builder/os',
      'content/public/ubi/dist/ubi8/8/aarch64/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/ppc64le/baseos/debug',
      'content/public/ubi/dist/ubi8/8/ppc64le/baseos/os',
      'content/public/ubi/dist/ubi8/8/ppc64le/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/ppc64le/codeready-builder/debug',
      'content/public/ubi/dist/ubi8/8/ppc64le/codeready-builder/os',
      'content/public/ubi/dist/ubi8/8/ppc64le/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/s390x/baseos/debug',
      'content/public/ubi/dist/ubi8/8/s390x/baseos/os',
      'content/public/ubi/dist/ubi8/8/s390x/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/s390x/codeready-builder/debug',
      'content/public/ubi/dist/ubi8/8/s390x/codeready-builder/os',
      'content/public/ubi/dist/ubi8/8/s390x/codeready-builder/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/x86_64/baseos/debug',
      'content/public/ubi/dist/ubi8/8/x86_64/baseos/os',
      'content/public/ubi/dist/ubi8/8/x86_64/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi8/8/x86_64/codeready-builder/debug',
      'content/public/ubi/dist/ubi8/8/x86_64/codeready-builder/os',
      'content/public/ubi/dist/ubi8/8/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-core-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-cross-headers-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-core-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-extra-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-extra-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-305.19.1.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-305.19.1.el8_4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-305.19.1.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-305.19.1.el8_4', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-305.19.1.el8_4', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-305.19.1.el8_4', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-4.18.0-305.19.1.el8_4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-core-4.18.0-305.19.1.el8_4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-devel-4.18.0-305.19.1.el8_4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-4.18.0-305.19.1.el8_4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-305.19.1.el8_4', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-perf-4.18.0-305.19.1.el8_4', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-core / kernel-cross-headers / etc');
}
