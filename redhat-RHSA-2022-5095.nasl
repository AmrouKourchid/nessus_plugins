##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:5095. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162329);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2021-3695",
    "CVE-2021-3696",
    "CVE-2021-3697",
    "CVE-2022-28733",
    "CVE-2022-28734",
    "CVE-2022-28735",
    "CVE-2022-28736",
    "CVE-2022-28737"
  );
  script_xref(name:"RHSA", value:"2022:5095");

  script_name(english:"RHEL 8 : grub2, mokutil, shim, and shim-unsigned-x64 (RHSA-2022:5095)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for grub2 / mokutil / shim / shim-unsigned-x64.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:5095 advisory.

    The grub2 packages provide version 2 of the Grand Unified Boot Loader (GRUB), a highly configurable and
    customizable boot loader with modular architecture. The packages support a variety of kernel formats, file
    systems, computer architectures, and hardware devices.

    The shim package contains a first-stage UEFI boot loader that handles chaining to a trusted full boot
    loader under secure boot environments.

    Security Fix(es):

    * grub2: Integer underflow in grub_net_recv_ip4_packets (CVE-2022-28733)

    * grub2: Crafted PNG grayscale images may lead to out-of-bounds write in heap (CVE-2021-3695)

    * grub2: Crafted PNG image may lead to out-of-bound write during huffman table handling (CVE-2021-3696)

    * grub2: Crafted JPEG image can lead to buffer underflow write in the heap (CVE-2021-3697)

    * grub2: Out-of-bound write when handling split HTTP headers (CVE-2022-28734)

    * grub2: shim_lock verifier allows non-kernel files to be loaded (CVE-2022-28735)

    * grub2: use-after-free in grub_cmd_chainloader() (CVE-2022-28736)

    * shim: Buffer overflow when loading crafted EFI images (CVE-2022-28737)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_5095.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f5a9e65");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:5095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1991685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1991686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1991687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2083339");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2090463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2090857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2090899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2092613");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL grub2 / mokutil / shim / shim-unsigned-x64 packages based on the guidance in RHSA-2022:5095.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3696");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28733");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120, 191, 416, 787, 829);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-aa64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-aa64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-aa64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-ia32-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-ia32-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-x64-cdboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-ppc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-ppc64le-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-tools-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:grub2-tools-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:shim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:shim-aa64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:shim-ia32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:shim-unsigned-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:shim-x64");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','8.6'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.6/x86_64/baseos/debug',
      'content/aus/rhel8/8.6/x86_64/baseos/os',
      'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/aarch64/baseos/debug',
      'content/e4s/rhel8/8.6/aarch64/baseos/os',
      'content/e4s/rhel8/8.6/aarch64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.6/ppc64le/baseos/os',
      'content/e4s/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/baseos/debug',
      'content/e4s/rhel8/8.6/x86_64/baseos/os',
      'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/baseos/debug',
      'content/eus/rhel8/8.6/aarch64/baseos/os',
      'content/eus/rhel8/8.6/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/baseos/debug',
      'content/eus/rhel8/8.6/ppc64le/baseos/os',
      'content/eus/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/baseos/debug',
      'content/eus/rhel8/8.6/x86_64/baseos/os',
      'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/baseos/debug',
      'content/tus/rhel8/8.6/x86_64/baseos/os',
      'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'grub2-common-2.02-123.el8_6.8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-aa64-2.02-123.el8_6.8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-aa64-cdboot-2.02-123.el8_6.8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-aa64-modules-2.02-123.el8_6.8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-ia32-2.02-123.el8_6.8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-ia32-cdboot-2.02-123.el8_6.8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-ia32-modules-2.02-123.el8_6.8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-x64-2.02-123.el8_6.8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-x64-cdboot-2.02-123.el8_6.8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-x64-modules-2.02-123.el8_6.8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-pc-2.02-123.el8_6.8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-pc-modules-2.02-123.el8_6.8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-ppc64le-2.02-123.el8_6.8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-ppc64le-modules-2.02-123.el8_6.8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-2.02-123.el8_6.8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-2.02-123.el8_6.8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-2.02-123.el8_6.8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-efi-2.02-123.el8_6.8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-extra-2.02-123.el8_6.8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-extra-2.02-123.el8_6.8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-extra-2.02-123.el8_6.8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-minimal-2.02-123.el8_6.8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-minimal-2.02-123.el8_6.8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-minimal-2.02-123.el8_6.8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'shim-aa64-15.6-1.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-28737']},
      {'reference':'shim-ia32-15.6-1.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-28737']},
      {'reference':'shim-x64-15.6-1.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-28737']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8.10/aarch64/baseos/debug',
      'content/dist/rhel8/8.10/aarch64/baseos/os',
      'content/dist/rhel8/8.10/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/ppc64le/baseos/debug',
      'content/dist/rhel8/8.10/ppc64le/baseos/os',
      'content/dist/rhel8/8.10/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/baseos/debug',
      'content/dist/rhel8/8.10/x86_64/baseos/os',
      'content/dist/rhel8/8.10/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/aarch64/baseos/debug',
      'content/dist/rhel8/8.6/aarch64/baseos/os',
      'content/dist/rhel8/8.6/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/baseos/debug',
      'content/dist/rhel8/8.6/ppc64le/baseos/os',
      'content/dist/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/baseos/debug',
      'content/dist/rhel8/8.6/x86_64/baseos/os',
      'content/dist/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/aarch64/baseos/debug',
      'content/dist/rhel8/8.8/aarch64/baseos/os',
      'content/dist/rhel8/8.8/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/baseos/debug',
      'content/dist/rhel8/8.8/ppc64le/baseos/os',
      'content/dist/rhel8/8.8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/baseos/debug',
      'content/dist/rhel8/8.8/x86_64/baseos/os',
      'content/dist/rhel8/8.8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/aarch64/baseos/debug',
      'content/dist/rhel8/8.9/aarch64/baseos/os',
      'content/dist/rhel8/8.9/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/baseos/debug',
      'content/dist/rhel8/8.9/ppc64le/baseos/os',
      'content/dist/rhel8/8.9/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/baseos/debug',
      'content/dist/rhel8/8.9/x86_64/baseos/os',
      'content/dist/rhel8/8.9/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8/aarch64/baseos/debug',
      'content/dist/rhel8/8/aarch64/baseos/os',
      'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/baseos/debug',
      'content/dist/rhel8/8/ppc64le/baseos/os',
      'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8/x86_64/baseos/debug',
      'content/dist/rhel8/8/x86_64/baseos/os',
      'content/dist/rhel8/8/x86_64/baseos/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'grub2-common-2.02-123.el8_6.8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-aa64-2.02-123.el8_6.8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-aa64-cdboot-2.02-123.el8_6.8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-aa64-modules-2.02-123.el8_6.8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-ia32-2.02-123.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-ia32-cdboot-2.02-123.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-ia32-modules-2.02-123.el8_6.8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-x64-2.02-123.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-x64-cdboot-2.02-123.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-efi-x64-modules-2.02-123.el8_6.8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-pc-2.02-123.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-pc-modules-2.02-123.el8_6.8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-ppc64le-2.02-123.el8_6.8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-ppc64le-modules-2.02-123.el8_6.8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-2.02-123.el8_6.8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-2.02-123.el8_6.8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-2.02-123.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-efi-2.02-123.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-extra-2.02-123.el8_6.8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-extra-2.02-123.el8_6.8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-extra-2.02-123.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-minimal-2.02-123.el8_6.8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-minimal-2.02-123.el8_6.8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'grub2-tools-minimal-2.02-123.el8_6.8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'cves':['CVE-2021-3695', 'CVE-2021-3696', 'CVE-2021-3697', 'CVE-2022-28733', 'CVE-2022-28734', 'CVE-2022-28735', 'CVE-2022-28736']},
      {'reference':'shim-aa64-15.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-28737']},
      {'reference':'shim-ia32-15.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-28737']},
      {'reference':'shim-x64-15.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-28737']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8.10/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.10/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.10/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.10/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.10/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.10/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.10/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.6/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.8/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.8/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.8/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.8/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/os',
      'content/dist/rhel8/8.9/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8.9/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8.9/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/os',
      'content/dist/rhel8/8.9/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8/aarch64/codeready-builder/os',
      'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'shim-unsigned-x64-15.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-28737']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/eus/rhel8/8.6/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'shim-unsigned-x64-15.6-1.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'cves':['CVE-2022-28737']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub2-common / grub2-efi-aa64 / grub2-efi-aa64-cdboot / etc');
}
