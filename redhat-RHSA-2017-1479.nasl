#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1479. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100890);
  script_version("3.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2017-1000366");
  script_xref(name:"RHSA", value:"2017:1479");

  script_name(english:"RHEL 5 / 6 / 7 : glibc (RHSA-2017:1479)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for glibc.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 / 6 / 7 host has packages installed that are affected by a vulnerability as
referenced in the RHSA-2017:1479 advisory.

    The glibc packages provide the standard C libraries (libc), POSIX thread libraries (libpthread), standard
    math libraries (libm), and the name service cache daemon (nscd) used by multiple programs on the system.
    Without these libraries, the Linux system cannot function correctly.

    Security Fix(es):

    * A flaw was found in the way memory was being allocated on the stack for user space binaries. If heap (or
    different memory region) and stack memory regions were adjacent to each other, an attacker could use this
    flaw to jump over the stack guard gap, cause controlled memory corruption on process stack or the adjacent
    memory region, and thus increase their privileges on the system. This is glibc-side mitigation which
    blocks processing of LD_LIBRARY_PATH for programs running in secure-execution mode and reduces the number
    of allocations performed by the processing of LD_AUDIT, LD_PRELOAD, and LD_HWCAP_MASK, making successful
    exploitation of this issue more difficult. (CVE-2017-1000366)

    Red Hat would like to thank Qualys Research Labs for reporting this issue.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2017/rhsa-2017_1479.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4931cf0");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/vulnerabilities/stackguard");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1452543");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:1479");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL glibc package based on the guidance in RHSA-2017:1479.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000366");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_els:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:6.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['5','5.9','6.2','6.4','6.5','6.6','6.7','7.2'])) audit(AUDIT_OS_NOT, 'Red Hat 5.x / 5.x / 6.x / 6.x / 6.x / 6.x / 6.x / 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/5/5.9/i386/debug',
      'content/aus/rhel/server/5/5.9/i386/os',
      'content/aus/rhel/server/5/5.9/i386/source/SRPMS',
      'content/aus/rhel/server/5/5.9/x86_64/debug',
      'content/aus/rhel/server/5/5.9/x86_64/os',
      'content/aus/rhel/server/5/5.9/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glibc-2.5-107.el5_9.9', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.5-107.el5_9.9', 'sp':'9', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.5-107.el5_9.9', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.5-107.el5_9.9', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.5-107.el5_9.9', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.5-107.el5_9.9', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.5-107.el5_9.9', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.5-107.el5_9.9', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.5-107.el5_9.9', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.5-107.el5_9.9', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.5-107.el5_9.9', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.5-107.el5_9.9', 'sp':'9', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.5-107.el5_9.9', 'sp':'9', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.2/x86_64/debug',
      'content/aus/rhel/server/6/6.2/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.2/x86_64/optional/os',
      'content/aus/rhel/server/6/6.2/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.2/x86_64/os',
      'content/aus/rhel/server/6/6.2/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glibc-2.12-1.47.el6_2.18', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.12-1.47.el6_2.18', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.12-1.47.el6_2.18', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.12-1.47.el6_2.18', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.12-1.47.el6_2.18', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.12-1.47.el6_2.18', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.12-1.47.el6_2.18', 'sp':'2', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.12-1.47.el6_2.18', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.12-1.47.el6_2.18', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.12-1.47.el6_2.18', 'sp':'2', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.4/x86_64/debug',
      'content/aus/rhel/server/6/6.4/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.4/x86_64/optional/os',
      'content/aus/rhel/server/6/6.4/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.4/x86_64/os',
      'content/aus/rhel/server/6/6.4/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glibc-2.12-1.107.el6_4.10', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.12-1.107.el6_4.10', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.12-1.107.el6_4.10', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.12-1.107.el6_4.10', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.12-1.107.el6_4.10', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.12-1.107.el6_4.10', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.12-1.107.el6_4.10', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.12-1.107.el6_4.10', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.12-1.107.el6_4.10', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.12-1.107.el6_4.10', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.5/x86_64/debug',
      'content/aus/rhel/server/6/6.5/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.5/x86_64/optional/os',
      'content/aus/rhel/server/6/6.5/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.5/x86_64/os',
      'content/aus/rhel/server/6/6.5/x86_64/source/SRPMS',
      'content/tus/rhel/server/6/6.5/x86_64/debug',
      'content/tus/rhel/server/6/6.5/x86_64/optional/debug',
      'content/tus/rhel/server/6/6.5/x86_64/optional/os',
      'content/tus/rhel/server/6/6.5/x86_64/optional/source/SRPMS',
      'content/tus/rhel/server/6/6.5/x86_64/os',
      'content/tus/rhel/server/6/6.5/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glibc-2.12-1.132.el6_5.9', 'sp':'5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.12-1.132.el6_5.9', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.12-1.132.el6_5.9', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.12-1.132.el6_5.9', 'sp':'5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.12-1.132.el6_5.9', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.12-1.132.el6_5.9', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.12-1.132.el6_5.9', 'sp':'5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.12-1.132.el6_5.9', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.12-1.132.el6_5.9', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.12-1.132.el6_5.9', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.6/x86_64/debug',
      'content/aus/rhel/server/6/6.6/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.6/x86_64/optional/os',
      'content/aus/rhel/server/6/6.6/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.6/x86_64/os',
      'content/aus/rhel/server/6/6.6/x86_64/source/SRPMS',
      'content/tus/rhel/server/6/6.6/x86_64/debug',
      'content/tus/rhel/server/6/6.6/x86_64/optional/debug',
      'content/tus/rhel/server/6/6.6/x86_64/optional/os',
      'content/tus/rhel/server/6/6.6/x86_64/optional/source/SRPMS',
      'content/tus/rhel/server/6/6.6/x86_64/os',
      'content/tus/rhel/server/6/6.6/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glibc-2.12-1.149.el6_6.12', 'sp':'6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.12-1.149.el6_6.12', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.12-1.149.el6_6.12', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.12-1.149.el6_6.12', 'sp':'6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.12-1.149.el6_6.12', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.12-1.149.el6_6.12', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.12-1.149.el6_6.12', 'sp':'6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.12-1.149.el6_6.12', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.12-1.149.el6_6.12', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.12-1.149.el6_6.12', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/7/7.2/x86_64/debug',
      'content/aus/rhel/server/7/7.2/x86_64/optional/debug',
      'content/aus/rhel/server/7/7.2/x86_64/optional/os',
      'content/aus/rhel/server/7/7.2/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/7/7.2/x86_64/os',
      'content/aus/rhel/server/7/7.2/x86_64/source/SRPMS',
      'content/e4s/rhel/server/7/7.2/x86_64/debug',
      'content/e4s/rhel/server/7/7.2/x86_64/highavailability/debug',
      'content/e4s/rhel/server/7/7.2/x86_64/highavailability/os',
      'content/e4s/rhel/server/7/7.2/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel/server/7/7.2/x86_64/optional/debug',
      'content/e4s/rhel/server/7/7.2/x86_64/optional/os',
      'content/e4s/rhel/server/7/7.2/x86_64/optional/source/SRPMS',
      'content/e4s/rhel/server/7/7.2/x86_64/os',
      'content/e4s/rhel/server/7/7.2/x86_64/source/SRPMS',
      'content/eus/rhel/computenode/7/7.2/x86_64/debug',
      'content/eus/rhel/computenode/7/7.2/x86_64/optional/debug',
      'content/eus/rhel/computenode/7/7.2/x86_64/optional/os',
      'content/eus/rhel/computenode/7/7.2/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/7/7.2/x86_64/os',
      'content/eus/rhel/computenode/7/7.2/x86_64/source/SRPMS',
      'content/eus/rhel/power-le/7/7.2/ppc64le/debug',
      'content/eus/rhel/power-le/7/7.2/ppc64le/optional/debug',
      'content/eus/rhel/power-le/7/7.2/ppc64le/optional/os',
      'content/eus/rhel/power-le/7/7.2/ppc64le/optional/source/SRPMS',
      'content/eus/rhel/power-le/7/7.2/ppc64le/os',
      'content/eus/rhel/power-le/7/7.2/ppc64le/source/SRPMS',
      'content/eus/rhel/power/7/7.2/ppc64/debug',
      'content/eus/rhel/power/7/7.2/ppc64/optional/debug',
      'content/eus/rhel/power/7/7.2/ppc64/optional/os',
      'content/eus/rhel/power/7/7.2/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/7/7.2/ppc64/os',
      'content/eus/rhel/power/7/7.2/ppc64/source/SRPMS',
      'content/eus/rhel/server/7/7.2/x86_64/debug',
      'content/eus/rhel/server/7/7.2/x86_64/highavailability/debug',
      'content/eus/rhel/server/7/7.2/x86_64/highavailability/os',
      'content/eus/rhel/server/7/7.2/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/7/7.2/x86_64/optional/debug',
      'content/eus/rhel/server/7/7.2/x86_64/optional/os',
      'content/eus/rhel/server/7/7.2/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/7/7.2/x86_64/os',
      'content/eus/rhel/server/7/7.2/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/7/7.2/s390x/debug',
      'content/eus/rhel/system-z/7/7.2/s390x/optional/debug',
      'content/eus/rhel/system-z/7/7.2/s390x/optional/os',
      'content/eus/rhel/system-z/7/7.2/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/7/7.2/s390x/os',
      'content/eus/rhel/system-z/7/7.2/s390x/source/SRPMS',
      'content/tus/rhel/server/7/7.2/x86_64/debug',
      'content/tus/rhel/server/7/7.2/x86_64/optional/debug',
      'content/tus/rhel/server/7/7.2/x86_64/optional/os',
      'content/tus/rhel/server/7/7.2/x86_64/optional/source/SRPMS',
      'content/tus/rhel/server/7/7.2/x86_64/os',
      'content/tus/rhel/server/7/7.2/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glibc-2.17-106.el7_2.9', 'sp':'2', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.17-106.el7_2.9', 'sp':'2', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.17-106.el7_2.9', 'sp':'2', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.17-106.el7_2.9', 'sp':'2', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.17-106.el7_2.9', 'sp':'2', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.17-106.el7_2.9', 'sp':'2', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.17-106.el7_2.9', 'sp':'2', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.17-106.el7_2.9', 'sp':'2', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.17-106.el7_2.9', 'sp':'2', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.17-106.el7_2.9', 'sp':'2', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.17-106.el7_2.9', 'sp':'2', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.17-106.el7_2.9', 'sp':'2', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.17-106.el7_2.9', 'sp':'2', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.17-106.el7_2.9', 'sp':'2', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.17-106.el7_2.9', 'sp':'2', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.17-106.el7_2.9', 'sp':'2', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.17-106.el7_2.9', 'sp':'2', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.17-106.el7_2.9', 'sp':'2', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.17-106.el7_2.9', 'sp':'2', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.17-106.el7_2.9', 'sp':'2', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.17-106.el7_2.9', 'sp':'2', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/els/rhel/server/5/5Server/i386/debug',
      'content/els/rhel/server/5/5Server/i386/os',
      'content/els/rhel/server/5/5Server/i386/source/SRPMS',
      'content/els/rhel/server/5/5Server/x86_64/debug',
      'content/els/rhel/server/5/5Server/x86_64/os',
      'content/els/rhel/server/5/5Server/x86_64/source/SRPMS',
      'content/els/rhel/system-z/5/5Server/s390x/debug',
      'content/els/rhel/system-z/5/5Server/s390x/os',
      'content/els/rhel/system-z/5/5Server/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glibc-2.5-123.el5_11.4', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.5-123.el5_11.4', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.5-123.el5_11.4', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.5-123.el5_11.4', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.5-123.el5_11.4', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.5-123.el5_11.4', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.5-123.el5_11.4', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.5-123.el5_11.4', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.5-123.el5_11.4', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.5-123.el5_11.4', 'cpu':'s390', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.5-123.el5_11.4', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.5-123.el5_11.4', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.5-123.el5_11.4', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.5-123.el5_11.4', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.5-123.el5_11.4', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.5-123.el5_11.4', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.5-123.el5_11.4', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.5-123.el5_11.4', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.5-123.el5_11.4', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.5-123.el5_11.4', 'cpu':'s390x', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.5-123.el5_11.4', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/eus/rhel/computenode/6/6.7/x86_64/debug',
      'content/eus/rhel/computenode/6/6.7/x86_64/optional/debug',
      'content/eus/rhel/computenode/6/6.7/x86_64/optional/os',
      'content/eus/rhel/computenode/6/6.7/x86_64/optional/source/SRPMS',
      'content/eus/rhel/computenode/6/6.7/x86_64/os',
      'content/eus/rhel/computenode/6/6.7/x86_64/sfs/debug',
      'content/eus/rhel/computenode/6/6.7/x86_64/sfs/os',
      'content/eus/rhel/computenode/6/6.7/x86_64/sfs/source/SRPMS',
      'content/eus/rhel/computenode/6/6.7/x86_64/source/SRPMS',
      'content/eus/rhel/power/6/6.7/ppc64/debug',
      'content/eus/rhel/power/6/6.7/ppc64/optional/debug',
      'content/eus/rhel/power/6/6.7/ppc64/optional/os',
      'content/eus/rhel/power/6/6.7/ppc64/optional/source/SRPMS',
      'content/eus/rhel/power/6/6.7/ppc64/os',
      'content/eus/rhel/power/6/6.7/ppc64/source/SRPMS',
      'content/eus/rhel/server/6/6.7/i386/debug',
      'content/eus/rhel/server/6/6.7/i386/highavailability/debug',
      'content/eus/rhel/server/6/6.7/i386/highavailability/os',
      'content/eus/rhel/server/6/6.7/i386/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.7/i386/loadbalancer/debug',
      'content/eus/rhel/server/6/6.7/i386/loadbalancer/os',
      'content/eus/rhel/server/6/6.7/i386/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.7/i386/optional/debug',
      'content/eus/rhel/server/6/6.7/i386/optional/os',
      'content/eus/rhel/server/6/6.7/i386/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.7/i386/os',
      'content/eus/rhel/server/6/6.7/i386/resilientstorage/debug',
      'content/eus/rhel/server/6/6.7/i386/resilientstorage/os',
      'content/eus/rhel/server/6/6.7/i386/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.7/i386/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/debug',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/debug',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/highavailability/debug',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/highavailability/os',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/os',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/scalablefilesystem/debug',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/scalablefilesystem/os',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/scalablefilesystem/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/eus-ext/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/highavailability/debug',
      'content/eus/rhel/server/6/6.7/x86_64/highavailability/os',
      'content/eus/rhel/server/6/6.7/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/loadbalancer/debug',
      'content/eus/rhel/server/6/6.7/x86_64/loadbalancer/os',
      'content/eus/rhel/server/6/6.7/x86_64/loadbalancer/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/optional/debug',
      'content/eus/rhel/server/6/6.7/x86_64/optional/os',
      'content/eus/rhel/server/6/6.7/x86_64/optional/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/os',
      'content/eus/rhel/server/6/6.7/x86_64/resilientstorage/debug',
      'content/eus/rhel/server/6/6.7/x86_64/resilientstorage/os',
      'content/eus/rhel/server/6/6.7/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/sap-hana/debug',
      'content/eus/rhel/server/6/6.7/x86_64/sap-hana/os',
      'content/eus/rhel/server/6/6.7/x86_64/sap-hana/source/SRPMS',
      'content/eus/rhel/server/6/6.7/x86_64/source/SRPMS',
      'content/eus/rhel/system-z/6/6.7/s390x/debug',
      'content/eus/rhel/system-z/6/6.7/s390x/optional/debug',
      'content/eus/rhel/system-z/6/6.7/s390x/optional/os',
      'content/eus/rhel/system-z/6/6.7/s390x/optional/source/SRPMS',
      'content/eus/rhel/system-z/6/6.7/s390x/os',
      'content/eus/rhel/system-z/6/6.7/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glibc-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'ppc', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'s390', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'ppc', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'s390', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'ppc', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'s390', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.12-1.166.el6_7.8', 'sp':'7', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc / glibc-common / glibc-devel / glibc-headers / glibc-static / etc');
}
