#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0487. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108276);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/04");

  script_cve_id("CVE-2017-3145");
  script_xref(name:"RHSA", value:"2018:0487");

  script_name(english:"RHEL 6 : bind (RHSA-2018:0487)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for bind.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2018:0487 advisory.

    The Berkeley Internet Name Domain (BIND) is an implementation of the Domain Name System (DNS) protocols.
    BIND includes a DNS server (named); a resolver library (routines for applications to use when interfacing
    with DNS); and tools for verifying that the DNS server is operating correctly.

    Security Fix(es):

    * bind: Improper fetch cleanup sequencing in the resolver can cause named to crash (CVE-2017-3145)

    For more details about the security issue(s), including the impact, a CVSS score, and other related
    information, refer to the CVE page(s) listed in the References section.

    Red Hat would like to thank ISC for reporting this issue. Upstream acknowledges Jayachandran Palanisamy
    (Cygate AB) as the original reporter.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2018/rhsa-2018_0487.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4f61e94");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:0487");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1534812");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL bind package based on the guidance in RHSA-2018:0487.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3145");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(416);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:6.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['6.4','6.5','6.6','6.7'])) audit(AUDIT_OS_NOT, 'Red Hat 6.4 / 6.5 / 6.6 / 6.7', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
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
      {'reference':'bind-9.8.2-0.17.rc1.el6_4.13', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-chroot-9.8.2-0.17.rc1.el6_4.13', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.17.rc1.el6_4.13', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.17.rc1.el6_4.13', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.17.rc1.el6_4.13', 'sp':'4', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.17.rc1.el6_4.13', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-9.8.2-0.17.rc1.el6_4.13', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-utils-9.8.2-0.17.rc1.el6_4.13', 'sp':'4', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/aus/rhel/server/6/6.5/x86_64/debug',
      'content/aus/rhel/server/6/6.5/x86_64/optional/debug',
      'content/aus/rhel/server/6/6.5/x86_64/optional/os',
      'content/aus/rhel/server/6/6.5/x86_64/optional/source/SRPMS',
      'content/aus/rhel/server/6/6.5/x86_64/os',
      'content/aus/rhel/server/6/6.5/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bind-9.8.2-0.23.rc1.el6_5.8', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-chroot-9.8.2-0.23.rc1.el6_5.8', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.23.rc1.el6_5.8', 'sp':'5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.23.rc1.el6_5.8', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.23.rc1.el6_5.8', 'sp':'5', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.23.rc1.el6_5.8', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-9.8.2-0.23.rc1.el6_5.8', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-utils-9.8.2-0.23.rc1.el6_5.8', 'sp':'5', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'}
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
      {'reference':'bind-9.8.2-0.30.rc1.el6_6.10', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-chroot-9.8.2-0.30.rc1.el6_6.10', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.30.rc1.el6_6.10', 'sp':'6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.30.rc1.el6_6.10', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.30.rc1.el6_6.10', 'sp':'6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.30.rc1.el6_6.10', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-9.8.2-0.30.rc1.el6_6.10', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-utils-9.8.2-0.30.rc1.el6_6.10', 'sp':'6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'}
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
      {'reference':'bind-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-chroot-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-chroot-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-chroot-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-chroot-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'ppc', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'s390', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-devel-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'ppc', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'s390', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-libs-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-sdb-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-utils-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-utils-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'ppc64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-utils-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'s390x', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
      {'reference':'bind-utils-9.8.2-0.37.rc1.el6_7.12', 'sp':'7', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'}
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
    'Advanced Update Support, Extended Update Support or Telco Extended Update Support repositories.\n' +
    'Access to these repositories requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind / bind-chroot / bind-devel / bind-libs / bind-sdb / bind-utils');
}
