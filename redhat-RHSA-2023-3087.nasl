#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:3087. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(175895);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2022-21594",
    "CVE-2022-21599",
    "CVE-2022-21604",
    "CVE-2022-21608",
    "CVE-2022-21611",
    "CVE-2022-21617",
    "CVE-2022-21625",
    "CVE-2022-21632",
    "CVE-2022-21633",
    "CVE-2022-21637",
    "CVE-2022-21640",
    "CVE-2022-39400",
    "CVE-2022-39408",
    "CVE-2022-39410",
    "CVE-2023-21836",
    "CVE-2023-21863",
    "CVE-2023-21864",
    "CVE-2023-21865",
    "CVE-2023-21867",
    "CVE-2023-21868",
    "CVE-2023-21869",
    "CVE-2023-21870",
    "CVE-2023-21871",
    "CVE-2023-21873",
    "CVE-2023-21874",
    "CVE-2023-21875",
    "CVE-2023-21876",
    "CVE-2023-21877",
    "CVE-2023-21878",
    "CVE-2023-21879",
    "CVE-2023-21880",
    "CVE-2023-21881",
    "CVE-2023-21882",
    "CVE-2023-21883",
    "CVE-2023-21887",
    "CVE-2023-21912",
    "CVE-2023-21913",
    "CVE-2023-21917",
    "CVE-2023-21963",
    "CVE-2023-22015",
    "CVE-2023-22026",
    "CVE-2023-22028"
  );
  script_xref(name:"IAVA", value:"2023-A-0212-S");
  script_xref(name:"RHSA", value:"2023:3087");
  script_xref(name:"IAVA", value:"2023-A-0043-S");
  script_xref(name:"IAVA", value:"2022-A-0432-S");

  script_name(english:"RHEL 8 : mysql:8.0 (RHSA-2023:3087)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:3087 advisory.

    MySQL is a multi-user, multi-threaded SQL database server. It consists of the MySQL server daemon (mysqld)
    and many client programs and libraries.

    The following packages have been upgraded to a later upstream version: mysql (8.0.32). (BZ#2177734,
    BZ#2177735, BZ#2177736)

    Security Fix(es):

    * mysql: Server: Security: Privileges unspecified vulnerability (CPU Apr 2023) (CVE-2023-21912)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-21594)

    * mysql: Server: Stored Procedure unspecified vulnerability (CPU Oct 2022) (CVE-2022-21599)

    * mysql: InnoDB unspecified vulnerability (CPU Oct 2022) (CVE-2022-21604)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-21608)

    * mysql: InnoDB unspecified vulnerability (CPU Oct 2022) (CVE-2022-21611)

    * mysql: Server: Connection Handling unspecified vulnerability (CPU Oct 2022) (CVE-2022-21617)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-21625)

    * mysql: Server: Security: Privileges unspecified vulnerability (CPU Oct 2022) (CVE-2022-21632)

    * mysql: Server: Replication unspecified vulnerability (CPU Oct 2022) (CVE-2022-21633)

    * mysql: InnoDB unspecified vulnerability (CPU Oct 2022) (CVE-2022-21637)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-21640)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-39400)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-39408)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Oct 2022) (CVE-2022-39410)

    * mysql: Server: DML unspecified vulnerability (CPU Jan 2023) (CVE-2023-21836)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21863)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21864)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21865)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21867)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21868)

    * mysql: InnoDB unspecified vulnerability (CPU Jan 2023) (CVE-2023-21869)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21870)

    * mysql: InnoDB unspecified vulnerability (CPU Jan 2023) (CVE-2023-21871)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21873)

    * mysql: Server: Security: Encryption unspecified vulnerability (CPU Jan 2023) (CVE-2023-21875)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21876)

    * mysql: InnoDB unspecified vulnerability (CPU Jan 2023) (CVE-2023-21877)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21878)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21879)

    * mysql: InnoDB unspecified vulnerability (CPU Jan 2023) (CVE-2023-21880)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21881)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21883)

    * mysql: Server: GIS unspecified vulnerability (CPU Jan 2023) (CVE-2023-21887)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Apr 2023) (CVE-2023-21917)

    * mysql: Server: Thread Pooling unspecified vulnerability (CPU Jan 2023) (CVE-2023-21874)

    * mysql: Server: Optimizer unspecified vulnerability (CPU Jan 2023) (CVE-2023-21882)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * RHEL8 AppStream and Devel channels missing mecab-devel rpm (BZ#2180411)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_3087.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d27a3a23");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:3087");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142873");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2142881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162272");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162276");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162277");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162285");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162287");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2162291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2177735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2180411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188110");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188112");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21880");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-21875");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab-ipadic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mecab-ipadic-EUCJP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-errmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql-test");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','8.8'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'mysql:8.0': [
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8.10/aarch64/appstream/debug',
        'content/dist/rhel8/8.10/aarch64/appstream/os',
        'content/dist/rhel8/8.10/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/ppc64le/appstream/debug',
        'content/dist/rhel8/8.10/ppc64le/appstream/os',
        'content/dist/rhel8/8.10/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/s390x/appstream/debug',
        'content/dist/rhel8/8.10/s390x/appstream/os',
        'content/dist/rhel8/8.10/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/x86_64/appstream/debug',
        'content/dist/rhel8/8.10/x86_64/appstream/os',
        'content/dist/rhel8/8.10/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/aarch64/appstream/debug',
        'content/dist/rhel8/8.6/aarch64/appstream/os',
        'content/dist/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/ppc64le/appstream/debug',
        'content/dist/rhel8/8.6/ppc64le/appstream/os',
        'content/dist/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/s390x/appstream/debug',
        'content/dist/rhel8/8.6/s390x/appstream/os',
        'content/dist/rhel8/8.6/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/x86_64/appstream/debug',
        'content/dist/rhel8/8.6/x86_64/appstream/os',
        'content/dist/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/aarch64/appstream/debug',
        'content/dist/rhel8/8.8/aarch64/appstream/os',
        'content/dist/rhel8/8.8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/ppc64le/appstream/debug',
        'content/dist/rhel8/8.8/ppc64le/appstream/os',
        'content/dist/rhel8/8.8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/s390x/appstream/debug',
        'content/dist/rhel8/8.8/s390x/appstream/os',
        'content/dist/rhel8/8.8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/x86_64/appstream/debug',
        'content/dist/rhel8/8.8/x86_64/appstream/os',
        'content/dist/rhel8/8.8/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/aarch64/appstream/debug',
        'content/dist/rhel8/8.9/aarch64/appstream/os',
        'content/dist/rhel8/8.9/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/ppc64le/appstream/debug',
        'content/dist/rhel8/8.9/ppc64le/appstream/os',
        'content/dist/rhel8/8.9/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/s390x/appstream/debug',
        'content/dist/rhel8/8.9/s390x/appstream/os',
        'content/dist/rhel8/8.9/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/x86_64/appstream/debug',
        'content/dist/rhel8/8.9/x86_64/appstream/os',
        'content/dist/rhel8/8.9/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8/aarch64/appstream/debug',
        'content/dist/rhel8/8/aarch64/appstream/os',
        'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/appstream/debug',
        'content/dist/rhel8/8/ppc64le/appstream/os',
        'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8/s390x/appstream/debug',
        'content/dist/rhel8/8/s390x/appstream/os',
        'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8/x86_64/appstream/debug',
        'content/dist/rhel8/8/x86_64/appstream/os',
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'mecab-0.996-2.module+el8.8.0+18436+8918dd75', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-devel-0.996-2.module+el8.8.0+18436+8918dd75', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-ipadic-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de', 'release':'8', 'el_string':'el8.0.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de', 'release':'8', 'el_string':'el8.0.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-8.0.32-1.module+el8.8.0+18446+fca6280e', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-common-8.0.32-1.module+el8.8.0+18446+fca6280e', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-devel-8.0.32-1.module+el8.8.0+18446+fca6280e', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-errmsg-8.0.32-1.module+el8.8.0+18446+fca6280e', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-libs-8.0.32-1.module+el8.8.0+18446+fca6280e', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-server-8.0.32-1.module+el8.8.0+18446+fca6280e', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-test-8.0.32-1.module+el8.8.0+18446+fca6280e', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
    {
      'repo_relative_urls': [
        'content/e4s/rhel8/8.8/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.8/ppc64le/appstream/os',
        'content/e4s/rhel8/8.8/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.8/x86_64/appstream/debug',
        'content/e4s/rhel8/8.8/x86_64/appstream/os',
        'content/e4s/rhel8/8.8/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.8/aarch64/appstream/debug',
        'content/eus/rhel8/8.8/aarch64/appstream/os',
        'content/eus/rhel8/8.8/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.8/ppc64le/appstream/debug',
        'content/eus/rhel8/8.8/ppc64le/appstream/os',
        'content/eus/rhel8/8.8/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.8/s390x/appstream/debug',
        'content/eus/rhel8/8.8/s390x/appstream/os',
        'content/eus/rhel8/8.8/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.8/x86_64/appstream/debug',
        'content/eus/rhel8/8.8/x86_64/appstream/os',
        'content/eus/rhel8/8.8/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.8/x86_64/appstream/debug',
        'content/tus/rhel8/8.8/x86_64/appstream/os',
        'content/tus/rhel8/8.8/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'mecab-0.996-2.module+el8.8.0+18436+8918dd75', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-devel-0.996-2.module+el8.8.0+18436+8918dd75', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-ipadic-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de', 'sp':'8', 'release':'8', 'el_string':'el8.0.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mecab-ipadic-EUCJP-2.7.0.20070801-16.module+el8.0.0+3898+e09bb8de', 'sp':'8', 'release':'8', 'el_string':'el8.0.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-8.0.32-1.module+el8.8.0+18446+fca6280e', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-common-8.0.32-1.module+el8.8.0+18446+fca6280e', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-devel-8.0.32-1.module+el8.8.0+18446+fca6280e', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-errmsg-8.0.32-1.module+el8.8.0+18446+fca6280e', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-libs-8.0.32-1.module+el8.8.0+18446+fca6280e', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-server-8.0.32-1.module+el8.8.0+18446+fca6280e', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'mysql-test-8.0.32-1.module+el8.8.0+18446+fca6280e', 'sp':'8', 'release':'8', 'el_string':'el8.8.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/mysql');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');
if ('8.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module mysql:' + module_ver);

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      foreach var package_array ( module_array['pkgs'] ) {
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
        if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module mysql:8.0');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mecab / mecab-devel / mecab-ipadic / mecab-ipadic-EUCJP / mysql / etc');
}
