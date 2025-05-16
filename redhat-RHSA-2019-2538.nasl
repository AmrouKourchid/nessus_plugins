#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2538. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128106);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id("CVE-2018-14662", "CVE-2018-16846", "CVE-2018-16889");
  script_xref(name:"RHSA", value:"2019:2538");

  script_name(english:"RHEL 7 : Red Hat Ceph Storage 3.3 (RHSA-2019:2538)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2019:2538 advisory.

    Red Hat Ceph Storage is a scalable, open, software-defined storage platform that combines the most stable
    version of the Ceph storage system with a Ceph management platform, deployment utilities, and support
    services.

    Security Fix(es):

    * ceph: ListBucket max-keys has no defined limit in the RGW codebase (CVE-2018-16846)

    * ceph: debug logging for v4 auth does not sanitize encryption keys (CVE-2018-16889)

    * ceph: authenticated user with read only permissions can steal dm-crypt / LUKS key (CVE-2018-14662)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es) and Enhancement(s):

    For detailed information on changes in this release, see the Red Hat Ceph Storage 3.3 Release Notes
    available at:

    https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/3.3/html/release_notes/index

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/3.3/html/release_notes/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44063626");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_2538.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a171f27");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:2538");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1337915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1572933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1599852");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1627567");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1628309");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1628311");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1631010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1636136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1637327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1639712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1644321");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1644461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1644610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1644847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1651054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1656908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1659611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1661504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1665334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1666822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1668478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1668896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1668897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1669838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1670527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1670785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1677269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1680144");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1680155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1685253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1685734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1686306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1695850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1696227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1696691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1696880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1700896");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1701029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702091");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702093");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1702732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1703557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1704948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1705258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1705922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1708346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1708650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1708798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1709765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1710855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1713779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1714810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1714814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1715577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1715946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1717135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1718135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1718328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1719023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1720205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1720741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1721165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1722663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1722664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1725521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1725536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1732142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1732706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1734550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1739209");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16889");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 285, 770);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-iscsi-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephmetrics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephmetrics-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libntirpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nfs-ganesha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nfs-ganesha-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nfs-ganesha-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-mon/3/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-mon/3/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-mon/3/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-osd/3/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-osd/3/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-osd/3/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-tools/3/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-tools/3/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-tools/3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-mon/3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-mon/3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-mon/3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-osd/3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-osd/3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-osd/3/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-textonly/3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-tools/3/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-tools/3/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-tools/3/source/SRPMS',
      'content/els/rhel/power-le/7/7Server/ppc64le/rhceph-mon/3/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/rhceph-mon/3/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/rhceph-mon/3/source/SRPMS',
      'content/els/rhel/power-le/7/7Server/ppc64le/rhceph-osd/3/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/rhceph-osd/3/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/rhceph-osd/3/source/SRPMS',
      'content/els/rhel/power-le/7/7Server/ppc64le/rhceph-tools/3/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/rhceph-tools/3/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/rhceph-tools/3/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/rhceph-mon/3/debug',
      'content/els/rhel/server/7/7Server/x86_64/rhceph-mon/3/os',
      'content/els/rhel/server/7/7Server/x86_64/rhceph-mon/3/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/rhceph-osd/3/debug',
      'content/els/rhel/server/7/7Server/x86_64/rhceph-osd/3/os',
      'content/els/rhel/server/7/7Server/x86_64/rhceph-osd/3/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/rhceph-tools/3/debug',
      'content/els/rhel/server/7/7Server/x86_64/rhceph-tools/3/os',
      'content/els/rhel/server/7/7Server/x86_64/rhceph-tools/3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ceph-ansible-3.2.24-1.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-iscsi-config-2.6-19.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mds-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mds-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mon-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mon-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-osd-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-osd-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-radosgw-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-radosgw-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-test-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'cephmetrics-ansible-2.0.6-1.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libntirpc-1.7.4-1.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'libntirpc-1.7.4-1.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'nfs-ganesha-2.7.4-10.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'nfs-ganesha-2.7.4-10.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'nfs-ganesha-ceph-2.7.4-10.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'nfs-ganesha-ceph-2.7.4-10.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'nfs-ganesha-rgw-2.7.4-10.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'nfs-ganesha-rgw-2.7.4-10.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'python-cephfs-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-cephfs-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rados-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rados-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rbd-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rbd-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rgw-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rgw-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python2-crypto-2.6.1-16.el7ost', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'python2-crypto-2.6.1-16.el7ost', 'cpu':'x86_64', 'release':'7', 'el_string':'el7ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'rbd-mirror-12.2.12-45.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-mirror-12.2.12-45.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph-ansible / ceph-base / ceph-common / ceph-fuse / etc');
}
