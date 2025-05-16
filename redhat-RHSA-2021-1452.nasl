##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:1452. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(149060);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2020-25678", "CVE-2021-3139");
  script_xref(name:"RHSA", value:"2021:1452");

  script_name(english:"RHEL 7 / 8 : Red Hat Ceph Storage security,  Update (Important) (RHSA-2021:1452)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:1452 advisory.

    Red Hat Ceph Storage is a scalable, open, software-defined storage platform that combines the most stable
    version of the Ceph storage system with a Ceph management platform, deployment utilities, and support
    services.

    The ceph-ansible package provides Ansible playbooks for installing, maintaining, and upgrading Red Hat
    Ceph Storage.

    Perf Tools is a collection of performance analysis tools, including a high performance multi-threaded
    malloc() implementation that works particularly well with threads and STL, a thread-friendly heap-checker,
    a heap profiler, and a cpu-profiler.

    The tcmu-runner packages provide a service that handles the complexity of the LIO kernel target's
    userspace passthrough interface (TCMU). It presents a C plugin API for extension modules that handle SCSI
    requests in ways not possible or suitable to be handled by LIO's in-kernel backstores.

    Security Fix(es):

    * tcmu-runner: SCSI target (LIO) write to any block on ILO backstore (CVE-2021-3139)

    * ceph: mgr modules' passwords are in clear text in mgr logs (CVE-2020-25678)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    These updated packages include numerous bug fixes. Space precludes documenting all of these changes in
    this advisory. Users are directed to the Red Hat Ceph Storage 4.2 Release Notes for information on the
    most significant of these changes:

    https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/4.2/html/release_notes/index

    All users of Red Hat Ceph Storage are advised to upgrade to these updated
    packages, which provide numerous bug fixes.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa-2021_1452.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e14d852");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:1452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1831779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1831798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1859257");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1867717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1873881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1875346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1875777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1876827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1881304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1882561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1884469");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1885441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1888630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1892109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1892265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1892824");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1901543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1901865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1901973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1903990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1908910");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1909176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1912454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1912538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1915478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1916045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1917374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1917687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1919102");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1919123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1919201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1919294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1919416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1919956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1921829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1922998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1925247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1925350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1925650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1925651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1927719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1928019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1928268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1929064");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1929714");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1930164");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1931365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1931441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1931494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1932175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1932780");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1932848");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1933963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1936210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1936647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1937088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1937997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1938105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1938669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1939766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1942142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1943471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1944611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1947142");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1949166");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3139");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 312);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-grafana-dashboards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr-dashboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr-diskprediction-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr-k8sevents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr-rook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gperftools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gperftools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libradospp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtcmu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-nbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tcmu-runner");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['7','8'])) audit(AUDIT_OS_NOT, 'Red Hat 7.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/ppc64le/rhceph-mon/4/debug',
      'content/dist/layered/rhel8/ppc64le/rhceph-mon/4/os',
      'content/dist/layered/rhel8/ppc64le/rhceph-mon/4/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhceph-osd/4/debug',
      'content/dist/layered/rhel8/ppc64le/rhceph-osd/4/os',
      'content/dist/layered/rhel8/ppc64le/rhceph-osd/4/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhceph-tools/4/debug',
      'content/dist/layered/rhel8/ppc64le/rhceph-tools/4/os',
      'content/dist/layered/rhel8/ppc64le/rhceph-tools/4/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhceph-mon/4/debug',
      'content/dist/layered/rhel8/s390x/rhceph-mon/4/os',
      'content/dist/layered/rhel8/s390x/rhceph-mon/4/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhceph-osd/4/debug',
      'content/dist/layered/rhel8/s390x/rhceph-osd/4/os',
      'content/dist/layered/rhel8/s390x/rhceph-osd/4/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhceph-tools/4/debug',
      'content/dist/layered/rhel8/s390x/rhceph-tools/4/os',
      'content/dist/layered/rhel8/s390x/rhceph-tools/4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhceph-mon/4/debug',
      'content/dist/layered/rhel8/x86_64/rhceph-mon/4/os',
      'content/dist/layered/rhel8/x86_64/rhceph-mon/4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhceph-osd/4/debug',
      'content/dist/layered/rhel8/x86_64/rhceph-osd/4/os',
      'content/dist/layered/rhel8/x86_64/rhceph-osd/4/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhceph-tools/4/debug',
      'content/dist/layered/rhel8/x86_64/rhceph-tools/4/os',
      'content/dist/layered/rhel8/x86_64/rhceph-tools/4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ceph-ansible-4.0.49.2-1.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-grafana-dashboards-14.2.11-147.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mds-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mds-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mds-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-dashboard-14.2.11-147.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-diskprediction-local-14.2.11-147.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-k8sevents-14.2.11-147.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-rook-14.2.11-147.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mon-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mon-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mon-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-osd-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-osd-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-osd-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-radosgw-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-radosgw-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-radosgw-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-test-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-test-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-test-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'gperftools-libs-2.6.3-3.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'gperftools-libs-2.6.3-3.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'gperftools-libs-2.6.3-3.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libtcmu-1.5.2-3.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'libtcmu-1.5.2-3.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'libtcmu-1.5.2-3.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-argparse-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-argparse-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-argparse-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-cephfs-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-cephfs-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-cephfs-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rados-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rados-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rados-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rbd-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rbd-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rbd-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rgw-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rgw-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rgw-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-mirror-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-mirror-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-mirror-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-14.2.11-147.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-14.2.11-147.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-14.2.11-147.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'tcmu-runner-1.5.2-3.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'tcmu-runner-1.5.2-3.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'tcmu-runner-1.5.2-3.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-mon/4/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-mon/4/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-mon/4/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-osd/4/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-osd/4/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-osd/4/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-tools/4/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-tools/4/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/rhceph-tools/4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-mon/4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-mon/4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-mon/4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-osd/4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-osd/4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-osd/4/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-tools/4/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-tools/4/os',
      'content/dist/rhel/server/7/7Server/x86_64/rhceph-tools/4/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ceph-ansible-4.0.49.2-1.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-grafana-dashboards-14.2.11-147.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mds-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mds-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-dashboard-14.2.11-147.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-diskprediction-local-14.2.11-147.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-k8sevents-14.2.11-147.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-rook-14.2.11-147.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mon-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mon-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-osd-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-osd-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-radosgw-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-radosgw-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-test-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-test-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libtcmu-1.5.2-2.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'libtcmu-1.5.2-2.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'python-ceph-argparse-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-ceph-argparse-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-cephfs-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-cephfs-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rados-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rados-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rbd-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rbd-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rgw-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rgw-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-mirror-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-mirror-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-14.2.11-147.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-14.2.11-147.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'tcmu-runner-1.5.2-2.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'tcmu-runner-1.5.2-2.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'}
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
