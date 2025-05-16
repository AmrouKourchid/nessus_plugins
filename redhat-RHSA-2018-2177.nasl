#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2177. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(111145);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id("CVE-2018-10861", "CVE-2018-1128", "CVE-2018-1129");
  script_xref(name:"RHSA", value:"2018:2177");

  script_name(english:"RHEL 7 : Red Hat Ceph Storage 3.0 (RHSA-2018:2177)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat Ceph Storage 3.0.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2018:2177 advisory.

    Red Hat Ceph Storage is a scalable, open, software-defined storage platform
    that combines the most stable version of the Ceph storage system with a
    Ceph management platform, deployment utilities, and support services.

    Security Fix(es):

    * ceph: cephx protocol is vulnerable to replay attack (CVE-2018-1128)

    * ceph: cephx uses weak signatures (CVE-2018-1129)

    * ceph: ceph-mon does not perform authorization on OSD pool ops (CVE-2018-10861)

    For more details about the security issue(s), including the impact, a CVSS score, and other related
    information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * Previously, Ceph RADOS Gateway (RGW) instances in zones configured for multi-site replication would
    crash if configured to disable sync (rgw_run_sync_thread = false). Therefor, multi-site replication
    environments could not start dedicated non-replication RGW instances. With this update, the
    rgw_run_sync_thread option can be used to configure RGW instances that will not participate in
    replication even if their zone is replicated. (BZ#1552202)

    * Previously, when increasing max_mds from 1 to 2, if the Metadata Server (MDS) daemon was in the
    starting/resolve state for a long period of time, then restarting the MDS daemon lead to assert. This
    caused the Ceph File System (CephFS) to be in degraded state. With this update, increasing max_mds no
    longer causes CephFS to be in degraded state. (BZ#1566016)

    * Previously, the transition to containerized Ceph left some ceph-disk unit files. The files were
    harmless, but appeared as failing. With this update, executing the switch-from-non-containerized-to-
    containerized-ceph-daemons.yml playbook disables the ceph-disk unit files too. (BZ#1577846)

    * Previously, the entries_behind_master metric output from the rbd mirror image status CLI tool did
    not always reduce to zero under synthetic workloads. This could cause a false alarm that there is an issue
    with RBD mirroring replications. With this update, the metric is now updated periodically without the need
    for an explicit I/O flush in the workload. (BZ#1578509)

    * Previously, when using the pool create command with expected_num_objects, placement group (PG)
    directories were not pre-created at pool creation time as expected, resulting in performance drops when
    filestore splitting occurred. With this update, the expected_num_objects parameter is now passed through
    to filestore correctly, and PG directories for the expected number of objects are pre-created at pool
    creation time. (BZ#1579039)

    * Previously, internal RADOS Gateway (RGW) multi-site sync logic behaved incorrectly when attempting to
    sync containers with S3 object versioning enabled. Objects in versioning-enabled containers would fail to
    sync in some scenariosfor example, when using s3cmd sync to mirror a filesystem directory. With this
    update, RGW multi-site replication logic has been corrected for the known failure cases. (BZ#1580497)

    * When restarting OSD daemons, the ceph-ansible restart script goes through all the daemons by listing
    the units with systemctl list-units. Under certain circumstances, the output of the command contains extra
    spaces, which caused parsing and restart to fail. With this update, the underlying code has been changed
    to handle the extra space.

    * Previously, the Ceph RADOS Gateway (RGW) server treated negative byte-range object requests (bytes=0--
    1) as invalid. Applications that expect the AWS behavior for negative or other invalid range requests saw
    unexpected errors and could fail. With this update, a new option rgw_ignore_get_invalid_range has been
    added to RGW. When rgw_ignore_get_invalid_range is set to true, the RGW behavior for invalid range
    requests is backwards compatible with AWS.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2018/rhsa-2018_2177.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64bede54");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:2177");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1532645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1534657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1549004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1552202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1552509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1566016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1569694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1570597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1575024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1575866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1576057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1576861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1576908");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1577846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1578509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1578572");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1579039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1581403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1581573");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1585748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1593308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1594974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1598185");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat Ceph Storage 3.0 package based on the guidance in RHSA-2018:2177.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10861");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284, 285, 294);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephmetrics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephmetrics-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephmetrics-collectors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephmetrics-grafana-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs2");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'ceph-ansible-3.0.39-1.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mds-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mgr-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mon-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-osd-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-radosgw-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-test-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'cephmetrics-1.0.1-1.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'cephmetrics-ansible-1.0.1-1.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'cephmetrics-collectors-1.0.1-1.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'cephmetrics-grafana-plugins-1.0.1-1.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'nfs-ganesha-2.5.5-6.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'nfs-ganesha-ceph-2.5.5-6.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'nfs-ganesha-rgw-2.5.5-6.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'python-cephfs-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rados-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rbd-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python-rgw-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-mirror-12.2.4-30.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph-ansible / ceph-base / ceph-common / ceph-fuse / ceph-mds / etc');
}
