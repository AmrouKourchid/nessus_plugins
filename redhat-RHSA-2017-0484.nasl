#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0484. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(97928);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2015-1795");
  script_xref(name:"RHSA", value:"2017:0484");

  script_name(english:"RHEL 6 : Red Hat Gluster Storage 3.2.0 (RHSA-2017:0484)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2017:0484 advisory.

    Red Hat Gluster Storage is a software only scale-out storage solution that provides flexible and
    affordable unstructured data storage. It unifies data storage and infrastructure, increases performance,
    and improves availability and manageability to meet enterprise-level storage challenges.

    The following packages have been upgraded to a later upstream version: glusterfs (3.8.4), redhat-storage-
    server (3.2.0.3). (BZ#1362373)

    Security Fix(es):

    * It was found that glusterfs-server RPM package would write file with predictable name into world
    readable /tmp directory. A local attacker could potentially use this flaw to escalate their privileges to
    root by modifying the shell script during the installation of the glusterfs-server package.
    (CVE-2015-1795)

    This issue was discovered by Florian Weimer of Red Hat Product Security.

    Bug Fix(es):

    * Bricks remain stopped if server quorum is no longer met, or if server quorum is disabled, to ensure that
    bricks in maintenance are not started incorrectly. (BZ#1340995)

    * The metadata cache translator has been updated to improve Red Hat Gluster Storage performance when
    reading small files. (BZ#1427783)

    * The 'gluster volume add-brick' command is no longer allowed when the replica count has increased and any
    replica bricks are unavailable. (BZ#1404989)

    * Split-brain resolution commands work regardless of whether client-side heal or the self-heal daemon are
    enabled. (BZ#1403840)

    Enhancement(s):

    * Red Hat Gluster Storage now provides Transport Layer Security support for Samba and NFS-Ganesha.
    (BZ#1340608, BZ#1371475)

    * A new reset-sync-time option enables resetting the sync time attribute to zero when required.
    (BZ#1205162)

    * Tiering demotions are now triggered at most 5 seconds after a hi-watermark breach event. Administrators
    can use the cluster.tier-query-limit volume parameter to specify the number of records extracted from the
    heat database during demotion. (BZ#1361759)

    * The /var/log/glusterfs/etc-glusterfs-glusterd.vol.log file is now named /var/log/glusterfs/glusterd.log.
    (BZ#1306120)

    * The 'gluster volume attach-tier/detach-tier' commands are considered deprecated in favor of the new
    commands, 'gluster volume tier VOLNAME attach/detach'. (BZ#1388464)

    * The HA_VOL_SERVER parameter in the ganesha-ha.conf file is no longer used by Red Hat Gluster Storage.
    (BZ#1348954)

    * The volfile server role can now be passed to another server when a server is unavailable. (BZ#1351949)

    * Ports can now be reused when they stop being used by another service. (BZ#1263090)

    * The thread pool limit for the rebalance process is now dynamic, and is determined based on the number of
    available cores. (BZ#1352805)

    * Brick verification at reboot now uses UUID instead of brick path. (BZ#1336267)

    * LOGIN_NAME_MAX is now used as the maximum length for the slave user instead of __POSIX_LOGIN_NAME_MAX,
    allowing for up to 256 characters including the NULL byte. (BZ#1400365)

    * The client identifier is now included in the log message to make it easier to determine which client
    failed to connect. (BZ#1333885)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_gluster_storage/3.2/html/3.2_release_notes/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5a22bf1");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2017/rhsa-2017_0484.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f05653c3");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:0484");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1200927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1362373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1375059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1382319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1403587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1403919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1404551");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1424944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1425748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1432972");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1795");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(377);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-api-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-client-xlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-events");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-ganesha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-geo-replication");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-storage-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel/server/6/6Server/x86_64/rhs-client/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-client/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-client/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glusterfs-3.8.4-18.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-api-3.8.4-18.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-api-devel-3.8.4-18.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-cli-3.8.4-18.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-client-xlators-3.8.4-18.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-devel-3.8.4-18.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-fuse-3.8.4-18.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-libs-3.8.4-18.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-rdma-3.8.4-18.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'python-gluster-3.8.4-18.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/rhs-server/3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-server/3/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-server/3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glusterfs-3.8.4-18.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-api-3.8.4-18.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-api-devel-3.8.4-18.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-cli-3.8.4-18.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-client-xlators-3.8.4-18.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-devel-3.8.4-18.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-events-3.8.4-18.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-fuse-3.8.4-18.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-ganesha-3.8.4-18.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-geo-replication-3.8.4-18.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-libs-3.8.4-18.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-rdma-3.8.4-18.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-server-3.8.4-18.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'python-gluster-3.8.4-18.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'redhat-storage-server-3.2.0.3-1.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glusterfs / glusterfs-api / glusterfs-api-devel / glusterfs-cli / etc');
}
