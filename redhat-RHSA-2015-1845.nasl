#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(86306);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id("CVE-2014-8177", "CVE-2015-1856");
  script_bugtraq_id(76979);
  script_xref(name:"RHSA", value:"2015:1845");

  script_name(english:"RHEL 6 : Red Hat Gluster Storage 3.1 update (Moderate) (RHSA-2015:1845)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2015:1845 advisory.

    Red Hat Gluster Storage is a software only scale-out storage solution that
    provides flexible and affordable unstructured data storage. It unifies data
    storage and infrastructure, increases performance, and improves
    availability and manageability to meet enterprise-level storage challenges.

    Red Hat Gluster Storage's Unified File and Object Storage is built on
    OpenStack's Object Storage (swift).

    A flaw was found in the metadata constraints in Red Hat Gluster Storage's
    OpenStack Object Storage (swiftonfile). By adding metadata in several
    separate calls, a malicious user could bypass the max_meta_count
    constraint, and store more metadata than allowed by the configuration.
    (CVE-2014-8177)

    This update also fixes numerous bugs and adds various enhancements. Space
    precludes documenting all of these changes in this advisory. Users are
    directed to the Red Hat Gluster Storage 3.1 Technical Notes, linked to in
    the References section, for information on the most significant of these
    changes.

    This advisory introduces the following new features:

    * Gdeploy is a tool which automates the process of creating, formatting,
    and mounting bricks. When setting up a fresh cluster, gdeploy could be the
    preferred choice of cluster set up, as manually executing numerous commands
    can be error prone. The advantages of using gdeploy includes automated
    brick creation, flexibility in choosing the drives to configure (sd, vd,
    etc.), and flexibility in naming the logical volumes (LV) and volume groups
    (VG). (BZ#1248899)

    * The gstatus command is now fully supported. The gstatus command provides
    an easy-to-use, high-level view of the health of a trusted storage pool
    with a single command. It gathers information about the health of a Red Hat
    Gluster Storage trusted storage pool for distributed, replicated,
    distributed-replicated, dispersed, and distributed-dispersed volumes.
    (BZ#1250453)

    * You can now recover a bad file detected by BitRot from a replicated
    volume. The information about the bad file will be logged in the scrubber
    log file located at /var/log/glusterfs/scrub.log. (BZ#1238171)

    * Two tailored tuned profiles are introduced to improve the performance for
    specific Red Hat Gluster Storage workloads. They are: rhgs-sequential-io,
    which improves performance of large files with sequential I/O workloads,
    and rhgs-random-io, which improves performance of small files with random
    I/O workloads (BZ# 1251360)

    All users of Red Hat Gluster Storage are advised to apply this update.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2015/rhsa-2015_1845.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3fbe9687");
  # https://access.redhat.com/documentation/en-US/Red_Hat_Storage/3.1/html/Technical_Notes/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c54d416");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2015:1845");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1027723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1064265");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1076033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1091936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1134288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1178100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1213893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1215816");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1225452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1226665");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1226817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1227724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1227759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1228135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1228158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1229606");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1229621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1231080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1232216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1232569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1234213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1234399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1234610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1234708");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1235182");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1235571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1235971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1236038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1236546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1236672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1236990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1238070");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1238071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1238111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1238116");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1238118");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1238147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1238171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1238398");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1238977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1239021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1239075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1240614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1240657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1241385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1241761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1241807");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1241862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1241871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1242803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1243542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1243722");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1243886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1244415");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1244527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1245162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1245165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1245536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1245542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1245897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1245915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1245919");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1245924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1246946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1247445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1247537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1248899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1249989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1250453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1250821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1251360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1251925");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1253141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1254432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1254514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1254866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1254991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1255015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1255308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1255471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1257099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1257162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1257468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1257509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1257525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1258434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1258810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1258821");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1259750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1260086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1260982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1262236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1262291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1263094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1263581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1263653");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1856");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-8177");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:swiftonfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-debug-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-ethtool-options");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-faqemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-openstacknet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-hook-qemucmdline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-jsonrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-python-zombiereaper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-reg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm-yajsonrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdeploy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gluster-nagios-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gluster-nagios-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-api-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-client-xlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-ganesha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-geo-replication");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glusterfs-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gstatus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nagios-server-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nfs-ganesha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nfs-ganesha-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-swift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-swift-account");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-swift-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-swift-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-swift-object");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openstack-swift-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-storage-server");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2025 Tenable Network Security, Inc.");

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
      'content/dist/rhel/server/6/6Server/x86_64/rhgs-server-nfs/3.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhgs-server-nfs/3.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhgs-server-nfs/3.1/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'nfs-ganesha-2.2.0-9.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'nfs-ganesha-gluster-2.2.0-9.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/rhs-client/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-client/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-client/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glusterfs-3.7.1-16.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-api-3.7.1-16.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-api-devel-3.7.1-16.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-cli-3.7.1-16.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-client-xlators-3.7.1-16.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-devel-3.7.1-16.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-fuse-3.7.1-16.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-libs-3.7.1-16.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-rdma-3.7.1-16.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'python-gluster-3.7.1-16.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/rhs-nagios/3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-nagios/3/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-nagios/3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'nagios-server-addons-0.2.2-1.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/rhs-nagios/3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-nagios/3/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-nagios/3/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-server/3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-server/3/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-server/3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'gluster-nagios-common-0.2.2-1.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/6/6Server/x86_64/rhs-server/3/debug',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-server/3/os',
      'content/dist/rhel/server/6/6Server/x86_64/rhs-server/3/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'gdeploy-1.0-12.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'gluster-nagios-addons-0.2.5-1.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-3.7.1-16.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-api-3.7.1-16.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-api-devel-3.7.1-16.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-cli-3.7.1-16.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-client-xlators-3.7.1-16.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-devel-3.7.1-16.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-fuse-3.7.1-16.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-ganesha-3.7.1-16.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-geo-replication-3.7.1-16.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-libs-3.7.1-16.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-rdma-3.7.1-16.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'glusterfs-server-3.7.1-16.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'gstatus-0.65-1.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'openstack-swift-1.13.1-6.el6ost', 'release':'6', 'el_string':'el6ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'openstack-swift-account-1.13.1-6.el6ost', 'release':'6', 'el_string':'el6ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'openstack-swift-container-1.13.1-6.el6ost', 'release':'6', 'el_string':'el6ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'openstack-swift-doc-1.13.1-6.el6ost', 'release':'6', 'el_string':'el6ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'openstack-swift-object-1.13.1-6.el6ost', 'release':'6', 'el_string':'el6ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'openstack-swift-proxy-1.13.1-6.el6ost', 'release':'6', 'el_string':'el6ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'python-gluster-3.7.1-16.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'redhat-storage-server-3.1.1.0-2.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'swiftonfile-1.13.1-5.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-4.16.20-1.3.el6rhs', 'cpu':'x86_64', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-cli-4.16.20-1.3.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-debug-plugin-4.16.20-1.3.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-gluster-4.16.20-1.3.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-hook-ethtool-options-4.16.20-1.3.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-hook-faqemu-4.16.20-1.3.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-hook-openstacknet-4.16.20-1.3.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-hook-qemucmdline-4.16.20-1.3.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-jsonrpc-4.16.20-1.3.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-python-4.16.20-1.3.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-python-zombiereaper-4.16.20-1.3.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-reg-4.16.20-1.3.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-tests-4.16.20-1.3.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-xmlrpc-4.16.20-1.3.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'},
      {'reference':'vdsm-yajsonrpc-4.16.20-1.3.el6rhs', 'release':'6', 'el_string':'el6rhs', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'glusterfs'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gdeploy / gluster-nagios-addons / gluster-nagios-common / glusterfs / etc');
}
