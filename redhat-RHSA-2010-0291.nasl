#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0291. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63925);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/20");

  script_cve_id("CVE-2010-0727");
  script_xref(name:"RHSA", value:"2010:0291");

  script_name(english:"RHEL 5 : gfs-kmod (RHSA-2010:0291)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 5 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2010:0291 advisory.

    The gfs-kmod packages contain modules that provide the ability to mount and
    use GFS file systems.

    A flaw was found in the gfs_lock() implementation. The GFS locking code
    could skip the lock operation for files that have the S_ISGID bit
    (set-group-ID on execution) in their mode set. A local, unprivileged user
    on a system that has a GFS file system mounted could use this flaw to cause
    a kernel panic. (CVE-2010-0727)

    These updated gfs-kmod packages are in sync with the latest kernel
    (2.6.18-194.el5). The modules in earlier gfs-kmod packages failed to load
    because they did not match the running kernel. It was possible to
    force-load the modules. With this update, however, users no longer need to.

    These updated gfs-kmod packages also fix the following bugs:

    * when SELinux was in permissive mode, a race condition during file
    creation could have caused one or more cluster nodes to be fenced and lock
    the remaining nodes out of the GFS file system. This race condition no
    longer occurs with this update. (BZ#471258)

    * when ACLs (Access Control Lists) are enabled on a GFS file system, if a
    transaction that has started to do a write request does not have enough
    spare blocks for the operation it causes a kernel panic. This update
    ensures that there are enough blocks for the write request before starting
    the operation. (BZ#513885)

    * requesting a flock on a file in GFS in either read-only or read-write
    mode would sometimes cause a Resource temporarily unavailable state error
    (error 11 for EWOULDBLOCK) to occur. In these cases, a flock could not be
    obtained on the file in question. This has been fixed with this update so
    that flocks can successfully be obtained on GFS files without this error
    occurring. (BZ#515717)

    * the GFS withdraw function is a data integrity feature of GFS file systems
    in a cluster. If the GFS kernel module detects an inconsistency in a GFS
    file system following an I/O operation, the file system becomes unavailable
    to the cluster. The GFS withdraw function is less severe than a kernel
    panic, which would cause another node to fence the node. With this update,
    you can override the GFS withdraw function by mounting the file system with
    the -o errors=panic option specified. When this option is specified, any
    errors that would normally cause the system to withdraw cause the system to
    panic instead. This stops the node's cluster communications, which causes
    the node to be fenced. (BZ#517145)

    Finally, these updated gfs-kmod packages provide the following enhancement:

    * the GFS kernel modules have been updated to use the new generic freeze
    and unfreeze ioctl interface that is also supported by the following file
    systems: ext3, ext4, GFS2, JFS and ReiserFS. With this update, GFS supports
    freeze/unfreeze through the VFS-level FIFREEZE/FITHAW ioctl interface.
    (BZ#487610)

    Users are advised to upgrade to these latest gfs-kmod packages, updated for
    use with the 2.6.18-194.el5 kernel, which contain backported patches to
    correct these issues, fix these bugs, and add this enhancement.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2010/rhsa-2010_0291.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b264e09b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0291");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=471258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=487610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=513885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=515717");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=517145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=570863");
  script_set_attribute(attribute:"solution", value:
"Update the affected kmod-gfs, kmod-gfs-PAE and / or kmod-gfs-xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0727");
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kmod-gfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kmod-gfs-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kmod-gfs-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gfs-kmod");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2025 Tenable Network Security, Inc.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '5')) audit(AUDIT_OS_NOT, 'Red Hat 5.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel/server/5/5Server/i386/resilientstorage/debug',
      'content/dist/rhel/server/5/5Server/i386/resilientstorage/os',
      'content/dist/rhel/server/5/5Server/i386/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/5/5Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/5/5Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/5/5Server/x86_64/resilientstorage/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kmod-gfs-0.1.34-12.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kmod-gfs-0.1.34-12.el5', 'cpu':'ppc64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kmod-gfs-0.1.34-12.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kmod-gfs-PAE-0.1.34-12.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kmod-gfs-xen-0.1.34-12.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kmod-gfs-xen-0.1.34-12.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kmod-gfs / kmod-gfs-PAE / kmod-gfs-xen');
}
