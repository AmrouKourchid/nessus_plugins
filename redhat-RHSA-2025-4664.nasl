#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:4664. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235495);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id(
    "CVE-2023-23934",
    "CVE-2023-25577",
    "CVE-2023-46446",
    "CVE-2023-48795",
    "CVE-2024-24790",
    "CVE-2024-34069",
    "CVE-2024-42353",
    "CVE-2024-47191",
    "CVE-2024-48916"
  );
  script_xref(name:"RHSA", value:"2025:4664");

  script_name(english:"RHEL 8 / 9 : Red Hat Ceph Storage 7.1 security,  updates (Important) (RHSA-2025:4664)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2025:4664 advisory.

    Red Hat Ceph Storage is a scalable, open, software-defined storage platform that combines the most stable
    version of the Ceph storage system with a Ceph management platform, deployment utilities, and support
    services.

    These new packages include numerous enhancements, bug fixes, and known issues. Space precludes documenting
    all of these changes in this advisory. Users are directed to the Red Hat Ceph Storage Release Notes for
    information on the most significant of these changes:

    https://docs.redhat.com/en/documentation/red_hat_ceph_storage/7/html/7.1_release_notes

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2252788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2270948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2284356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2314387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2315596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2315885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2321291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2348763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2348935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2348945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2348968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2348970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2349723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2351271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2351465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2352965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2356542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2358562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2360911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2362258");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_4664.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96690043");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:4664");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24790");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-48795");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 22, 115, 222, 345, 352, 359, 601, 770);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-immutable-object-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-mib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephfs-top");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:liboath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libradospp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:oath-toolkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-nbd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','9'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/ppc64le/rhceph-tools/7/debug',
      'content/dist/layered/rhel8/ppc64le/rhceph-tools/7/os',
      'content/dist/layered/rhel8/ppc64le/rhceph-tools/7/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhceph-tools/7/debug',
      'content/dist/layered/rhel8/s390x/rhceph-tools/7/os',
      'content/dist/layered/rhel8/s390x/rhceph-tools/7/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhceph-tools/7/debug',
      'content/dist/layered/rhel8/x86_64/rhceph-tools/7/os',
      'content/dist/layered/rhel8/x86_64/rhceph-tools/7/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ceph-base-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-immutable-object-cache-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-immutable-object-cache-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mib-18.2.1-329.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-resource-agents-18.2.1-329.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'cephfs-top-18.2.1-329.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'liboath-2.6.12-1.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'liboath-2.6.12-1.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-argparse-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-argparse-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-common-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-common-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-cephfs-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-cephfs-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rados-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rados-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rbd-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rbd-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rgw-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rgw-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-18.2.1-329.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-18.2.1-329.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/ppc64le/rhceph-tools/7/debug',
      'content/dist/layered/rhel9/ppc64le/rhceph-tools/7/os',
      'content/dist/layered/rhel9/ppc64le/rhceph-tools/7/source/SRPMS',
      'content/dist/layered/rhel9/s390x/rhceph-tools/7/debug',
      'content/dist/layered/rhel9/s390x/rhceph-tools/7/os',
      'content/dist/layered/rhel9/s390x/rhceph-tools/7/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhceph-tools/7/debug',
      'content/dist/layered/rhel9/x86_64/rhceph-tools/7/os',
      'content/dist/layered/rhel9/x86_64/rhceph-tools/7/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ceph-base-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-base-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-common-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-fuse-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-immutable-object-cache-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-immutable-object-cache-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-immutable-object-cache-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-mib-18.2.1-329.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-resource-agents-18.2.1-329.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'ceph-selinux-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'cephadm-18.2.1-329.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'cephfs-top-18.2.1-329.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs-devel-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libcephfs2-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'liboath-2.6.12-1.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'liboath-2.6.12-1.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'liboath-2.6.12-1.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados-devel-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librados2-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradospp-devel-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'libradosstriper1-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd-devel-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librbd1-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw-devel-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'librgw2-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-argparse-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-argparse-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-argparse-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-common-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-common-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-ceph-common-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-cephfs-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-cephfs-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-cephfs-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rados-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rados-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rados-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rbd-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rbd-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rbd-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rgw-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rgw-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'python3-rgw-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-18.2.1-329.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-18.2.1-329.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'},
      {'reference':'rbd-nbd-18.2.1-329.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph-base / ceph-common / ceph-fuse / ceph-immutable-object-cache / etc');
}
