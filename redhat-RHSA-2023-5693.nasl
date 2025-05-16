#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:5693. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182992);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id(
    "CVE-2018-14041",
    "CVE-2018-20676",
    "CVE-2018-20677",
    "CVE-2023-43040",
    "CVE-2023-46159"
  );
  script_xref(name:"RHSA", value:"2023:5693");

  script_name(english:"RHEL 9 : Red Hat Ceph Storage 6.1 (RHSA-2023:5693)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:5693 advisory.

    Red Hat Ceph Storage is a scalable, open, software-defined storage platform
    that combines the most stable version of the Ceph storage system with a
    Ceph management platform, deployment utilities, and support services.

    These new packages include numerous enhancements, and bug fixes. Space precludes documenting all of these
    changes in this advisory.
    Users are directed to the Red Hat Ceph Storage Release Notes for
    information on the most significant of these changes:

    https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/6.1/html/release_notes/index

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/6.1/html/release_notes/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15054117");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_5693.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?304922f2");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:5693");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1601616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1668082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1668089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1960643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2088172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2114615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2138216");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2141003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2161569");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2166413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2166688");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2170836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2172838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2183926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2188557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2203397");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2210944");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2211290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2211477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2212787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2214278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2215392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2216230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2216855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2216920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2217817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2219465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2220922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2222720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2222726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2223990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2224407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2227045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2227842");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2228004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2228242");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2228357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2228875");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2229179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2229267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2231068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2232087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2232640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2233131");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2233762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2239697");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20677");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephadm-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cephfs-top");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/ppc64le/rhceph-tools/6/debug',
      'content/dist/layered/rhel9/ppc64le/rhceph-tools/6/os',
      'content/dist/layered/rhel9/ppc64le/rhceph-tools/6/source/SRPMS',
      'content/dist/layered/rhel9/s390x/rhceph-tools/6/debug',
      'content/dist/layered/rhel9/s390x/rhceph-tools/6/os',
      'content/dist/layered/rhel9/s390x/rhceph-tools/6/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhceph-tools/6/debug',
      'content/dist/layered/rhel9/x86_64/rhceph-tools/6/os',
      'content/dist/layered/rhel9/x86_64/rhceph-tools/6/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ceph-base-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-base-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-base-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-common-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-common-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-common-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-fuse-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-fuse-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-fuse-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-immutable-object-cache-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-immutable-object-cache-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-immutable-object-cache-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-mib-17.2.6-148.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-resource-agents-17.2.6-148.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-selinux-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-selinux-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'ceph-selinux-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'cephadm-17.2.6-148.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'cephadm-ansible-3.0.0-1.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-', 'cves':['CVE-2023-46159']},
      {'reference':'cephfs-top-17.2.6-148.el9cp', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'libcephfs-devel-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'libcephfs-devel-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'libcephfs-devel-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'libcephfs2-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'libcephfs2-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'libcephfs2-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librados-devel-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librados-devel-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librados-devel-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librados2-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librados2-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librados2-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'libradospp-devel-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'libradospp-devel-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'libradospp-devel-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'libradosstriper1-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'libradosstriper1-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'libradosstriper1-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librbd-devel-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librbd-devel-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librbd-devel-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librbd1-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librbd1-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librbd1-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librgw-devel-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librgw-devel-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librgw-devel-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librgw2-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librgw2-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'librgw2-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-ceph-argparse-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-ceph-argparse-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-ceph-argparse-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-ceph-common-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-ceph-common-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-ceph-common-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-cephfs-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-cephfs-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-cephfs-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-rados-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-rados-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-rados-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-rbd-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-rbd-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-rbd-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-rgw-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-rgw-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'python3-rgw-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'rbd-nbd-17.2.6-148.el9cp', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'rbd-nbd-17.2.6-148.el9cp', 'cpu':'s390x', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']},
      {'reference':'rbd-nbd-17.2.6-148.el9cp', 'cpu':'x86_64', 'release':'9', 'el_string':'el9cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2018-14041', 'CVE-2018-20676', 'CVE-2018-20677', 'CVE-2023-43040', 'CVE-2023-46159']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph-base / ceph-common / ceph-fuse / ceph-immutable-object-cache / etc');
}
