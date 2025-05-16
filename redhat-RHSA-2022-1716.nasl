##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:1716. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160541);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2020-25658", "CVE-2021-3524", "CVE-2021-3979");
  script_xref(name:"RHSA", value:"2022:1716");

  script_name(english:"RHEL 7 / 8 : Red Hat Ceph Storage 4.3 Security and Bug Fix update (Moderate) (RHSA-2022:1716)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:1716 advisory.

    Red Hat Ceph Storage is a scalable, open, software-defined storage platform that combines the most stable
    version of the Ceph storage system with a Ceph management platform, deployment utilities, and support
    services.

    Security Fix(es):

    * python-rsa: bleichenbacher timing oracle attack against RSA decryption (CVE-2020-25658)

    * ceph object gateway: radosgw: CRLF injection (CVE-2021-3524)

    * ceph: Ceph volume does not honour osd_dmcrypt_key_size (CVE-2021-3979)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    These new packages include numerous bug fixes. Space precludes documenting all of these changes in this
    advisory. Users are directed to the Red Hat Ceph Storage Release Notes for information on the most
    significant of these changes:

    https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/4.3/html/release_notes/index

    All users of Red Hat Ceph Storage are advised to upgrade to these new packages, which provide bug fixes.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_1716.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f46647c0");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:1716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1786691");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1855350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1876860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1889972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1891557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1894038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1896803");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1902999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1906022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1927574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1936299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1941775");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1951674");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1952571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1955038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1960306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1962748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1964097");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1964099");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1965314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1965504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1965540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1967532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1975102");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1978643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1979186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1981860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1986684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1987041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1988171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1990772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1992178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1992246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1994930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1995037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1995562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1995574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1996765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1997586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2001444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2002084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2002261");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2003212");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2003219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2004738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2006166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2006686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2006805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2006912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2006984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2008860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2009516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2011451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2014304");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2016994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2017878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2021037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2021075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2021447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2021993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2022585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2022650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2023379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2024788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2027449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2027721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2027812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2028248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2028827");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2030452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2032560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2034595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2034637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2034999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2036930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2036941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2038798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2039175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2040161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2042585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2044176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2044370");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2044406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2047694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2052202");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2056719");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2056906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2058201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2063029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2071137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2076192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2077139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2079016");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3524");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3979");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 287, 385);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-nbd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      {'reference':'ceph-base-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-base-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-base-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-common-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-common-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-common-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-fuse-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-fuse-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-fuse-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-grafana-dashboards-14.2.22-110.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mds-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mds-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mds-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mgr-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mgr-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mgr-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mgr-dashboard-14.2.22-110.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mgr-diskprediction-local-14.2.22-110.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mgr-k8sevents-14.2.22-110.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mgr-rook-14.2.22-110.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mon-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mon-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mon-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-osd-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-osd-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-osd-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-radosgw-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-radosgw-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-radosgw-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-selinux-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-selinux-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-selinux-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-test-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-test-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-test-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libcephfs-devel-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libcephfs-devel-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libcephfs-devel-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libcephfs2-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libcephfs2-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libcephfs2-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librados-devel-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librados-devel-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librados-devel-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librados2-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librados2-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librados2-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libradospp-devel-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libradospp-devel-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libradospp-devel-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libradosstriper1-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libradosstriper1-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libradosstriper1-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librbd-devel-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librbd-devel-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librbd-devel-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librbd1-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librbd1-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librbd1-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librgw-devel-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librgw-devel-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librgw-devel-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librgw2-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librgw2-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librgw2-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-ceph-argparse-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-ceph-argparse-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-ceph-argparse-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-cephfs-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-cephfs-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-cephfs-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-rados-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-rados-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-rados-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-rbd-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-rbd-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-rbd-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-rgw-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-rgw-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-rgw-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python3-rsa-4.8-1.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25658']},
      {'reference':'rbd-mirror-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'rbd-mirror-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'rbd-mirror-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'rbd-nbd-14.2.22-110.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'rbd-nbd-14.2.22-110.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'rbd-nbd-14.2.22-110.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']}
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
      {'reference':'ceph-base-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-base-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-common-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-common-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-fuse-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-fuse-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-grafana-dashboards-14.2.22-110.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mds-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mds-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mgr-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mgr-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mgr-dashboard-14.2.22-110.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mgr-diskprediction-local-14.2.22-110.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mgr-k8sevents-14.2.22-110.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mgr-rook-14.2.22-110.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mon-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-mon-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-osd-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-osd-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-radosgw-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-radosgw-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-selinux-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-selinux-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-test-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'ceph-test-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libcephfs-devel-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libcephfs-devel-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libcephfs2-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libcephfs2-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librados-devel-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librados-devel-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librados2-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librados2-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libradospp-devel-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libradospp-devel-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libradosstriper1-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'libradosstriper1-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librbd-devel-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librbd-devel-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librbd1-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librbd1-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librgw-devel-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librgw-devel-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librgw2-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'librgw2-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python-ceph-argparse-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python-ceph-argparse-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python-cephfs-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python-cephfs-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python-rados-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python-rados-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python-rbd-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python-rbd-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python-rgw-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'python-rgw-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'rbd-mirror-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'rbd-mirror-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'rbd-nbd-14.2.22-110.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']},
      {'reference':'rbd-nbd-14.2.22-110.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2021-3524', 'CVE-2021-3979']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ceph-base / ceph-common / ceph-fuse / ceph-grafana-dashboards / etc');
}
