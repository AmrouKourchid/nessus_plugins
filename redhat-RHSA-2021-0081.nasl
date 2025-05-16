##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:0081. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144871);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2020-25660", "CVE-2020-25677", "CVE-2020-27781");
  script_xref(name:"RHSA", value:"2021:0081");

  script_name(english:"RHEL 7 / 8 : Red Hat Ceph Storage 4.2 Security and Bug Fix update (Important) (RHSA-2021:0081)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:0081 advisory.

    Red Hat Ceph Storage is a scalable, open, software-defined storage platform that combines the most stable
    version of the Ceph storage system with a Ceph management platform, deployment utilities, and support
    services.

    The ceph-ansible package provides Ansible playbooks for installing, maintaining, and upgrading Red Hat
    Ceph Storage.

    This package contains a new implementation of the original libtirpc, transport-independent RPC (TI-RPC)
    library for NFS-Ganesha.

    NFS-GANESHA is a NFS Server running in user space. It comes with various back-end modules (called FSALs)
    provided as shared objects to support different file systems and name-spaces.

    Security Fix(es):

    * ceph: User credentials can be manipulated and stolen by Native CephFS consumers of OpenStack Manila
    (CVE-2020-27781)

    * ceph: CEPHX_V2 replay attack protection lost (CVE-2020-25660)

    * ceph-ansible: insecure ownership on /etc/ceph/iscsi-gateway.conf configuration file (CVE-2020-25677)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    These updated packages include numerous bug fixes. Space precludes documenting all of these changes in
    this advisory. Users are directed to the Red Hat Ceph Storage 4.2 Release Notes for information on the
    most significant of these changes:

    https://access.redhat.com/documentation/en-us/red_hat_ceph_storage/4.2/html
    /release_notes/

    All users of Red Hat Ceph Storage are advised to upgrade to these updated
    packages, which provide numerous bug fixes.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa-2021_0081.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce45b86a");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:0081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1582280");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1731158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1763021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1774428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1774605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1786106");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1791911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1800382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1826690");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1828246");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1829214");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1830375");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1831299");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1831682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1836431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1841436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1845501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1847166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1850947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1855148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1855439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1855448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1856916");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1856960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1856981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1857414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1859180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1859679");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1859872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1860057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1860073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1860739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1861755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1866257");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1866308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1866834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1867697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1867698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1868638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1869797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1872006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1872028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1872030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1872033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1872459");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1872879");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1873221");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1873915");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1874756");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1875628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1875736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1876692");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1876976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1877300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1877413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1877737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1877745");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1877910");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1878145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1878250");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1878267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1878268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1878271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1878500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1879178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1879819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1879836");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1880188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1880252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1880458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1880476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1881288");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1881313");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1881523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1882426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1882484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1882705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1883283");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1884023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1885693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1886461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1886534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1886653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1886670");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1886677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1887716");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1889426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1889668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1889712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1889963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1890354");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1890439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1891098");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1892108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1892173");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1892295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1892387");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1893740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1893989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1894702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1896587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1897125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1897995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1898486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1898599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1898856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1899860");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1900109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1901036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1902034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1902149");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1902281");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1903612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1904340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1904958");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(294, 312, 522);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/12");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rbd-nbd");
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
      {'reference':'ceph-ansible-4.0.41-1.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25677']},
      {'reference':'ceph-base-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-base-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-base-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-common-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-common-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-common-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-fuse-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-fuse-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-fuse-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-grafana-dashboards-14.2.11-95.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mds-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mds-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mds-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mgr-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mgr-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mgr-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mgr-dashboard-14.2.11-95.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mgr-diskprediction-local-14.2.11-95.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mgr-k8sevents-14.2.11-95.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mgr-rook-14.2.11-95.el8cp', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mon-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mon-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mon-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-osd-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-osd-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-osd-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-radosgw-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-radosgw-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-radosgw-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-selinux-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-selinux-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-selinux-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-test-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-test-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-test-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libcephfs-devel-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libcephfs-devel-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libcephfs-devel-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libcephfs2-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libcephfs2-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libcephfs2-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librados-devel-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librados-devel-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librados-devel-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librados2-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librados2-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librados2-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libradospp-devel-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libradospp-devel-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libradospp-devel-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libradosstriper1-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libradosstriper1-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libradosstriper1-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librbd-devel-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librbd-devel-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librbd-devel-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librbd1-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librbd1-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librbd1-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librgw-devel-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librgw-devel-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librgw-devel-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librgw2-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librgw2-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librgw2-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-ceph-argparse-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-ceph-argparse-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-ceph-argparse-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-cephfs-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-cephfs-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-cephfs-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-rados-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-rados-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-rados-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-rbd-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-rbd-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-rbd-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-rgw-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-rgw-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python3-rgw-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'rbd-mirror-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'rbd-mirror-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'rbd-mirror-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'rbd-nbd-14.2.11-95.el8cp', 'cpu':'ppc64le', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'rbd-nbd-14.2.11-95.el8cp', 'cpu':'s390x', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'rbd-nbd-14.2.11-95.el8cp', 'cpu':'x86_64', 'release':'8', 'el_string':'el8cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']}
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
      {'reference':'ceph-ansible-4.0.41-1.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25677']},
      {'reference':'ceph-base-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-base-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-common-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-common-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-fuse-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-fuse-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-grafana-dashboards-14.2.11-95.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mds-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mds-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mgr-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mgr-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mgr-dashboard-14.2.11-95.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mgr-diskprediction-local-14.2.11-95.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mgr-k8sevents-14.2.11-95.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mgr-rook-14.2.11-95.el7cp', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mon-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-mon-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-osd-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-osd-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-radosgw-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-radosgw-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-selinux-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-selinux-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-test-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'ceph-test-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libcephfs-devel-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libcephfs-devel-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libcephfs2-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libcephfs2-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librados-devel-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librados-devel-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librados2-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librados2-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libradospp-devel-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libradospp-devel-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libradosstriper1-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'libradosstriper1-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librbd-devel-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librbd-devel-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librbd1-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librbd1-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librgw-devel-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librgw-devel-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librgw2-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'librgw2-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python-ceph-argparse-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python-ceph-argparse-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python-cephfs-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python-cephfs-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python-rados-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python-rados-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python-rbd-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python-rbd-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python-rgw-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'python-rgw-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'rbd-mirror-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'rbd-mirror-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'rbd-nbd-14.2.11-95.el7cp', 'cpu':'ppc64le', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']},
      {'reference':'rbd-nbd-14.2.11-95.el7cp', 'cpu':'x86_64', 'release':'7', 'el_string':'el7cp', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'ceph-mon-', 'cves':['CVE-2020-25660', 'CVE-2020-27781']}
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
