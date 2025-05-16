#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:3612. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194287);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2022-41717",
    "CVE-2022-41723",
    "CVE-2022-41724",
    "CVE-2022-41725",
    "CVE-2023-24534",
    "CVE-2023-24536",
    "CVE-2023-24537",
    "CVE-2023-24538",
    "CVE-2023-24540",
    "CVE-2023-27561"
  );
  script_xref(name:"RHSA", value:"2023:3612");

  script_name(english:"RHEL 8 / 9 : OpenShift Container Platform 4.13.4 (RHSA-2023:3612)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for OpenShift Container Platform 4.13.4.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:3612 advisory.

    Red Hat OpenShift Container Platform is Red Hat's cloud computing Kubernetes application platform solution
    designed for on-premise or private cloud deployments.

    This advisory contains the RPM packages for Red Hat OpenShift Container Platform 4.13.4. See the following
    advisory for the container images for this release:

    https://access.redhat.com/errata/RHSA-2023:3614

    Security Fix(es):

    * golang: html/template: improper handling of JavaScript whitespace
    (CVE-2023-24540)

    * golang: net/http: excessive memory growth in a Go server accepting HTTP/2
    requests (CVE-2022-41717)

    * golang: crypto/tls: large handshake records may cause panics
    (CVE-2022-41724)

    * golang: net/http, mime/multipart: denial of service from excessive
    resource consumption (CVE-2022-41725)

    * golang: net/http, net/textproto: denial of service from excessive memory
    allocation (CVE-2023-24534)

    * golang: net/http, net/textproto, mime/multipart: denial of service from
    excessive resource consumption (CVE-2023-24536)

    * golang: go/parser: Infinite loop in parsing (CVE-2023-24537)

    * golang: html/template: backticks not treated as string delimiters
    (CVE-2023-24538)

    * runc: volume mount race condition (regression of CVE 2019-19921)
    (CVE-2023-27561)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    All OpenShift Container Platform 4.13 users are advised to upgrade to these updated packages and images
    when they are available in the appropriate release channel. To check for available updates, use the
    OpenShift CLI (oc) or web console. Instructions for upgrading a cluster are available at
    https://docs.openshift.com/container-platform/4.13/updating/updating-cluster-cli.html

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/articles/11258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2161274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2175721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2178488");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2178492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2196027");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_3612.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b48abbe3");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:3612");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL OpenShift Container Platform 4.13.4 packages based on the guidance in RHSA-2023:3612.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24540");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(41, 94, 176, 400, 770, 835);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-debug-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-64k-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-ipaclones-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-selftests-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-selftests-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-uki-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel-matched");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-partner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-hyperkube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-gvproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rtla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo-tests");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

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

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2022-41717', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24537', 'CVE-2023-24538', 'CVE-2023-24540', 'CVE-2023-27561');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2023:3612');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/aarch64/rhocp/4.13/debug',
      'content/dist/layered/rhel8/aarch64/rhocp/4.13/os',
      'content/dist/layered/rhel8/aarch64/rhocp/4.13/source/SRPMS',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.13/debug',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.13/os',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.13/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.13/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.13/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.13/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.13/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.13/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.13/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'buildah-1.29.1-2.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'buildah-tests-1.29.1-2.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'conmon-2.1.7-2.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24537', 'CVE-2023-24538']},
      {'reference':'containernetworking-plugins-1.0.1-7.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723', 'CVE-2023-24537']},
      {'reference':'cri-o-1.26.3-9.rhaos4.13.git994242a.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'openshift-hyperkube-4.13.0-202306072143.p0.g7d22122.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'podman-4.4.1-4.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41717', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24540']},
      {'reference':'podman-catatonit-4.4.1-4.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41717', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24540']},
      {'reference':'podman-docker-4.4.1-4.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41717', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24540']},
      {'reference':'podman-gvproxy-4.4.1-4.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41717', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24540']},
      {'reference':'podman-plugins-4.4.1-4.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41717', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24540']},
      {'reference':'podman-remote-4.4.1-4.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41717', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24540']},
      {'reference':'podman-tests-4.4.1-4.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41717', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24540']},
      {'reference':'runc-1.1.6-4.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723', 'CVE-2022-41724', 'CVE-2023-27561']},
      {'reference':'skopeo-1.11.2-2.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24537']},
      {'reference':'skopeo-tests-1.11.2-2.rhaos4.13.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24537']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/aarch64/rhocp/4.13/debug',
      'content/dist/layered/rhel9/aarch64/rhocp/4.13/os',
      'content/dist/layered/rhel9/aarch64/rhocp/4.13/source/SRPMS',
      'content/dist/layered/rhel9/ppc64le/rhocp/4.13/debug',
      'content/dist/layered/rhel9/ppc64le/rhocp/4.13/os',
      'content/dist/layered/rhel9/ppc64le/rhocp/4.13/source/SRPMS',
      'content/dist/layered/rhel9/s390x/rhocp/4.13/debug',
      'content/dist/layered/rhel9/s390x/rhocp/4.13/os',
      'content/dist/layered/rhel9/s390x/rhocp/4.13/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhocp/4.13/debug',
      'content/dist/layered/rhel9/x86_64/rhocp/4.13/os',
      'content/dist/layered/rhel9/x86_64/rhocp/4.13/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-7.0.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'buildah-1.29.1-2.1.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'buildah-tests-1.29.1-2.1.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'conmon-2.1.7-2.1.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24537', 'CVE-2023-24538']},
      {'reference':'cri-o-1.26.3-10.rhaos4.13.git994242a.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-core-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-debug-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-debug-core-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-debug-devel-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-debug-devel-matched-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-debug-modules-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-debug-modules-core-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-debug-modules-extra-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-debug-modules-internal-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-debug-modules-partner-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-devel-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-devel-matched-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-modules-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-modules-core-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-modules-extra-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-modules-internal-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-64k-modules-partner-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-core-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-cross-headers-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-debug-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-debug-core-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-debug-devel-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-debug-devel-matched-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-debug-modules-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-debug-modules-core-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-debug-modules-extra-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-debug-modules-internal-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-debug-modules-partner-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-debug-uki-virt-5.14.0-284.18.1.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-devel-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-devel-matched-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-headers-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-ipaclones-internal-5.14.0-284.18.1.el9_2', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-ipaclones-internal-5.14.0-284.18.1.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-modules-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-modules-core-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-modules-extra-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-modules-internal-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-modules-partner-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-core-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-debug-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-debug-core-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-debug-devel-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-debug-devel-matched-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-debug-kvm-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-debug-modules-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-debug-modules-core-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-debug-modules-extra-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-debug-modules-internal-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-debug-modules-partner-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-devel-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-devel-matched-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-kvm-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-modules-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-modules-core-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-modules-extra-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-modules-internal-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-modules-partner-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-rt-selftests-internal-5.14.0-284.18.1.rt14.303.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-selftests-internal-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-tools-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-tools-libs-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-tools-libs-5.14.0-284.18.1.el9_2', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-tools-libs-5.14.0-284.18.1.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.18.1.el9_2', 'cpu':'aarch64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.18.1.el9_2', 'cpu':'ppc64le', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-tools-libs-devel-5.14.0-284.18.1.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-uki-virt-5.14.0-284.18.1.el9_2', 'cpu':'x86_64', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-zfcpdump-5.14.0-284.18.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-zfcpdump-core-5.14.0-284.18.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-zfcpdump-devel-5.14.0-284.18.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-zfcpdump-devel-matched-5.14.0-284.18.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-zfcpdump-modules-5.14.0-284.18.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-zfcpdump-modules-core-5.14.0-284.18.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-zfcpdump-modules-extra-5.14.0-284.18.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-zfcpdump-modules-internal-5.14.0-284.18.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'kernel-zfcpdump-modules-partner-5.14.0-284.18.1.el9_2', 'cpu':'s390x', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'openshift-hyperkube-4.13.0-202306072143.p0.g7d22122.assembly.stream.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'perf-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'podman-4.4.1-5.1.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41717', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24540']},
      {'reference':'podman-docker-4.4.1-5.1.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41717', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24540']},
      {'reference':'podman-gvproxy-4.4.1-5.1.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41717', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24540']},
      {'reference':'podman-plugins-4.4.1-5.1.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41717', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24540']},
      {'reference':'podman-remote-4.4.1-5.1.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41717', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24540']},
      {'reference':'podman-tests-4.4.1-5.1.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41717', 'CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24540']},
      {'reference':'python3-perf-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'rtla-5.14.0-284.18.1.el9_2', 'release':'9', 'el_string':'el9_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723']},
      {'reference':'skopeo-1.11.2-2.1.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24537']},
      {'reference':'skopeo-tests-1.11.2-2.1.rhaos4.13.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2022-41723', 'CVE-2022-41724', 'CVE-2022-41725', 'CVE-2023-24534', 'CVE-2023-24536', 'CVE-2023-24537']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / buildah / buildah-tests / conmon / etc');
}
