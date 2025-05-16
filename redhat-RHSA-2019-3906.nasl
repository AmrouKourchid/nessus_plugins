#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3906. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131154);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2019-9512", "CVE-2019-9514");
  script_xref(name:"RHSA", value:"2019:3906");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"RHEL 7 : OpenShift Container Platform 3.11 HTTP/2 (RHSA-2019:3906)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for OpenShift Container Platform 3.11 HTTP/2.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2019:3906 advisory.

    Red Hat OpenShift Container Platform is Red Hat's cloud computing
    Kubernetes application platform solution designed for on-premise or private
    cloud deployments.

    The following RPM packages have been rebuilt with updated version of Go, which includes the security fixes
    listed further below:

    atomic-enterprise-service-catalog
    atomic-openshift-cluster-autoscaler
    atomic-openshift-descheduler
    atomic-openshift-metrics-server
    atomic-openshift-node-problem-detector
    atomic-openshift-service-idler
    atomic-openshift-web-console
    cockpit
    csi-attacher
    csi-driver-registrar
    csi-livenessprobe
    csi-provisioner
    golang-github-openshift-oauth-proxy
    golang-github-openshift-prometheus-alert-buffer
    golang-github-prometheus-alertmanager
    golang-github-prometheus-node_exporter
    golang-github-prometheus-prometheus
    hawkular-openshift-agent
    heapster
    image-inspector
    openshift-enterprise-autoheal
    openshift-enterprise-cluster-capacity
    openshift-eventrouter
    openshift-external-storage

    Security Fix(es):

    * HTTP/2: flood using PING frames results in unbounded memory growth (CVE-2019-9512)

    * HTTP/2: flood using HEADERS frames results in unbounded memory growth (CVE-2019-9514)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2019/rhsa-2019_3906.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84812716");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3906");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1735645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1735744");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL OpenShift Container Platform 3.11 HTTP/2 package based on the guidance in RHSA-2019:3906.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9514");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_cwe_id(400);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-enterprise-service-catalog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-enterprise-service-catalog-svcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-cluster-autoscaler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-descheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-metrics-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-node-problem-detector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-service-idler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-web-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cockpit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cockpit-kubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:csi-attacher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:csi-driver-registrar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:csi-livenessprobe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:csi-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:golang-github-openshift-oauth-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:golang-github-openshift-prometheus-alert-buffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:golang-github-prometheus-alertmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:golang-github-prometheus-node_exporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:golang-github-prometheus-prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hawkular-openshift-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:heapster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:image-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-autoheal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-cluster-capacity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-eventrouter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-cephfs-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-efs-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-local-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-manila-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-snapshot-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-snapshot-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:prometheus-alertmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:prometheus-node-exporter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/ose/3.11/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/ose/3.11/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/ose/3.11/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/3.11/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/3.11/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/3.11/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.11/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.11/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.11/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'atomic-enterprise-service-catalog-3.11.154-1.git.1.fa68ced.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-ansible'},
      {'reference':'atomic-enterprise-service-catalog-3.11.154-1.git.1.fa68ced.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-ansible'},
      {'reference':'atomic-enterprise-service-catalog-svcat-3.11.154-1.git.1.fa68ced.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-ansible'},
      {'reference':'atomic-enterprise-service-catalog-svcat-3.11.154-1.git.1.fa68ced.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-ansible'},
      {'reference':'atomic-openshift-cluster-autoscaler-3.11.154-1.git.1.532da7a.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'atomic-openshift-cluster-autoscaler-3.11.154-1.git.1.532da7a.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'atomic-openshift-descheduler-3.11.154-1.git.1.1d31032.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'atomic-openshift-descheduler-3.11.154-1.git.1.1d31032.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'atomic-openshift-metrics-server-3.11.154-1.git.1.6a6b6ce.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'atomic-openshift-metrics-server-3.11.154-1.git.1.6a6b6ce.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'atomic-openshift-node-problem-detector-3.11.154-1.git.1.5e8e065.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'atomic-openshift-node-problem-detector-3.11.154-1.git.1.5e8e065.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'atomic-openshift-service-idler-3.11.154-1.git.1.f80fb86.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'atomic-openshift-service-idler-3.11.154-1.git.1.f80fb86.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'atomic-openshift-web-console-3.11.154-1.git.1.f54cb18.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'atomic-openshift-web-console-3.11.154-1.git.1.f54cb18.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'cockpit-kubernetes-195-2.rhaos.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'cockpit-kubernetes-195-2.rhaos.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'csi-attacher-0.2.0-4.git27299be.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'csi-attacher-0.2.0-4.git27299be.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'csi-driver-registrar-0.2.0-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'csi-driver-registrar-0.2.0-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'csi-livenessprobe-0.0.1-2.gitff5b6a0.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'csi-livenessprobe-0.0.1-2.gitff5b6a0.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'csi-provisioner-0.2.0-3.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'csi-provisioner-0.2.0-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'golang-github-openshift-oauth-proxy-3.11.154-1.git.1.220e3dc.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'golang-github-openshift-oauth-proxy-3.11.154-1.git.1.220e3dc.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'golang-github-openshift-prometheus-alert-buffer-0-3.gitceca8c1.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'golang-github-openshift-prometheus-alert-buffer-0-3.gitceca8c1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'hawkular-openshift-agent-1.2.2-3.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'hawkular-openshift-agent-1.2.2-3.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'heapster-1.3.0-4.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'heapster-1.3.0-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'image-inspector-2.4.0-4.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'image-inspector-2.4.0-4.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-autoheal-3.11.154-1.git.1.13199be.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-autoheal-3.11.154-1.git.1.13199be.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-cluster-capacity-3.11.154-1.git.1.5798c2c.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-cluster-capacity-3.11.154-1.git.1.5798c2c.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-eventrouter-0.2-4.git7c289cc.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-eventrouter-0.2-4.git7c289cc.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-external-storage-cephfs-provisioner-0.0.2-9.gitd3c94f0.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-external-storage-cephfs-provisioner-0.0.2-9.gitd3c94f0.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-external-storage-efs-provisioner-0.0.2-9.gitd3c94f0.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-external-storage-efs-provisioner-0.0.2-9.gitd3c94f0.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-external-storage-local-provisioner-0.0.2-9.gitd3c94f0.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-external-storage-local-provisioner-0.0.2-9.gitd3c94f0.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-external-storage-manila-provisioner-0.0.2-9.gitd3c94f0.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-external-storage-manila-provisioner-0.0.2-9.gitd3c94f0.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-external-storage-snapshot-controller-0.0.2-9.gitd3c94f0.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-external-storage-snapshot-controller-0.0.2-9.gitd3c94f0.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-external-storage-snapshot-provisioner-0.0.2-9.gitd3c94f0.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-external-storage-snapshot-provisioner-0.0.2-9.gitd3c94f0.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'prometheus-3.11.154-1.git.1.148db48.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'prometheus-3.11.154-1.git.1.148db48.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'prometheus-alertmanager-3.11.154-1.git.1.4acd2e6.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'prometheus-alertmanager-3.11.154-1.git.1.4acd2e6.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'prometheus-node-exporter-3.11.154-1.git.1.bc9f224.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'prometheus-node-exporter-3.11.154-1.git.1.bc9f224.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'atomic-enterprise-service-catalog / etc');
}
