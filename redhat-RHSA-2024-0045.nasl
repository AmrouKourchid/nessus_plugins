#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:0045. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201091);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id(
    "CVE-2023-29483",
    "CVE-2023-45289",
    "CVE-2023-45290",
    "CVE-2024-3727",
    "CVE-2024-24783",
    "CVE-2024-24784",
    "CVE-2024-24785",
    "CVE-2024-24786",
    "CVE-2024-28176"
  );
  script_xref(name:"RHSA", value:"2024:0045");

  script_name(english:"RHEL 8 / 9 : OpenShift Container Platform 4.16.0 (RHSA-2024:0045)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for OpenShift Container Platform 4.16.0.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:0045 advisory.

    Red Hat OpenShift Container Platform is Red Hat's cloud computing
    Kubernetes application platform solution designed for on-premise or private
    cloud deployments.

    This advisory contains the RPM packages for Red Hat OpenShift Container
    Platform 4.16.0. See the following advisory for the container images for
    this release:

    https://access.redhat.com/errata/RHSA-2024:0041

    Security Fix(es):

    * dnspython: denial of service in stub resolver (CVE-2023-29483)
    * golang: net/http/cookiejar: incorrect forwarding of sensitive headers and
    cookies on HTTP redirect (CVE-2023-45289)
    * golang: net/http: memory exhaustion in Request.ParseMultipartForm
    (CVE-2023-45290)
    * containers/image: digest type does not guarantee valid type
    (CVE-2024-3727)
    * golang: crypto/x509: Verify panics on certificates with an unknown public
    key algorithm (CVE-2024-24783)
    * golang: net/mail: comments in display names are incorrectly handled
    (CVE-2024-24784)
    * golang: html/template: errors returned from MarshalJSON methods may break
    template escaping (CVE-2024-24785)
    * golang-protobuf: encoding/protojson, internal/encoding/json: infinite
    loop in protojson.Unmarshal when unmarshaling certain forms of invalid JSON
    (CVE-2024-24786)
    * jose: resource exhaustion (CVE-2024-28176)

    For more details about the security issue(s), including the impact, a CVSS
    score, acknowledgments, and other related information, refer to the CVE
    page(s) listed in the References section.

    All OpenShift Container Platform 4.16 users are advised to upgrade to these
    updated packages and images when they are available in the appropriate
    release channel. To check for available updates, use the OpenShift CLI (oc)
    or web console. Instructions for upgrading a cluster are available at
    https://docs.openshift.com/container-platform/4.16/updating/updating_a_cluster/updating-cluster-cli.html

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_0045.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76d20d5c");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  # https://docs.openshift.com/container-platform/4.16/release_notes/ocp-4-16-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c99ed152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2262921");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2268820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274767");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:0045");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL OpenShift Container Platform 4.16.0 package based on the guidance in RHSA-2024:0045.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24785");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-3727");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 115, 200, 354, 400, 696, 835);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:butane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:butane-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:golang-github-prometheus-promu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ignition");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ignition-validate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-hyperkube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-kube-apiserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-kube-controller-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-kube-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-kubelet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-prometheus-promu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ose-aws-ecr-image-credential-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ose-azure-acr-image-credential-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ose-gcp-gcr-image-credential-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-gvproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-eventlet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-eventlet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo-tests");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
      'content/dist/layered/rhel8/ppc64le/rhocp/4.16/debug',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.16/os',
      'content/dist/layered/rhel8/ppc64le/rhocp/4.16/source/SRPMS',
      'content/dist/layered/rhel8/s390x/rhocp/4.16/debug',
      'content/dist/layered/rhel8/s390x/rhocp/4.16/os',
      'content/dist/layered/rhel8/s390x/rhocp/4.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/rhocp/4.16/debug',
      'content/dist/layered/rhel8/x86_64/rhocp/4.16/os',
      'content/dist/layered/rhel8/x86_64/rhocp/4.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'butane-0.21.0-1.rhaos4.16.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290']},
      {'reference':'butane-redistributable-0.21.0-1.rhaos4.16.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290']},
      {'reference':'cri-o-1.29.5-5.rhaos4.16.git7032128.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-24783']},
      {'reference':'cri-tools-1.29.0-3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24786']},
      {'reference':'openshift-hyperkube-4.16.0-202406170957.p0.g29c95f3.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45289', 'CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785']},
      {'reference':'openshift-kube-apiserver-4.16.0-202406170957.p0.g29c95f3.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45289', 'CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785']},
      {'reference':'openshift-kube-controller-manager-4.16.0-202406170957.p0.g29c95f3.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45289', 'CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785']},
      {'reference':'openshift-kube-scheduler-4.16.0-202406170957.p0.g29c95f3.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45289', 'CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785']},
      {'reference':'openshift-kubelet-4.16.0-202406170957.p0.g29c95f3.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45289', 'CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785']},
      {'reference':'ose-aws-ecr-image-credential-provider-4.16.0-202405311136.p0.ga53e9de.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785']},
      {'reference':'ose-azure-acr-image-credential-provider-4.16.0-202404301345.p0.g0e95532.assembly.stream.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45289', 'CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786']},
      {'reference':'ose-gcp-gcr-image-credential-provider-4.16.0-202404181812.p0.g26b43df.assembly.stream.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786']},
      {'reference':'ose-gcp-gcr-image-credential-provider-4.16.0-202404181812.p0.g26b43df.assembly.stream.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786']},
      {'reference':'ose-gcp-gcr-image-credential-provider-4.16.0-202404181812.p0.g26b43df.assembly.stream.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786']},
      {'reference':'podman-4.9.4-5.1.rhaos4.16.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-3727', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786', 'CVE-2024-28176']},
      {'reference':'podman-catatonit-4.9.4-5.1.rhaos4.16.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-3727', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786', 'CVE-2024-28176']},
      {'reference':'podman-docker-4.9.4-5.1.rhaos4.16.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-3727', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786', 'CVE-2024-28176']},
      {'reference':'podman-gvproxy-4.9.4-5.1.rhaos4.16.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-3727', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786', 'CVE-2024-28176']},
      {'reference':'podman-plugins-4.9.4-5.1.rhaos4.16.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-3727', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786', 'CVE-2024-28176']},
      {'reference':'podman-remote-4.9.4-5.1.rhaos4.16.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-3727', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786', 'CVE-2024-28176']},
      {'reference':'podman-tests-4.9.4-5.1.rhaos4.16.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-3727', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786', 'CVE-2024-28176']},
      {'reference':'runc-1.1.12-3.1.rhaos4.16.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-24783']},
      {'reference':'skopeo-1.14.4-1.rhaos4.16.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-3727', 'CVE-2024-28176']},
      {'reference':'skopeo-tests-1.14.4-1.rhaos4.16.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-3727', 'CVE-2024-28176']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/ppc64le/rhocp-ironic/4.16/debug',
      'content/dist/layered/rhel9/ppc64le/rhocp-ironic/4.16/os',
      'content/dist/layered/rhel9/ppc64le/rhocp-ironic/4.16/source/SRPMS',
      'content/dist/layered/rhel9/s390x/rhocp-ironic/4.16/debug',
      'content/dist/layered/rhel9/s390x/rhocp-ironic/4.16/os',
      'content/dist/layered/rhel9/s390x/rhocp-ironic/4.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhocp-ironic/4.16/debug',
      'content/dist/layered/rhel9/x86_64/rhocp-ironic/4.16/os',
      'content/dist/layered/rhel9/x86_64/rhocp-ironic/4.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python3-eventlet-0.33.1-6.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-29483']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/ppc64le/rhocp/4.16/debug',
      'content/dist/layered/rhel9/ppc64le/rhocp/4.16/os',
      'content/dist/layered/rhel9/ppc64le/rhocp/4.16/source/SRPMS',
      'content/dist/layered/rhel9/s390x/rhocp/4.16/debug',
      'content/dist/layered/rhel9/s390x/rhocp/4.16/os',
      'content/dist/layered/rhel9/s390x/rhocp/4.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/rhocp/4.16/debug',
      'content/dist/layered/rhel9/x86_64/rhocp/4.16/os',
      'content/dist/layered/rhel9/x86_64/rhocp/4.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'cri-o-1.29.5-5.rhaos4.16.git7032128.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-24783']},
      {'reference':'cri-tools-1.29.0-3.1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24786']},
      {'reference':'golang-github-prometheus-promu-0.15.0-15.2.gitd5383c5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-24783']},
      {'reference':'ignition-2.18.0-2.1.rhaos4.16.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-24785']},
      {'reference':'ignition-validate-2.18.0-2.1.rhaos4.16.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-24785']},
      {'reference':'openshift-hyperkube-4.16.0-202406170957.p0.g29c95f3.assembly.stream.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45289', 'CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785']},
      {'reference':'openshift-kube-apiserver-4.16.0-202406170957.p0.g29c95f3.assembly.stream.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45289', 'CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785']},
      {'reference':'openshift-kube-controller-manager-4.16.0-202406170957.p0.g29c95f3.assembly.stream.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45289', 'CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785']},
      {'reference':'openshift-kube-scheduler-4.16.0-202406170957.p0.g29c95f3.assembly.stream.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45289', 'CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785']},
      {'reference':'openshift-kubelet-4.16.0-202406170957.p0.g29c95f3.assembly.stream.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45289', 'CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785']},
      {'reference':'openshift-prometheus-promu-0.15.0-15.2.gitd5383c5.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-24783']},
      {'reference':'ose-aws-ecr-image-credential-provider-4.16.0-202405311136.p0.ga53e9de.assembly.stream.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785']},
      {'reference':'ose-azure-acr-image-credential-provider-4.16.0-202404301345.p0.g0e95532.assembly.stream.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45289', 'CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786']},
      {'reference':'ose-gcp-gcr-image-credential-provider-4.16.0-202404181812.p0.g26b43df.assembly.stream.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786']},
      {'reference':'ose-gcp-gcr-image-credential-provider-4.16.0-202404181812.p0.g26b43df.assembly.stream.el9', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786']},
      {'reference':'ose-gcp-gcr-image-credential-provider-4.16.0-202404181812.p0.g26b43df.assembly.stream.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786']},
      {'reference':'podman-4.9.4-5.1.rhaos4.16.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-3727', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786', 'CVE-2024-28176']},
      {'reference':'podman-docker-4.9.4-5.1.rhaos4.16.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-3727', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786', 'CVE-2024-28176']},
      {'reference':'podman-plugins-4.9.4-5.1.rhaos4.16.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-3727', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786', 'CVE-2024-28176']},
      {'reference':'podman-remote-4.9.4-5.1.rhaos4.16.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-3727', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786', 'CVE-2024-28176']},
      {'reference':'podman-tests-4.9.4-5.1.rhaos4.16.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2023-45290', 'CVE-2024-3727', 'CVE-2024-24783', 'CVE-2024-24784', 'CVE-2024-24785', 'CVE-2024-24786', 'CVE-2024-28176']},
      {'reference':'runc-1.1.12-3.1.rhaos4.16.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-24783']},
      {'reference':'skopeo-1.14.4-1.rhaos4.16.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-3727', 'CVE-2024-28176']},
      {'reference':'skopeo-tests-1.14.4-1.rhaos4.16.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube', 'cves':['CVE-2024-3727', 'CVE-2024-28176']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'butane / butane-redistributable / cri-o / cri-tools / etc');
}
