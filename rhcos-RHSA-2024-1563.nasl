#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:1563. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192860);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id("CVE-2024-1394", "CVE-2024-24786", "CVE-2024-28180");
  script_xref(name:"RHSA", value:"2024:1563");

  script_name(english:"RHCOS 4 : OpenShift Container Platform 4.15.6 (RHSA-2024:1563)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat CoreOS host is missing one or more security updates for OpenShift Container Platform 4.15.6.");
  script_set_attribute(attribute:"description", value:
"The remote Red Hat Enterprise Linux CoreOS 4 host has packages installed that are affected by multiple vulnerabilities
as referenced in the RHSA-2024:1563 advisory.

  - A memory leak flaw was found in Golang in the RSA encrypting/decrypting code, which might lead to a
    resource exhaustion vulnerability using attacker-controlled inputs. The memory leak happens in
    github.com/golang-fips/openssl/openssl/rsa.go#L113. The objects leaked are pkey and ctx. That function
    uses named return parameters to free pkey and ctx if there is an error initializing the context or
    setting the different properties. All return statements related to error cases follow the return nil,
    nil, fail(...) pattern, meaning that pkey and ctx will be nil inside the deferred function that should
    free them. (CVE-2024-1394)

  - The protojson.Unmarshal function can enter an infinite loop when unmarshaling certain forms of invalid
    JSON. This condition can occur when unmarshaling into a message which contains a google.protobuf.Any
    value, or when the UnmarshalOptions.DiscardUnknown option is set. (CVE-2024-24786)

  - Package jose aims to provide an implementation of the Javascript Object Signing and Encryption set of
    standards. An attacker could send a JWE containing compressed data that used large amounts of memory and
    CPU when decompressed by Decrypt or DecryptMulti. Those functions now return an error if the decompressed
    data would exceed 250kB or 10x the compressed size (whichever is larger). This vulnerability has been
    patched in versions 4.0.1, 3.0.3 and 2.6.3. (CVE-2024-28180)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2024-1394");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2024-24786");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2024-28180");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:1563");
  script_set_attribute(attribute:"solution", value:
"Update the RHCOS OpenShift Container Platform 4.15.6 packages based on the guidance in RHSA-2024:1563.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1394");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-24786");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(401, 409, 835);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8:coreos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9:coreos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:butane");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:butane-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ignition");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ignition-validate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ose-aws-ecr-image-credential-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-gvproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo-tests");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat CoreOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '4.15')) audit(AUDIT_OS_NOT, 'Red Hat CoreOS 4.15', 'Red Hat CoreOS ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat CoreOS', cpu);

var pkgs = [
    {'reference':'buildah-1.29.1-20.3.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube'},
    {'reference':'buildah-1.29.1-20.3.rhaos4.15.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube'},
    {'reference':'buildah-tests-1.29.1-20.3.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube'},
    {'reference':'buildah-tests-1.29.1-20.3.rhaos4.15.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube'},
    {'reference':'butane-0.20.0-1.1.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'butane-redistributable-0.20.0-1.1.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'containernetworking-plugins-1.4.0-1.2.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube'},
    {'reference':'cri-o-1.28.4-8.rhaos4.15.git24f50b9.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'cri-o-1.28.4-8.rhaos4.15.git24f50b9.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'cri-tools-1.28.0-3.1.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'cri-tools-1.28.0-3.1.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'ignition-2.16.2-2.1.rhaos4.15.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'ignition-validate-2.16.2-2.1.rhaos4.15.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-4.15.0-202403211240.p0.g62c4d45.assembly.stream.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-4.15.0-202403211240.p0.g62c4d45.assembly.stream.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-redistributable-4.15.0-202403211240.p0.g62c4d45.assembly.stream.el8', 'cpu':'x86_64', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-redistributable-4.15.0-202403211240.p0.g62c4d45.assembly.stream.el9', 'cpu':'x86_64', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'ose-aws-ecr-image-credential-provider-4.15.0-202403211549.p0.g2e3cca1.assembly.stream.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'ose-aws-ecr-image-credential-provider-4.15.0-202403211549.p0.g2e3cca1.assembly.stream.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-4.4.1-21.1.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-4.4.1-21.1.rhaos4.15.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-catatonit-4.4.1-21.1.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-docker-4.4.1-21.1.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-docker-4.4.1-21.1.rhaos4.15.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-gvproxy-4.4.1-21.1.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-gvproxy-4.4.1-21.1.rhaos4.15.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-plugins-4.4.1-21.1.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-plugins-4.4.1-21.1.rhaos4.15.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-remote-4.4.1-21.1.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-remote-4.4.1-21.1.rhaos4.15.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-tests-4.4.1-21.1.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-tests-4.4.1-21.1.rhaos4.15.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'runc-1.1.12-1.1.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube'},
    {'reference':'runc-1.1.12-1.1.rhaos4.15.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4', 'exists_check':'openshift-hyperkube'},
    {'reference':'skopeo-1.11.2-21.2.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
    {'reference':'skopeo-1.11.2-21.2.rhaos4.15.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
    {'reference':'skopeo-tests-1.11.2-21.2.rhaos4.15.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
    {'reference':'skopeo-tests-1.11.2-21.2.rhaos4.15.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'RHCOS' + package_array['release'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (reference &&
      _release &&
      (!exists_check || rpm_exists(release:_release, rpm:exists_check)) &&
      rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'buildah / buildah-tests / butane / butane-redistributable / etc');
}
