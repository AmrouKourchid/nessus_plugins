#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:0560. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189429);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/24");

  script_cve_id(
    "CVE-2020-7692",
    "CVE-2022-25857",
    "CVE-2022-30946",
    "CVE-2022-30952",
    "CVE-2022-30953",
    "CVE-2022-30954",
    "CVE-2022-36882",
    "CVE-2022-36883",
    "CVE-2022-36884",
    "CVE-2022-36885",
    "CVE-2022-43401",
    "CVE-2022-43402",
    "CVE-2022-43403",
    "CVE-2022-43404",
    "CVE-2022-43405",
    "CVE-2022-43406",
    "CVE-2022-43407",
    "CVE-2022-43408",
    "CVE-2022-43409",
    "CVE-2022-45047",
    "CVE-2022-45379",
    "CVE-2022-45380",
    "CVE-2022-45381"
  );
  script_xref(name:"RHSA", value:"2023:0560");

  script_name(english:"RHCOS 4 : OpenShift Container Platform 4.10.51 (RHSA-2023:0560)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat CoreOS host is missing one or more security updates for OpenShift Container Platform 4.10.51.");
  script_set_attribute(attribute:"description", value:
"The remote Red Hat Enterprise Linux CoreOS 4 host has a package installed that is affected by multiple vulnerabilities
as referenced in the RHSA-2023:0560 advisory.

  - PKCE support is not implemented in accordance with the RFC for OAuth 2.0 for Native Apps. Without the use
    of PKCE, the authorization code returned by an authorization server is not enough to guarantee that the
    client that issued the initial authorization request is the one that will be authorized. An attacker is
    able to obtain the authorization code using a malicious app on the client-side and use it to gain
    authorization to the protected resource. This affects the package com.google.oauth-client:google-oauth-
    client before 1.31.0. (CVE-2020-7692)

  - The package org.yaml:snakeyaml from 0 and before 1.31 are vulnerable to Denial of Service (DoS) due
    missing to nested depth limitation for collections. (CVE-2022-25857)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Script Security Plugin 1158.v7c1b_73a_69a_08
    and earlier allows attackers to have Jenkins send an HTTP request to an attacker-specified webserver.
    (CVE-2022-30946)

  - Jenkins Pipeline SCM API for Blue Ocean Plugin 1.25.3 and earlier allows attackers with Job/Configure
    permission to access credentials with attacker-specified IDs stored in the private per-user credentials
    stores of any attacker-specified user in Jenkins. (CVE-2022-30952)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Blue Ocean Plugin 1.25.3 and earlier allows
    attackers to connect to an attacker-specified HTTP server. (CVE-2022-30953)

  - Jenkins Blue Ocean Plugin 1.25.3 and earlier does not perform a permission check in several HTTP
    endpoints, allowing attackers with Overall/Read permission to connect to an attacker-specified HTTP
    server. (CVE-2022-30954)

  - A cross-site request forgery (CSRF) vulnerability in Jenkins Git Plugin 4.11.3 and earlier allows
    attackers to trigger builds of jobs configured to use an attacker-specified Git repository and to cause
    them to check out an attacker-specified commit. (CVE-2022-36882)

  - A missing permission check in Jenkins Git Plugin 4.11.3 and earlier allows unauthenticated attackers to
    trigger builds of jobs configured to use an attacker-specified Git repository and to cause them to check
    out an attacker-specified commit. (CVE-2022-36883)

  - The webhook endpoint in Jenkins Git Plugin 4.11.3 and earlier provide unauthenticated attackers
    information about the existence of jobs configured to use an attacker-specified Git repository.
    (CVE-2022-36884)

  - Jenkins GitHub Plugin 1.34.4 and earlier uses a non-constant time comparison function when checking
    whether the provided and computed webhook signatures are equal, allowing attackers to use statistical
    methods to obtain a valid webhook signature. (CVE-2022-36885)

  - A sandbox bypass vulnerability involving various casts performed implicitly by the Groovy language runtime
    in Jenkins Script Security Plugin 1183.v774b_0b_0a_a_451 and earlier allows attackers with permission to
    define and run sandboxed scripts, including Pipelines, to bypass the sandbox protection and execute
    arbitrary code in the context of the Jenkins controller JVM. (CVE-2022-43401)

  - A sandbox bypass vulnerability involving various casts performed implicitly by the Groovy language runtime
    in Jenkins Pipeline: Groovy Plugin 2802.v5ea_628154b_c2 and earlier allows attackers with permission to
    define and run sandboxed scripts, including Pipelines, to bypass the sandbox protection and execute
    arbitrary code in the context of the Jenkins controller JVM. (CVE-2022-43402)

  - A sandbox bypass vulnerability involving casting an array-like value to an array type in Jenkins Script
    Security Plugin 1183.v774b_0b_0a_a_451 and earlier allows attackers with permission to define and run
    sandboxed scripts, including Pipelines, to bypass the sandbox protection and execute arbitrary code in the
    context of the Jenkins controller JVM. (CVE-2022-43403)

  - A sandbox bypass vulnerability involving crafted constructor bodies and calls to sandbox-generated
    synthetic constructors in Jenkins Script Security Plugin 1183.v774b_0b_0a_a_451 and earlier allows
    attackers with permission to define and run sandboxed scripts, including Pipelines, to bypass the sandbox
    protection and execute arbitrary code in the context of the Jenkins controller JVM. (CVE-2022-43404)

  - A sandbox bypass vulnerability in Jenkins Pipeline: Groovy Libraries Plugin 612.v84da_9c54906d and earlier
    allows attackers with permission to define untrusted Pipeline libraries and to define and run sandboxed
    scripts, including Pipelines, to bypass the sandbox protection and execute arbitrary code in the context
    of the Jenkins controller JVM. (CVE-2022-43405)

  - A sandbox bypass vulnerability in Jenkins Pipeline: Deprecated Groovy Libraries Plugin 583.vf3b_454e43966
    and earlier allows attackers with permission to define untrusted Pipeline libraries and to define and run
    sandboxed scripts, including Pipelines, to bypass the sandbox protection and execute arbitrary code in the
    context of the Jenkins controller JVM. (CVE-2022-43406)

  - Jenkins Pipeline: Input Step Plugin 451.vf1a_a_4f405289 and earlier does not restrict or sanitize the
    optionally specified ID of the 'input' step, which is used for the URLs that process user interactions for
    the given 'input' step (proceed or abort) and is not correctly encoded, allowing attackers able to
    configure Pipelines to have Jenkins build URLs from 'input' step IDs that would bypass the CSRF protection
    of any target URL in Jenkins when the 'input' step is interacted with. (CVE-2022-43407)

  - Jenkins Pipeline: Stage View Plugin 2.26 and earlier does not correctly encode the ID of 'input' steps
    when using it to generate URLs to proceed or abort Pipeline builds, allowing attackers able to configure
    Pipelines to specify 'input' step IDs resulting in URLs that would bypass the CSRF protection of any
    target URL in Jenkins. (CVE-2022-43408)

  - Jenkins Pipeline: Supporting APIs Plugin 838.va_3a_087b_4055b and earlier does not sanitize or properly
    encode URLs of hyperlinks sending POST requests in build logs, resulting in a stored cross-site scripting
    (XSS) vulnerability exploitable by attackers able to create Pipelines. (CVE-2022-43409)

  - Class org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider in Apache MINA SSHD <= 2.9.1 uses
    Java deserialization to load a serialized java.security.PrivateKey. The class is one of several
    implementations that an implementor using Apache MINA SSHD can choose for loading the host keys of an SSH
    server. (CVE-2022-45047)

  - Jenkins Script Security Plugin 1189.vb_a_b_7c8fd5fde and earlier stores whole-script approvals as the
    SHA-1 hash of the script, making it vulnerable to collision attacks. (CVE-2022-45379)

  - Jenkins JUnit Plugin 1159.v0b_396e1e07dd and earlier converts HTTP(S) URLs in test report output to
    clickable links in an unsafe manner, resulting in a stored cross-site scripting (XSS) vulnerability
    exploitable by attackers with Item/Configure permission. (CVE-2022-45380)

  - Jenkins Pipeline Utility Steps Plugin 2.13.1 and earlier does not restrict the set of enabled prefix
    interpolators and bundles versions of Apache Commons Configuration library that enable the 'file:' prefix
    interpolator by default, allowing attackers able to configure Pipelines to read arbitrary files from the
    Jenkins controller file system. (CVE-2022-45381)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-7692");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-25857");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-30946");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-30952");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-30953");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-30954");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-36882");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-36883");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-36884");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-36885");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-43401");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-43402");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-43403");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-43404");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-43405");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-43406");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-43407");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-43408");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-43409");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-45047");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-45379");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-45380");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-45381");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:0560");
  script_set_attribute(attribute:"solution", value:
"Update the RHCOS OpenShift Container Platform 4.10.51 package based on the guidance in RHSA-2023:0560.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7692");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-43406");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 200, 208, 285, 328, 352, 358, 400, 502, 552, 668, 693, 838, 862);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8:coreos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-2-plugins");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '4.10')) audit(AUDIT_OS_NOT, 'Red Hat CoreOS 4.10', 'Red Hat CoreOS ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat CoreOS', cpu);

var pkgs = [
    {'reference':'jenkins-2-plugins-4.10.1675144701-1.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jenkins-2-plugins');
}
