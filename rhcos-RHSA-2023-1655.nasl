#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:1655. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189435);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/26");

  script_cve_id(
    "CVE-2022-3172",
    "CVE-2022-31690",
    "CVE-2022-31692",
    "CVE-2022-42889",
    "CVE-2023-24422",
    "CVE-2023-25725",
    "CVE-2023-27898",
    "CVE-2023-27899",
    "CVE-2023-27903",
    "CVE-2023-27904"
  );
  script_xref(name:"RHSA", value:"2023:1655");
  script_xref(name:"IAVA", value:"2023-A-0127-S");
  script_xref(name:"IAVA", value:"2023-A-0593-S");

  script_name(english:"RHCOS 4 : OpenShift Container Platform 4.10.56 (RHSA-2023:1655)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat CoreOS host is missing one or more security updates for OpenShift Container Platform 4.10.56.");
  script_set_attribute(attribute:"description", value:
"The remote Red Hat Enterprise Linux CoreOS 4 host has packages installed that are affected by multiple vulnerabilities
as referenced in the RHSA-2023:1655 advisory.

  - Spring Security, versions 5.7 prior to 5.7.5, and 5.6 prior to 5.6.9, and older unsupported versions could
    be susceptible to a privilege escalation under certain conditions. A malicious user or attacker can modify
    a request initiated by the Client (via the browser) to the Authorization Server which can lead to a
    privilege escalation on the subsequent approval. This scenario can happen if the Authorization Server
    responds with an OAuth2 Access Token Response containing an empty scope list (per RFC 6749, Section 5.1)
    on the subsequent request to the token endpoint to obtain the access token. (CVE-2022-31690)

  - Spring Security, versions 5.7 prior to 5.7.5 and 5.6 prior to 5.6.9 could be susceptible to authorization
    rules bypass via forward or include dispatcher types. Specifically, an application is vulnerable when all
    of the following are true: The application expects that Spring Security applies security to forward and
    include dispatcher types. The application uses the AuthorizationFilter either manually or via the
    authorizeHttpRequests() method. The application configures the FilterChainProxy to apply to forward and/or
    include requests (e.g. spring.security.filter.dispatcher-types = request, error, async, forward, include).
    The application may forward or include the request to a higher privilege-secured endpoint.The application
    configures Spring Security to apply to every dispatcher type via
    authorizeHttpRequests().shouldFilterAllDispatcherTypes(true) (CVE-2022-31692)

  - A security issue was discovered in kube-apiserver that allows an aggregated API server to redirect client
    traffic to any URL. This could lead to the client performing unexpected actions as well as forwarding the
    client's API server credentials to third parties. (CVE-2022-3172)

  - Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and
    expanded. The standard format for interpolation is ${prefix:name}, where prefix is used to locate an
    instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with
    version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that
    could result in arbitrary code execution or contact with remote servers. These lookups are: - script -
    execute expressions using the JVM script execution engine (javax.script) - dns - resolve dns records -
    url - load values from urls, including from remote servers Applications using the interpolation defaults
    in the affected versions may be vulnerable to remote code execution or unintentional contact with remote
    servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons
    Text 1.10.0, which disables the problematic interpolators by default. (CVE-2022-42889)

  - A sandbox bypass vulnerability involving map constructors in Jenkins Script Security Plugin
    1228.vd93135a_2fb_25 and earlier allows attackers with permission to define and run sandboxed scripts,
    including Pipelines, to bypass the sandbox protection and execute arbitrary code in the context of the
    Jenkins controller JVM. (CVE-2023-24422)

  - HAProxy before 2.7.3 may allow a bypass of access control because HTTP/1 headers are inadvertently lost in
    some situations, aka request smuggling. The HTTP header parsers in HAProxy may accept empty header field
    names, which could be used to truncate the list of HTTP headers and thus make some headers disappear after
    being parsed and processed for HTTP/1.0 and HTTP/1.1. For HTTP/2 and HTTP/3, the impact is limited because
    the headers disappear before being parsed and processed, as if they had not been sent by the client. The
    fixed versions are 2.7.3, 2.6.9, 2.5.12, 2.4.22, 2.2.29, and 2.0.31. (CVE-2023-25725)

  - Jenkins 2.270 through 2.393 (both inclusive), LTS 2.277.1 through 2.375.3 (both inclusive) does not escape
    the Jenkins version a plugin depends on when rendering the error message stating its incompatibility with
    the current version of Jenkins, resulting in a stored cross-site scripting (XSS) vulnerability exploitable
    by attackers able to provide plugins to the configured update sites and have this message shown by Jenkins
    instances. (CVE-2023-27898)

  - Jenkins 2.393 and earlier, LTS 2.375.3 and earlier creates a temporary file in the default temporary
    directory with the default permissions for newly created files when uploading a plugin for installation,
    potentially allowing attackers with access to the Jenkins controller file system to read and write the
    file before it is used, potentially resulting in arbitrary code execution. (CVE-2023-27899)

  - Jenkins 2.393 and earlier, LTS 2.375.3 and earlier creates a temporary file in the default temporary
    directory with the default permissions for newly created files when uploading a file parameter through the
    CLI, potentially allowing attackers with access to the Jenkins controller file system to read and write
    the file before it is used. (CVE-2023-27903)

  - Jenkins 2.393 and earlier, LTS 2.375.3 and earlier prints an error stack trace on agent-related pages when
    agent connections are broken, potentially revealing information about Jenkins configuration that is
    otherwise inaccessible to attackers. (CVE-2023-27904)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-3172");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-31690");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-31692");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-42889");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-24422");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-25725");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-27898");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-27899");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-27903");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-27904");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:1655");
  script_set_attribute(attribute:"solution", value:
"Update the RHCOS OpenShift Container Platform 4.10.56 package based on the guidance in RHSA-2023:1655.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-27898");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42889");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Commons Text RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 79, 94, 200, 266, 269, 378, 444, 863, 918, 1188);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7:coreos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8:coreos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-2-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-hyperkube");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'reference':'haproxy22-2.2.19-4.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'jenkins-2-plugins-4.10.1680703106-1.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'jenkins-2.387.1.1680701869-1.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-hyperkube-4.10.0-202303221742.p0.g16bcd69.assembly.stream.el7', 'cpu':'x86_64', 'release':'4', 'el_string':'el7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-hyperkube-4.10.0-202303221742.p0.g16bcd69.assembly.stream.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'haproxy22 / jenkins / jenkins-2-plugins / openshift-hyperkube');
}
