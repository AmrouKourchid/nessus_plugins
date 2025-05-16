#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:0774. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194292);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2021-4213");
  script_xref(name:"RHSA", value:"2024:0774");

  script_name(english:"RHEL 8 : Red Hat Certificate System 10.4 for RHEL 8 (RHSA-2024:0774)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for Red Hat Certificate System 10.4 for RHEL 8.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2024:0774 advisory.

    Red Hat Certificate System (RHCS) is a complete implementation of an enterprise software system designed
    to manage enterprise Public Key Infrastructure (PKI) deployments.

    Security fixes:

    * JSS: memory leak in TLS connection leads to OOM (CVE-2021-4213)

    * pki-core:10.6/jss: memory leak in TLS connection leads to OOM (CVE-2021-4213)

    For more details about the security issues, refer to the link in the References section.

    Bug fixes:

    * no ROLE_ASSUME audit messages seen in TPS audit log (BZ#1549887)

    * Unassign certificate enrollment request not working (BZ#1858702)

    * Date Format on the TPS Agent Page (BZ#1984455)

    * Directory authentication plugin requires directory admin password just for user authentication
    (BZ#2017505)

    * Add SCEP AES support (BZ#2075363)

    * JSS cannot be properly initialized after using another NSS-backed security provider (BZ#2087224)

    * Empty subject field in CSR causes failure to certificate issuance (BZ#2105471)

    * RA Separation by KeyType - Set Token Status (BZ#2106153)

    * Disallowed supported_groups in TLS1.2 key exchange (BZ#2113782)

    * Some unsusable profiles are present in CA's EE page (BZ#2118662)

    * ClientIP and ServerIP are missing in ACCESS_SESSION_ESTABLISH/ACCESS_SESSION_TERMINATED Audit Event when
    PKI is acting as a Server (BZ#2122502)

    * add AES support for TMS server-side keygen on latest HSM / FIPS environment (BZ#2123071)

    * CA's Key Escrow is Failing Through httpd Reverse Proxy (BZ#2130250)

    * Provide Enrollment over Secure Transport / EST interface to Dogtag / RFC 7030 to support SCEP over EST
    (BZ#2142893)

    * DHE ciphers not working (dropping DHE ciphersuites) (BZ#2142903)

    * pkiconsole unable to connect pki servers that's in fips mode with client cert (BZ#2142904)

    * KRA and OCSP display banner prompts during pkispawn (BZ#2142905)

    * missing audit event CLIENT_ACCESS_SESSION_ESTABLISH when CS instance acting as a client and fails to
    connect (BZ#2142906)

    * EST prep work (BZ#2142907)

    * add AES support for TMS Shared Secret on latest HSM / FIPS environment (BZ#2142908)

    * CS instance when acting as a client does not observe the cipher list set in server.xml (BZ#2142909)

    * OCSP using AIA extension fails (BZ#2144080)

    * Lightweight CA: Add support for multiple sub-CAs underneath primary CA (BZ#2149115)

    * TPS Not allowing Token Status Change based on Revoke True/False and Hold till last True/False
    (BZ#2166003)

    * Unable to use the TPS UI Token Filter to filter a list of tokens (BZ#2179307)

    * TPS Not allowing Token Status Change based on Revoke True/False and Hold till last True/False (part 2)
    (BZ#2181142)

    * root CA signing cert should not have AIA extension (BZ#2182201)

    * PrettyPrintCert does not properly translate AIA information into a readable format (BZ#2184930)

    * OCSP AddCRLServlet SEVERE...NOT SUPPORTED log messages (BZ#2190283)

    * PrettyPrintCert does not properly translate Subject Information Access information into a readable
    format (BZ#2209624)

    * OCSP Responder not responding to certs issued by unknown CAs (BZ#2221818)

    * pkispawn non-CA pki instance result in TLS client-authentication to its internaldb not finding pkidbuser
    by default (BZ#2228209)

    * pkispawn externally signed sub CA clone with Thales Luna HSM fails: UNKNOWN_ISSUER (BZ#2228922)

    * OCSP responder to serve status check for itself using latest CRL (BZ#2229930)

    * RHCS Fails to Upgrade if Profile Does not exist (BZ#2230102)

    * CLIENT_ACCESS_SESSION_* audit events contain wrong ServerPort (BZ#2233740)

    * Server-side Key Generation Produces Certificates with Identical SKID (BZ#2246422)

    * Generating Keys with no OpsFlagMask set - ThalesHSM integration (BZ#2251981)

    * RootCA's OCSP fails to install with the SHA-2 subjectKeyIdentifier extension (BZ#2253044)

    * Make key wrapping algorithm configurable between AES-KWP and AES-CBC (BZ#2253675)

    * pkidestroy log keeps HSM token password (BZ#2253683)

    Users of RHCS 10 are advised to upgrade to these updated packages.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_0774.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c470bbb");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2042900");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:0774");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat Certificate System 10.4 for RHEL 8 package based on the guidance in RHSA-2024:0774.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4213");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(401);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-pki");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'redhat-pki:10': [
    {
      'repo_relative_urls': [
        'content/dist/layered/rhel8/x86_64/certsys/10.4/debug',
        'content/dist/layered/rhel8/x86_64/certsys/10.4/os',
        'content/dist/layered/rhel8/x86_64/certsys/10.4/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'jss-4.9.8-1.module+el8pki+19895+c800dfbd', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'redhat-pki-10.13.9-5.module+el8pki+21062+4ed906e8', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pki', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/redhat-pki');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module redhat-pki:10');
if ('10' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module redhat-pki:' + module_ver);

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      foreach var package_array ( module_array['pkgs'] ) {
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
        if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module redhat-pki:10');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'jss / redhat-pki');
}
