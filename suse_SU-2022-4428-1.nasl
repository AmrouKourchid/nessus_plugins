#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:4428-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(168719);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/16");

  script_cve_id(
    "CVE-2021-3711",
    "CVE-2021-36222",
    "CVE-2021-41174",
    "CVE-2021-41244",
    "CVE-2021-43798",
    "CVE-2021-43813",
    "CVE-2021-43815",
    "CVE-2022-29170",
    "CVE-2022-31097",
    "CVE-2022-31107",
    "CVE-2022-35957",
    "CVE-2022-36062"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:4428-1");
  script_xref(name:"IAVB", value:"2023-B-0087-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : grafana (SUSE-SU-2022:4428-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 host has a package installed that is affected by
multiple vulnerabilities as referenced in the SUSE-SU-2022:4428-1 advisory.

  - ec_verify in kdc/kdc_preauth_ec.c in the Key Distribution Center (KDC) in MIT Kerberos 5 (aka krb5) before
    1.18.4 and 1.19.x before 1.19.2 allows remote attackers to cause a NULL pointer dereference and daemon
    crash. This occurs because a return value is not properly managed in a certain situation. (CVE-2021-36222)

  - In order to decrypt SM2 encrypted data an application is expected to call the API function
    EVP_PKEY_decrypt(). Typically an application will call this function twice. The first time, on entry, the
    out parameter can be NULL and, on exit, the outlen parameter is populated with the buffer size
    required to hold the decrypted plaintext. The application can then allocate a sufficiently sized buffer
    and call EVP_PKEY_decrypt() again, but this time passing a non-NULL value for the out parameter. A bug
    in the implementation of the SM2 decryption code means that the calculation of the buffer size required to
    hold the plaintext returned by the first call to EVP_PKEY_decrypt() can be smaller than the actual size
    required by the second call. This can lead to a buffer overflow when EVP_PKEY_decrypt() is called by the
    application a second time with a buffer that is too small. A malicious attacker who is able present SM2
    content for decryption to an application could cause attacker chosen data to overflow the buffer by up to
    a maximum of 62 bytes altering the contents of other data held after the buffer, possibly changing
    application behaviour or causing the application to crash. The location of the buffer is application
    dependent but is typically heap allocated. Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k).
    (CVE-2021-3711)

  - Grafana is an open-source platform for monitoring and observability. In affected versions if an attacker
    is able to convince a victim to visit a URL referencing a vulnerable page, arbitrary JavaScript content
    may be executed within the context of the victim's browser. The user visiting the malicious link must be
    unauthenticated and the link must be for a page that contains the login button in the menu bar. The url
    has to be crafted to exploit AngularJS rendering and contain the interpolation binding for AngularJS
    expressions. AngularJS uses double curly braces for interpolation binding: {{ }} ex:
    {{constructor.constructor(alert(1)')()}}. When the user follows the link and the page renders, the login
    button will contain the original link with a query parameter to force a redirect to the login page. The
    URL is not validated and the AngularJS rendering engine will execute the JavaScript expression contained
    in the URL. Users are advised to upgrade as soon as possible. If for some reason you cannot upgrade, you
    can use a reverse proxy or similar to block access to block the literal string {{ in the path.
    (CVE-2021-41174)

  - Grafana is an open-source platform for monitoring and observability. In affected versions when the fine-
    grained access control beta feature is enabled and there is more than one organization in the Grafana
    instance admins are able to access users from other organizations. Grafana 8.0 introduced a mechanism
    which allowed users with the Organization Admin role to list, add, remove, and update users' roles in
    other organizations in which they are not an admin. With fine-grained access control enabled, organization
    admins can list, add, remove and update users' roles in another organization, where they do not have
    organization admin role. All installations between v8.0 and v8.2.3 that have fine-grained access control
    beta enabled and more than one organization should be upgraded as soon as possible. If you cannot upgrade,
    you should turn off the fine-grained access control using a feature flag. (CVE-2021-41244)

  - Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through
    8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files.
    The vulnerable URL path is: `<grafana_host_url>/public/plugins//`, where is the plugin ID for any
    installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched
    versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about
    vulnerable URL paths, mitigation, and the disclosure timeline. (CVE-2021-43798)

  - Grafana is an open-source platform for monitoring and observability. Grafana prior to versions 8.3.2 and
    7.5.12 contains a directory traversal vulnerability for fully lowercase or fully uppercase .md files. The
    vulnerability is limited in scope, and only allows access to files with the extension .md to authenticated
    users only. Grafana Cloud instances have not been affected by the vulnerability. Users should upgrade to
    patched versions 8.3.2 or 7.5.12. For users who cannot upgrade, running a reverse proxy in front of
    Grafana that normalizes the PATH of the request will mitigate the vulnerability. The proxy will have to
    also be able to handle url encoded paths. Alternatively, for fully lowercase or fully uppercase .md files,
    users can block /api/plugins/.*/markdown/.* without losing any functionality beyond inlined plugin help
    text. (CVE-2021-43813)

  - Grafana is an open-source platform for monitoring and observability. Grafana prior to versions 8.3.2 and
    7.5.12 has a directory traversal for arbitrary .csv files. It only affects instances that have the
    developer testing tool called TestData DB data source enabled and configured. The vulnerability is limited
    in scope, and only allows access to files with the extension .csv to authenticated users only. Grafana
    Cloud instances have not been affected by the vulnerability. Versions 8.3.2 and 7.5.12 contain a patch for
    this issue. There is a workaround available for users who cannot upgrade. Running a reverse proxy in front
    of Grafana that normalizes the PATH of the request will mitigate the vulnerability. The proxy will have to
    also be able to handle url encoded paths. (CVE-2021-43815)

  - Grafana is an open-source platform for monitoring and observability. In Grafana Enterprise, the Request
    security feature allows list allows to configure Grafana in a way so that the instance doesn't call or
    only calls specific hosts. The vulnerability present starting with version 7.4.0-beta1 and prior to
    versions 7.5.16 and 8.5.3 allows someone to bypass these security configurations if a malicious datasource
    (running on an allowed host) returns an HTTP redirect to a forbidden host. The vulnerability only impacts
    Grafana Enterprise when the Request security allow list is used and there is a possibility to add a custom
    datasource to Grafana which returns HTTP redirects. In this scenario, Grafana would blindly follow the
    redirects and potentially give secure information to the clients. Grafana Cloud is not impacted by this
    vulnerability. Versions 7.5.16 and 8.5.3 contain a patch for this issue. There are currently no known
    workarounds. (CVE-2022-29170)

  - Grafana is an open-source platform for monitoring and observability. Versions on the 8.x and 9.x branch
    prior to 9.0.3, 8.5.9, 8.4.10, and 8.3.10 are vulnerable to stored cross-site scripting via the Unified
    Alerting feature of Grafana. An attacker can exploit this vulnerability to escalate privilege from editor
    to admin by tricking an authenticated admin to click on a link. Versions 9.0.3, 8.5.9, 8.4.10, and 8.3.10
    contain a patch. As a workaround, it is possible to disable alerting or use legacy alerting.
    (CVE-2022-31097)

  - Grafana is an open-source platform for monitoring and observability. In versions 5.3 until 9.0.3, 8.5.9,
    8.4.10, and 8.3.10, it is possible for a malicious user who has authorization to log into a Grafana
    instance via a configured OAuth IdP which provides a login name to take over the account of another user
    in that Grafana instance. This can occur when the malicious user is authorized to log in to Grafana via
    OAuth, the malicious user's external user id is not already associated with an account in Grafana, the
    malicious user's email address is not already associated with an account in Grafana, and the malicious
    user knows the Grafana username of the target user. If these conditions are met, the malicious user can
    set their username in the OAuth provider to that of the target user, then go through the OAuth flow to log
    in to Grafana. Due to the way that external and internal user accounts are linked together during login,
    if the conditions above are all met then the malicious user will be able to log in to the target user's
    Grafana account. Versions 9.0.3, 8.5.9, 8.4.10, and 8.3.10 contain a patch for this issue. As a
    workaround, concerned users can disable OAuth login to their Grafana instance, or ensure that all users
    authorized to log in via OAuth have a corresponding user account in Grafana linked to their email address.
    (CVE-2022-31107)

  - Grafana is an open-source platform for monitoring and observability. Versions prior to 9.1.6 and 8.5.13
    are vulnerable to an escalation from admin to server admin when auth proxy is used, allowing an admin to
    take over the server admin account and gain full control of the grafana instance. All installations should
    be upgraded as soon as possible. As a workaround deactivate auth proxy following the instructions at:
    https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/auth-
    proxy/ (CVE-2022-35957)

  - Grafana is an open-source platform for monitoring and observability. In versions prior to 8.5.13, 9.0.9,
    and 9.1.6, Grafana is subject to Improper Preservation of Permissions resulting in privilege escalation on
    some folders where Admin is the only used permission. The vulnerability impacts Grafana instances where
    RBAC was disabled and enabled afterwards, as the migrations which are translating legacy folder
    permissions to RBAC permissions do not account for the scenario where the only user permission in the
    folder is Admin, as a result RBAC adds permissions for Editors and Viewers which allow them to edit and
    view folders accordingly. This issue has been patched in versions 8.5.13, 9.0.9, and 9.1.6. A workaround
    when the impacted folder/dashboard is known is to remove the additional permissions manually.
    (CVE-2022-36062)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192763");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-36222");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3711");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41174");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43813");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43815");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-29170");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31097");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-31107");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-35957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-36062");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-December/013218.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52f1f3b9");
  script_set_attribute(attribute:"solution", value:
"Update the affected grafana package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3711");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grafana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'grafana-8.5.13-150200.3.29.5', 'sp':'4', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'grafana-8.5.13-150200.3.29.5', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'grafana-8.5.13-150200.3.29.5', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'grafana-8.5.13-150200.3.29.5', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grafana');
}
