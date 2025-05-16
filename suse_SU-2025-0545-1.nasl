#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0545-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(216397);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id(
    "CVE-2023-3128",
    "CVE-2023-6152",
    "CVE-2024-6837",
    "CVE-2024-8118",
    "CVE-2024-45337"
  );
  script_xref(name:"IAVB", value:"2023-B-0044-S");
  script_xref(name:"IAVB", value:"2024-B-0012-S");
  script_xref(name:"IAVB", value:"2024-B-0142-S");
  script_xref(name:"IAVB", value:"2025-B-0016");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0545-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : grafana (SUSE-SU-2025:0545-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as
referenced in the SUSE-SU-2025:0545-1 advisory.

    grafana was updated from version 9.5.18 to 10.4.13 (jsc#PED-11591,jsc#PED-11649):

    - Security issues fixed:
      * CVE-2024-45337: Prevent possible misuse of ServerConfig.PublicKeyCallback by upgrading
        golang.org/x/crypto (bsc#1234554)
      * CVE-2023-3128: Fixed authentication bypass using Azure AD OAuth (bsc#1212641)
      * CVE-2023-6152: Add email verification when updating user email (bsc#1219912)
      * CVE-2024-6837: Fixed potential data source permission escalation (bsc#1236301)
      * CVE-2024-8118: Fixed permission on external alerting rule write endpoint (bsc#1231024)

    - Potential breaking changes in version 10:
      * In panels using the `extract fields` transformation, where one
        of the extracted names collides with one of the already
        existing ields, the extracted field will be renamed.
      * For the existing backend mode users who have table
        visualization might see some inconsistencies on their panels.
        We have updated the table column naming. This will
        potentially affect field transformations and/or field
        overrides. To resolve this either: update transformation or
        field override.
      * For the existing backend mode users who have Transformations
        with the `time` field, might see their transformations are
        not working. Those panels that have broken transformations
        will fail to render. This is because we changed the field
        key. To resolve this either: Remove the affected panel and
        re-create it; Select the `Time` field again; Edit the `time`
        field as `Time` for transformation in `panel.json` or
        `dashboard.json`
      * The following data source permission endpoints have been removed:
        `GET /datasources/:datasourceId/permissions`
        `POST /api/datasources/:datasourceId/permissions`
        `DELETE /datasources/:datasourceId/permissions`
        `POST /datasources/:datasourceId/enable-permissions`
        `POST /datasources/:datasourceId/disable-permissions`
        - Please use the following endpoints instead:
          `GET /api/access-control/datasources/:uid` for listing data
           source permissions
          `POST /api/access-control/datasources/:uid/users/:id`,
          `POST /api/access-control/datasources/:uid/teams/:id` and
          `POST /api/access-control/datasources/:uid/buildInRoles/:id`
          for adding or removing data source permissions
      * If you are using Terraform Grafana provider to manage data source permissions, you will need to
    upgrade your
        provider.
      * For the existing backend mode users who have table visualization might see some inconsistencies on
    their panels.
        We have updated the table column naming. This will potentially affect field transformations and/or
    field overrides.
      * The deprecated `/playlists/{uid}/dashboards` API endpoint has been removed.
        Dashboard information can be retrieved from the `/dashboard/...` APIs.
      * The `PUT /api/folders/:uid` endpoint no more supports modifying the folder's `UID`
      * Removed all components for the old panel header design.
      * Please review https://grafana.com/docs/grafana/next/breaking-changes/breaking-changes-v10-3/
        for more details
      * OAuth role mapping enforcement: This change impacts GitHub,
        Gitlab, Okta, and Generic OAuth. To avoid overriding manually
        set roles, enable the skip_org_role_sync option in the
        Grafana configuration for your OAuth provider before
        upgrading
      * Angular has been deprecated
      * Grafana legacy alerting has been deprecated
      * API keys are migrating to service accounts
      * The experimental dashboard previews feature is removed
      * Usernames are now case-insensitive by default
      * Grafana OAuth integrations do not work anymore with email lookups
      * The Alias field in the CloudWatch data source is removed
      * Athena data source plugin must be updated to version >=2.9.3
      * Redshift data source plugin must be updated to version >=1.8.3
      * DoiT International BigQuery plugin no longer supported
      * Please review https://grafana.com/docs/grafana/next/breaking-changes/breaking-changes-v10-0
        for more details

    - This update brings many new features, enhancements and fixes highlighted at:
      * https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v10-4/
      * https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v10-3/
      * https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v10-2/
      * https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v10-1/
      * https://grafana.com/docs/grafana/next/whatsnew/whats-new-in-v10-0/

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219912");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231024");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1236301");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-February/020341.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14eb4367");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3128");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6152");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45337");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8118");
  script_set_attribute(attribute:"solution", value:
"Update the affected grafana package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3128");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-8118");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grafana");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'grafana-10.4.13-150200.3.59.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'grafana-10.4.13-150200.3.59.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']}
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
