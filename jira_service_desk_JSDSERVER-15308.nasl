#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200690);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_cve_id("CVE-2024-21634");

  script_name(english:"Atlassian Jira Service Management Data Center and Server < 5.4.18 / 5.5.x < 5.12.6 / 5.13.x < 5.15.0 (JSDSERVER-15308)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Jira Service Management Data Center and Server (Jira Service Desk) host is missing a security
update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Jira Service Management Data Center and Server (Jira Service Desk) running on the remote host
is affected by a vulnerability as referenced in the JSDSERVER-15308 advisory.

  - Amazon Ion is a Java implementation of the Ion data notation. Prior to version 1.10.5, a potential denial-
    of-service issue exists in `ion-java` for applications that use `ion-java` to deserialize Ion text encoded
    data, or deserialize Ion text or binary encoded data into the `IonValue` model and then invoke certain
    `IonValue` methods on that in-memory representation. An actor could craft Ion data that, when loaded by
    the affected application and/or processed using the `IonValue` model, results in a `StackOverflowError`
    originating from the `ion-java` library. The patch is included in `ion-java` 1.10.5. As a workaround, do
    not load data which originated from an untrusted source or that could have been tampered with.
    (CVE-2024-21634)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JSDSERVER-15308");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Jira Service Management Data Center and Server version 5.4.18, 5.12.6, 5.15.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21634");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira_service_desk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "jira_service_desk_installed_win.nbin", "jira_service_desk_installed_nix.nbin");
  script_require_keys("installed_sw/JIRA Service Desk Application");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'JIRA Service Desk Application');

var constraints = [
  { 'min_version' : '0.0', 'max_version' : '4.21', 'fixed_display' : '5.4.18' },
  { 'min_version' : '4.22', 'max_version' : '4.22.6', 'fixed_display' : '5.4.18' },
  { 'equal' : '5.0', 'fixed_display' : '5.4.18' },
  { 'min_version' : '5.1', 'max_version' : '5.1.1', 'fixed_display' : '5.4.18' },
  { 'min_version' : '5.2', 'max_version' : '5.2.1', 'fixed_display' : '5.4.18' },
  { 'min_version' : '5.3', 'max_version' : '5.3.1', 'fixed_display' : '5.4.18' },
  { 'min_version' : '5.4', 'max_version' : '5.4.17', 'fixed_display' : '5.4.18' },
  { 'min_version' : '5.5', 'max_version' : '5.5.1', 'fixed_display' : '5.12.6' },
  { 'min_version' : '5.6', 'max_version' : '5.6.2', 'fixed_display' : '5.12.6' },
  { 'min_version' : '5.7', 'max_version' : '5.7.2', 'fixed_display' : '5.12.6' },
  { 'min_version' : '5.8', 'max_version' : '5.8.2', 'fixed_display' : '5.12.6' },
  { 'min_version' : '5.9', 'max_version' : '5.9.2', 'fixed_display' : '5.12.6' },
  { 'min_version' : '5.10', 'max_version' : '5.10.2', 'fixed_display' : '5.12.6' },
  { 'min_version' : '5.11', 'max_version' : '5.11.3', 'fixed_display' : '5.12.6' },
  { 'min_version' : '5.12', 'max_version' : '5.12.5', 'fixed_display' : '5.12.6' },
  { 'min_version' : '5.13', 'max_version' : '5.13.1', 'fixed_display' : '5.15.0 (Data Center Only)' },
  { 'min_version' : '5.14', 'max_version' : '5.14.2', 'fixed_display' : '5.15.0 (Data Center Only)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
