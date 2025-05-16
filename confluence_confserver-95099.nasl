#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194909);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2024-21634");

  script_name(english:"Atlassian Confluence < 7.19.20 / 7.20.x < 8.5.7 / 8.6.x < 8.9.0 (CONFSERVER-95099)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-95099 advisory.

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
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-95099");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.20, 8.5.7, 8.9.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21634");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl", "confluence_nix_installed.nbin", "confluence_win_installed.nbin");
  script_require_keys("installed_sw/Atlassian Confluence");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Atlassian Confluence');

var constraints = [
  { 'min_version' : '5.6.0', 'max_version' : '7.17.5', 'fixed_display' : '7.19.20' },
  { 'min_version' : '7.18.0', 'max_version' : '7.18.3', 'fixed_display' : '7.19.20' },
  { 'min_version' : '7.19.0', 'max_version' : '7.19.19', 'fixed_display' : '7.19.20' }, 
  { 'min_version' : '7.20.0', 'max_version' : '7.20.3', 'fixed_display' : '8.5.7'},
  { 'min_version' : '8.0.0', 'max_version' : '8.0.4', 'fixed_display' :' 8.5.7' },
  { 'min_version' : '8.1.0', 'max_version' : '8.1.4', 'fixed_display' : '8.5.7' },
  { 'min_version' : '8.2.0', 'max_version' : '8.2.3', 'fixed_display' : '8.5.7' },
  { 'min_version' : '8.3.0', 'max_version' : '8.3.4', 'fixed_display' : '8.5.7' },
  { 'min_version' : '8.4.0', 'max_version' : '8.4.5', 'fixed_display' : '8.5.7' },
  { 'min_version' : '8.5.0', 'max_version' : '8.5.6', 'fixed_display' : '8.5.7' },
  { 'min_version' : '8.6.0', 'max_version' : '8.8.1', 'fixed_display' : '8.9.0 (Data Center Only)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
