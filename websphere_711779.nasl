##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142140);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2015-0899");

  script_name(english:"IBM WebSphere Application Server 7.0.0.x <= 7.0.0.45 / 8.0.x <= 8.0.0.15 / 8.5.x < 8.5.5.14 / 9.x < 9.0.0.8 Security Bypass (CVE-2015-0899)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a security bypass vulnerability");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is version 7.0.0.x through 7.0.0.45, 8.0.0.x through
8.0.0.15, 8.5.0.x prior to 8.5.5.14, or 9.x prior to 9.0.0.8. It is, therefore, affected by a vulnerability in the
Apache Struts subcomponent deu to an error in the MultiPageValidator implementation. An unauthenticated, remote attacker
can exploit this, using a modified page parameter, to bypass restrictions and launch further attacks on the system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/711779");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 8.5.5.14, 9.0.0.8 or later. Alternatively, upgrade to the minimal fix pack
levels required by the interim fix and then apply Interim Fix PI95655 and PI98928.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0899");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');

app = 'IBM WebSphere Application Server';
fix = 'Interim Fix PI98928 and PI95655';

app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if (app_info['version'] =~ "^7\.")
{
  fix = 'Interim Fix PI95655';
  if ('PI95655' >< app_info['Fixes'])
    audit(AUDIT_INST_VER_NOT_VULN, app);
}
else if ('PI95655' >< app_info['Fixes'] && 'PI98928' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  {'min_version':'7.0.0.0', 'max_version':'7.0.0.45', 'fixed_display':fix},
  {'min_version':'8.0.0.0', 'max_version':'8.0.0.15', 'fixed_display':fix},
  {'min_version':'8.5.0.0', 'max_version':'8.5.5.13', 'fixed_display':'8.5.5.14 or ' + fix},
  {'min_version':'9.0.0.0', 'max_version':'9.0.0.7', 'fixed_display':'9.0.0.8 or ' + fix},
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
