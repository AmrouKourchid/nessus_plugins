#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200799);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id("CVE-2024-37279");
  script_xref(name:"IAVB", value:"2024-B-0080-S");

  script_name(english:"Kibana 8.6.3 < 8.14 (ESA-2024-15)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Kibana installed on the remote host is between 8.6.3 and 8.13.4. It is, therefore, affected by a vulnerability as
referenced in the ESA-2024-15 advisory.

  - A flaw was discovered in Kibana, allowing view-only users of alerting to use the run_soon API making the
    alerting rule run continuously, potentially affecting the system availability if the alerting rule is
    running complex queries.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://discuss.elastic.co/t/kibana-8-14-0-security-update-esa-2024-15/360887
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?abb7eaae");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kibana version 8.14.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37279");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:kibana");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kibana_web_detect.nbin");
  script_require_keys("installed_sw/Kibana");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Kibana');

var constraints = [
  { 'min_version' : '8.6.3', 'max_version' : '8.13.4', 'fixed_version' : '8.14' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
