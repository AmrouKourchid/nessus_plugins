#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200480);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id("CVE-2024-37280");
  script_xref(name:"IAVA", value:"2024-A-0337-S");

  script_name(english:"Elasticsearch 8.13.1 <= 8.13.4 DoS (ESA-2024-14)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability..");
  script_set_attribute(attribute:"description", value:
"The version of Elasticsearch installed on the remote host is between 8.13.1 and 8.13.4. It is, therefore,
affected by a denial of service (DoS) vulnerability as referenced in the ESA-2024-14 advisory:

  - A flaw was discovered in Elasticsearch, affecting document ingestion when an index template contains a
  dynamic field mapping of “passthrough” type. Under certain circumstances, ingesting documents in this index
  would cause a StackOverflow exception to be thrown and ultimately lead to a Denial of Service. Note that
  passthrough fields is an experimental feature. (CVE-2024-37280)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://discuss.elastic.co/t/elasticsearch-8-14-0-security-update-esa-2024-14/361007/1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f10ffef7");
  script_set_attribute(attribute:"solution", value:
"Upgrade Elasticsearch to 8.14.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37280");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/13");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:elasticsearch");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elastic:elasticsearch");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("elasticsearch_detect.nbin", "elastic_elasticsearch_nix_installed.nbin");
  script_require_keys("installed_sw/Elasticsearch");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Elasticsearch');

var constraints = [
  { 'min_version' : '8.13.1', 'max_version' : '8.13.4', 'fixed_version' : '8.14.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
