#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214589);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/03");

  script_cve_id("CVE-2024-43709");
  script_xref(name:"IAVA", value:"2025-A-0057");

  script_name(english:"Elasticsearch 8.0.x < 8.13.3 / 7.17.21 (ESA-2024-25)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Elasticsearch installed on the remote host is prior to 7.17.21 or 8.13.3. It is, therefore, affected by 
a vulnerability as referenced in the ESA-2024-25 advisory.

  - An allocation of resources without limits or throttling in Elasticsearch can lead to an OutOfMemoryError
    exception resulting in a crash via a specially crafted query using an SQL function. (CVE-2024-43709)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://discuss.elastic.co/t/elasticsearch-7-17-21-and-8-13-3-security-update-esa-2024-25/373442
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c41645fa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Elasticsearch version 7.17.21 / 8.13.3 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43709");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:elasticsearch");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elastic:elasticsearch");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("elasticsearch_detect.nbin", "elastic_elasticsearch_nix_installed.nbin");
  script_require_keys("installed_sw/Elasticsearch");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Elasticsearch');

var constraints = [
  { 'fixed_version' : '7.17.21' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.13.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
