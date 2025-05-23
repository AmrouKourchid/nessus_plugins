#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212077);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id("CVE-2024-52032");
  script_xref(name:"IAVA", value:"2024-A-0772-S");

  script_name(english:"Mattermost Server 9.11.x < 9.11.3, 10.0.x < 10.0.1, 10.1.0 (MMSA-2024-00385)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Mattermost Server installed on the remote host is prior to 9.11.3, 10.0.1 or 10.1.0. It is, therefore,
affected by a vulnerability as referenced in the MMSA-2024-00385 advisory.

  - Mattermost versions 10.0.x <= 10.0.0 and 9.11.x <= 9.11.2 fail to properly query ElasticSearch when
    searching for the channel name in channel switcher which allows an attacker to get private channels names
    of channels that they are not a member of, when Elasticsearch v8 was enabled. (CVE-2024-52032)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mattermost.com/security-updates/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mattermost Server version 9.11.3, 10.0.1, 10.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-52032");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mattermost:mattermost_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mattermost_server_detect.nbin");
  script_require_keys("installed_sw/Mattermost Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Mattermost Server');

var constraints = [
  { 'min_version' : '9.11', 'fixed_version' : '9.11.3' },
  { 'min_version' : '10.0', 'fixed_version' : '10.0.1', 'fixed_display' : '10.0.1, 10.1.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
