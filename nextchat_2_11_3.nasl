#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194721);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/19");

  script_cve_id("CVE-2023-49785");

  script_name(english:"NextChat < 2.11.3 SSRF");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a machine learning library that is affected by a Server Side Request Forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a torchserve version that is prior to 2.11.3. It is,
therefore, affected by a Server Side Request Forgery vulnerability in the api/cors endpoint.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.horizon3.ai/attack-research/attack-blogs/nextchat-an-ai-chatbot-that-lets-you-talk-to-anyone-you-want-to/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c711dba2");
  # https://github.com/ChatGPTNextWeb/ChatGPT-Next-Web/releases/tag/v2.11.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?159059b0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the NextChat 2.11.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-49785");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nextchat:nextchat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nextchat_detect.nbin");
  script_require_keys("installed_sw/NextChat");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'NextChat');
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '2.11.3' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
