#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206976);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/16");

  script_cve_id("CVE-2023-46229");

  script_name(english:"LangChain Python Library < 0.0.317 (CVE-2023-46229)");

  script_set_attribute(attribute:"synopsis", value:
"A Python library installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"LangChain is a framework for developing applications powered by large language models. LangChain before 0.0.317 allows
SSRF via document_loaders/recursive_url_loader.py because crawling can proceed from an external server to an internal 
server. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-655w-fm8m-m478");
  script_set_attribute(attribute:"see_also", value:"https://github.com/langchain-ai/langchain/pull/11925");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LangChain version 0.0.317 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46229");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:langchain:langchain_experimental");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_langchain_detect.nbin");
  script_require_ports("Host/nix/Python/Packages/Enumerated", "Host/win/Python/Packages/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_name = 'LangChain';
var app_info = vcf::get_app_info(app:app_name);

var constraints = [
  { 'fixed_version' : '0.0.317' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
