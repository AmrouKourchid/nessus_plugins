#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209518);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-3095");

  script_name(english:"LangChain < 0.2.9 SSRF");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a machine learning library that is affected by a server side request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a langchain version that is prior to 0.2.9. It is, therefore, affected by a Server-Side 
Request Forgery vulnerability in the Web Research Retriever component in langchain-community 
(langchain-community.retrievers.web_research.WebResearchRetriever). The vulnerability arises because the Web 
Research Retriever does not restrict requests to remote internet addresses, allowing it to reach local addresses. 
This flaw enables attackers to execute port scans, access local services, and in some scenarios, read instance 
metadata from cloud environments. The vulnerability is particularly concerning as it can be exploited to abuse 
the Web Explorer server as a proxy for web attacks on third parties and interact with servers in the local network, 
including reading their response data. This could potentially lead to arbitrary code execution, depending on the 
nature of the local services. The vulnerability is limited to GET requests, as POST requests are not possible, 
but the impact on confidentiality, integrity, and availability is significant due to the potential for stolen 
credentials and state-changing interactions with internal APIs.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/advisories/GHSA-q25c-c977-4cmh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29002fc4");
  # https://huntr.com/bounties/fa3a2753-57c3-4e08-a176-d7a3ffda28fe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a991d3d8");
  # https://github.com/langchain-ai/langchain/commit/604dfe2d99246b0c09f047c604f0c63eafba31e7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48f5c6ed");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LangChain 0.2.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3095");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(918);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:langchain-ai:langchain");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_langchain_detect.nbin");
  script_require_keys("installed_sw/LangChain");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'LangChain');
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '0.2.9' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);