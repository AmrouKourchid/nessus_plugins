#%NASL_MIN_LEVEL 80900

include('compat.inc');

if (description)
{
  script_id(207350);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-42479");

  script_name(english:"LLama cpp python binding < 0.2.88 Arbitrary Write Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an Arbitrary Code Injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of llama.cpp installed on the remote host is prior to 0.2.88. It is, therefore, affected by an
arbitrary write vulnerability. This vulnerability was combined with another arbitrary address read 
vulnerability to achieve RCE, demonstrating the significant impact of the vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://github.com/ggerganov/llama.cpp/security/advisories/GHSA-wcr5-566p-9cwj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?95db7d76");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the llama-cpp-python version 0.2.88 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42479");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:python:llama-cpp");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_llama-cpp_detect.nbin");
  script_require_keys("installed_sw/llama_cpp_python");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'llama_cpp_python');
var constraints = [
    { 'fixed_version':'0.2.88' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
        
