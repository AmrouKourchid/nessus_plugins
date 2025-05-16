#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210502);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/14");

  script_cve_id("CVE-2024-39720", "CVE-2024-39722");
  script_xref(name:"IAVB", value:"2024-B-0164-S");

  script_name(english:"Ollama < 0.1.46 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The Ollama instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Ollama installed on the remote host is prior to 0.1.46. It is, therefore, affected by multiple 
vulnerabilities:

  - An issue was discovered in Ollama before 0.1.46. An attacker can use two HTTP requests to upload a malformed GGUF 
    file containing just 4 bytes starting with the GGUF custom magic header. By leveraging a custom Modelfile that 
    includes a FROM statement pointing to the attacker-controlled blob file, the attacker can crash the application 
    through the CreateModel route, leading to a segmentation fault (signal SIGSEGV: segmentation violation).
    (CVE-2024-39720)

  - An issue was discovered in Ollama before 0.1.46. It exposes which files exist on the server on which it is 
    deployed via path traversal in the api/push route. (CVE-2024-39722)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oligo.security/blog/more-models-more-probllms");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ollama version 0.1.46 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-39720");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ollama:ollama");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ollama_mac_installed.nbin");
  script_require_keys("installed_sw/Ollama");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Ollama');

var constraints = [
  {'fixed_version': '0.1.46'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
