#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233434);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/15");

  script_cve_id(
    "CVE-2024-12055",
    "CVE-2024-12886",
    "CVE-2025-0315",
    "CVE-2025-0317"
  );
  script_xref(name:"IAVB", value:"2025-B-0041");

  script_name(english:"Ollama <= 0.3.14 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The Ollama instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Ollama installed on the remote host is prior or equal to 0.3.14. It is, therefore, affected by multiple
vulnerabilities, including the following:

  - A vulnerability in ollama/ollama versions <=0.3.14 allows a malicious user to upload and create a customized
    GGUF model file on the Ollama server. This can lead to a division by zero error in the ggufPadding
    function, causing the server to crash and resulting in a Denial of Service (DoS) attack. (CVE-2025-0317)
    
  - A vulnerability in ollama/ollama <=0.3.14 allows a malicious user to create a customized GGUF model file,
    upload it to the Ollama server, and create it. This can cause the server to allocate unlimited memory,
    leading to a Denial of Service (DoS) attack. (CVE-2025-0315)

  - A vulnerability in Ollama versions <=0.3.14 allows a malicious user to create a customized gguf model
    file that can be uploaded to the public Ollama server. When the server processes this malicious model,
    it crashes, leading to a Denial of Service (DoS) attack. The root cause of the issue is an out-of-bounds
    read in the gguf.go file. (CVE-2024-12055)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://huntr.com/bounties/a9951bca-9bd8-49b2-b143-4cd4219f9fa0");
  script_set_attribute(attribute:"see_also", value:"https://huntr.com/bounties/da414d29-b55a-496f-b135-17e0fcec67bc");
  script_set_attribute(attribute:"see_also", value:"https://huntr.com/bounties/f115fe52-58af-4844-ad29-b1c25f7245df");
  script_set_attribute(attribute:"see_also", value:"https://huntr.com/bounties/7b111d55-8215-4727-8807-c5ed4cf1bfbe");
  script_set_attribute(attribute:"solution", value:
"Upgrade Ollama to a version later than 0.3.14.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-12055");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ollama:ollama");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ollama_mac_installed.nbin", "ollama_nix_installed.nbin");
  script_require_keys("installed_sw/Ollama");

  exit(0);
}
include('vdf.inc');

# macos detection with brew install registers ollama, macos detection with non-brew install registers Ollama

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'Ollama', 'type': 'app'},
      'requires': [ {'scope': 'target', 'match_one': {'os': ['linux', 'macos'] } } ],
      'check_algorithm': 'default',
      'constraints': [
        {
          'fixed_version': '0.3.15', 'fixed_display' : 'A version greater than 0.3.14'
        }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);
