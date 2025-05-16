#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235353);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/06");

  script_cve_id("CVE-2025-32375");
  script_cwe_id(502);

  script_name(english:"BentoML 1.x < 1.4.8 Arbitrary Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The BentoML library installed on the remote host is affected by a code injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the BentoML library installed on the remote host has an arbitrary code execution vulnerability. 
BentoML is a Python library for building online serving systems optimized for AI apps and model inference. 
Prior to 1.4.8, there was an insecure deserialization in BentoML's runner server. By setting specific headers 
and parameters in the POST request, it is possible to execute any unauthorized arbitrary code on the server, 
which will grant the attackers to have the initial access and information disclosure on the server.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://zeropath.com/blog/critical-rce-bentoml-cve-2025-32375");
  # https://github.com/bentoml/BentoML/security/advisories/GHSA-7v4r-c989-xh26
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbbeef33");
  script_set_attribute(attribute:"solution", value:
"This vulnerability is currently not fixed. Fix the code manually or monitor new releases for a fix.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-32375");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bentoml:bentoml");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_bentoml_detect.nasl");
  script_require_keys("installed_sw/BentoML");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'product': {'name': 'BentoML', 'type': 'app'},
      'check_algorithm': 'default',
      'constraints': [
        {
          'min_version':'1.0.0', 'fixed_version': '1.4.8'
        }
      ]
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result:result);