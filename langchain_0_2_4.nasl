#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209519);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-5998");

  script_name(english:"LangChain < 0.2.4 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a machine learning library that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a langchain version that is prior to 0.2.4. It is,
therefore, affected by a vulnerability in the FAISS.deserialize_from_bytes function of 
langchain-ai/langchain which allows for pickle deserialization of untrusted data. This can lead to the 
execution of arbitrary commands via the os.system function.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/advisories/GHSA-q25c-c977-4cmh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29002fc4");
  # https://huntr.com/bounties/fa3a2753-57c3-4e08-a176-d7a3ffda28fe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a991d3d8");
  # https://github.com/langchain-ai/langchain/commit/77209f315efd13442ec51c67719ba37dfaa44511
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?680fa077");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LangChain 0.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5998");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(502);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/17");
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
  { 'fixed_version' : '0.2.4' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);