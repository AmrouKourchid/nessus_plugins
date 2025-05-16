#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200978);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2024-5480");

  script_name(english:"PyTorch < 2.2.2 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a machine learning library that is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a torchserve version that is prior to  2.2.2. It is,
therefore, affected by a remote code execution vulnerability.  A vulnerability in the PyTorch's 
torch.distributed.rpc framework, specifically in versions prior to 2.2.2, allows for remote code 
execution (RCE). The framework, which is used in distributed training scenarios, does not properly 
verify the functions being called during RPC (Remote Procedure Call) operations. This oversight 
permits attackers to execute arbitrary commands by leveraging built-in Python functions such as 
eval during multi-cpu RPC communication. The vulnerability arises from the lack of restriction 
on function calls when a worker node serializes and sends a PythonUDF (User Defined Function) 
to the master node, which then deserializes and executes the function without validation. This 
flaw can be exploited to compromise master nodes initiating distributed training, potentially 
leading to the theft of sensitive AI-related data.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://huntr.com/bounties/39811836-c5b3-4999-831e-46fee8fcade3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6ab4eea");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PyTorch 2.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-5480");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:linuxfoundation:pytorch");
  script_set_attribute(attribute:"asset_categories", value:"component");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pytorch_detect.nbin");
  script_require_keys("installed_sw/Torch");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Torch');
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '2.2.2' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
