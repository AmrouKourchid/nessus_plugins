#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202051);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/11");

  script_cve_id("CVE-2024-38086");

  script_name(english:"Microsoft Azure Kinect SDK < 1.4.2 Remote Code Execution (July 2024)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Azure Kinect SDK installed on the remote host is prior to 1.4.2. It is, therefore, affected
by an undisclosed remote code execution vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38086
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?923985f2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Azure Kinect SDK 1.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38086");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:azure_kinect_sdk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_azure_kinect_sdk_win_installed.nbin");

  exit(0);
}

include('vcf.inc');

var appname = 'Microsoft Azure Kinect SDK';
var app_info = vcf::get_app_info(app:appname);

var constraints = [
  { 'fixed_version' : '1.4.2' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
