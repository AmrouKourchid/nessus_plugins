#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233868);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2025-3047", "CVE-2025-3048");
  script_xref(name:"IAVB", value:"2025-A-0212");

  script_name(english:"AWS SAM CLI < 1.133.0 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The AWS SAM CLI instance installed on the remote host is affected multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of AWS SAM CLI installed on the remote host is prior to 1.133.0 and is,
therefore, affected by multiple vulnerabilities:

  - When running the AWS SAM CLI build process with Docker and symlinks are included in the build files, the container 
    environment allows a user to access privileged files on the host by leveraging the elevated permissions granted to 
    the tool. A user could leverage the elevated permissions to access restricted files via symlinks and copy them to a 
    more permissive location on the container. This issue affects AWS SAM CLI <= v1.132.0 and has been resolved in v1.133.0.
    To retain the previous behavior after upgrading and allow symlinks to resolve on the host machine, please use the 
    explicit '--mount-symlinks' parameter. (CVE-2025-3047)

  - After completing a build with AWS SAM CLI which include symlinks, the content of those symlinks are copied to the 
    cache of the local workspace as regular files or directories. As a result, a user who does not have access to those
    symlinks outside of the Docker container would now have access via the local workspace. This issue affects AWS SAM CLI 
    <= v1.133.0 and has been resolved in v1.134.0. After upgrading, users must re-build their applications using the sam 
    build --use-container to update the symlinks. (CVE-2025-3048)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://aws.amazon.com/security/security-bulletins/AWS-2025-008/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Devolutions Remote Desktop Manager version 1.133.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-3047");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:aws:sam_cli");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("aws_sam_cli_win_detect.nbin");
  script_require_keys("installed_sw/AWS SAM CLI");

  exit(0);
}

include('vdf.inc');

# @tvdl-content
var vuln_data = {
  'metadata': {'spec_version': '1.0'},
  'checks': [
    {
      'check_algorithm': 'default',
      'product': {'name': 'AWS SAM CLI', 'type': 'app'},
      'constraints': [
        {
          'fixed_version' : '1.133.0'
        }
      ] 
    }
  ]
};

var result = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result:result);
