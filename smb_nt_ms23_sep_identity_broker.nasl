#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(183959);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2023-36736");

  script_name(english:"Microsoft Identity Linux Broker RCE Vulnerability (September 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Identity Broker is installed on the remote host is affected by multiple remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Microsoft Identity Broker  app installed on the remote Windows host is prior to 1.6.1. It
is, therefore, affected by a remote code execution vulnerability where an attacker must send the user a malicious 
file and convince them to open it to exploit this unauthorized arbitrary command execution vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36736");
  script_set_attribute(attribute:"solution", value:
"Update to the latest version of Microsoft Identity Linux Broker.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36736");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:identity_linux_broker");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_identity_broker_nix_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/nix/packages");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app = 'Microsoft Identity Broker';

var app_info = vcf::get_app_info(app:app);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [{ 'fixed_version':'1.6.1'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
