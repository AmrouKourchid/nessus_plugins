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
  script_id(205459);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id(
    "CVE-2023-50782",
    "CVE-2024-26130",
    "CVE-2024-37890",
    "CVE-2024-38195"
  );
  script_xref(name:"IAVA", value:"2024-A-0487");

  script_name(english:"Security Updates for Azure CycleCloud (August 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Azure CycleCloud product is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Azure CycleCloud product is missing security updates. It is, therefore, affected by the following vulnerabilities:

  - A remote code execution vulnerability exists due to a disclosure of the storage credentials. An
    authenticated, remote attacker can exploit this to bypass authentication and execute arbitrary commands
    with root privileges. (CVE-2024-38195)

  - A flaw was found in the python-cryptography package. This issue may allow a remote attacker to decrypt
    captured messages in TLS servers that use RSA key exchanges, which may lead to exposure of confidential or
    sensitive data. (CVE-2023-50782)

  - A denial of service (DoS) vulnerability exists in python-cryptography due to the
    pkcs12.serialize_key_and_certificates function. An unauthenticated, remote attacker can exploit this
    issue, via specially crafted certificate, to cause the process to stop responding. (CVE-2024-26130)

  - A denial of service (DoS) vulnerability exists in ws, an open source WebSocket client and server for
    Node.js, due to the handling of headers. An unauthenticated, remote attacker can exploit this issue, via
    specially crafted request, to cause the application to stop responding. (CVE-2024-37890)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38195");
  # https://learn.microsoft.com/en-us/azure/cyclecloud/release-notes/8-6-3?view=cyclecloud-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da517d63");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released CycleCloud version 8.6.3 to address this issue");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50782");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-38195");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:azure_cyclecloud");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("azure_cyclecloud_web_detect.nbin", "microsoft_azure_cyclecloud_web_detect.nbin");
  script_require_keys("installed_sw/Microsoft Azure CycleCloud");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'Microsoft Azure CycleCloud', webapp:TRUE, port:port);

var constraints = [
  {'min_version': '8.0.0', 'fixed_version': '8.6.3'}
];

vcf::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
