#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209672);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/28");

  script_cve_id("CVE-2023-24509");

  script_name(english:"Arista Networks EOS Improper Privilege Management (SA0082)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by a privilege management vulnerability.");
  script_set_attribute(attribute:"description", value:
"On affected modular platforms running Arista EOS equipped with both redundant supervisor modules and having the 
redundancy protocol configured with RPR or SSO, an existing unprivileged user can login to the standby supervisor 
as a root user, leading to a privilege escalation. Valid user credentials are required in order to exploit this 
vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisory/16985-security-advisory-0082
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4a53bd5");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to a fixed version as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24509");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version", "Host/Arista-EOS/model", "Settings/ParanoidReport");

  exit(0);
}

include('arista_eos_func.inc');
include('audit.inc');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var version = get_kb_item_or_exit('Host/Arista-EOS/Version');
var model = toupper(get_kb_item_or_exit('Host/Arista-EOS/model'));

if (model !~ ".*73(04|24|08|28|16).*" &&
    model !~ ".*75(0|1|5|8).*" &&
    model !~ ".*78(04|08|12|16)R3.*")
    audit(AUDIT_HOST_NOT, 'an affected model');

var ext='SecurityAdvisory82_CVE-2023-24509_Hotfix.swix';
var sha='7833ab99e11cfea1ec28c09aedffd062cfc865a20a843ee6184caff1081e748c8a02590644d0c7b0e377027379cbaadc8b1a70d1c37097bf98c1bedb429dca56';

if(eos_extension_installed(ext:ext, sha:sha))
  audit(AUDIT_HOST_NOT, 'affected as a relevant hotfix has been installed');

var vmatrix = make_array();
vmatrix['M']   =  make_list('4.28.0<=4.28.3',
                            '4.27.0<=4.27.6',
                            '4.26.0<=4.26.8',
                            '4.25.0<=4.25.9',
                            '4.24.0<=4.24.10',
                            '4.23.0<=4.23.13');
vmatrix['fix'] = '4.24.11M / 4.25.10M / 4.26.9M / 4.27.7M / 4.28.4M';

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:eos_report_get());
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);
