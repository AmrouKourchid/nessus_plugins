#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189898);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/18");

  script_cve_id("CVE-2023-24510");

  script_name(english:"Arista Networks EOS DoS (SA0087)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"On affected platforms running Arista EOS, a malformed DHCP packet might cause the DHCP relay agent to restart.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisory/17445-security-advisory-0087
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6af30cf8");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to a fixed version as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24510");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/01");

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

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var version = get_kb_item_or_exit('Host/Arista-EOS/Version');
var model = toupper(get_kb_item_or_exit('Host/Arista-EOS/model'));

if (model !~ ".*70(1|2|5|6)0.*" &&
    model !~ ".*71(3|5|6|7)0.*" &&
    model !~ ".*72(0|2|50|60|80).*" &&
    model !~ ".*73(00|20|58|68|88).*" &&
    model !~ ".*7(5|80)0.*")
    audit(AUDIT_HOST_NOT, 'an affected model');

var ext='SecurityAdvisory87_Hotfix.swix';
var sha='fc9051ad9a83c7b507d843bebc4964259f68ae0a7dfb4783680d44b8eda078a5f3a7041e584bc4508480197fb4f8d27da39f87c45e6f98f0d839a5240a48f71f';

if(eos_extension_installed(ext:ext, sha:sha))
  audit(AUDIT_HOST_NOT, 'affected as a relevant hotfix has been installed');

var vmatrix = make_array();
vmatrix['F']   =  make_list('4.29.0<=4.29.1');
vmatrix['M']   =  make_list('4.28.0<=4.28.6.1',
                            '4.27.0<=4.27.9',
                            '4.26.0<=4.26.9',
                            '4.25.0<=4.25.10',
                            '4.24.0<=4.24.11');
vmatrix['fix'] = '4.26.10M / 4.27.10M / 4.28.7M / 4.29.2F';

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:eos_report_get());
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);