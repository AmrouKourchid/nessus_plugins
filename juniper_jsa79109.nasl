#TRUSTED 3f25978b092c7a2b9ee91ba9013acab48ab069f5fb3c02108ddf3cc5a642eef50df4d816ab687f1013a4f98abf0fe94b8db3885196fe3ee51e8cdeda44f6d0321e53a0c263738cb6f21d94bcc053ca240f1bc8d31760a728a5bb90baf8d81a13e5d7f1e402e1c38026316a3614d7548792044d02f8b9cd0f2c2a120411e523b0b06a38769e59de462f9a378b76dd0a040191f63cb6d4f4c8884046d47340f328b61a371e2ef1653119ce110e31bfbefd62ba95987524381482cb9b71a24ecf9c4ab306a8e35ad3539a997629ec5ce3971389b770fc8255d3ed278547be0cf70795a06839ae7febb87bb159cea3a13148a8a3503a1e911cef04ed04484b7ea1a6b76af269ee94c1439a5a9c7897e34d4b705cca09cba5c5c16fe9fe59b8ec884238495339bb241b44db71a1da5fe1e53c53efa5d826293afd854f799b794f0dbd38246b10a9dd8dff8ffd5ec335b7f84dca5db912e33b8e94478e14ce68f5be276ab6b07ab7527f0e3b1ad4a0b3c297f0a7d593091c7fec8a1e6e4f1123a54ddb447754b2a14f9f3572603f17b8b4b6d05bf94da939353aea8e3da668f8537020a24beb441ea5d1fb90bb81af084c202670d97db341abea4def1d5571d669fda7ed5a1b5b05423d1d5174e90646741140687244f6e1910902c5237a065340ad4c9bfc12e65a2149808253ce4b2f315e055664dc8beddf8026cb289dfabac716ed
#TRUST-RSA-SHA256 03ea33ef6539e76e4a137ea2b53e2e448581527ea71a84615c660deb644e3422c686719c9f6ab6da9b9ff7693e8a8e6110a45b3a7c53a51d7e964f56c046c69d924176a3294050f7e6a1cec732cc52558e480fd51ab4853a170e2ea1de731e7aa2fed8f0bf5da6374643eec3a1b201106d50dd7437ebfccfc1d3f571090ac32d1eeeef21a5468cd89536d82b3fde1c074b471b2413f5e0a6ddc87b85479971527d94a04e3d820cae35797b1b7d49d68083323e0591c7a829d4905aad72cda54a9c086d002dbf4effd01d7bd29e97a38df25417c0c033ea730df4f1fd8bb1ce5ee144736768ab0624d8912ee02b70daa97dff05dd4d58a49bd698e0fb4005f33c1bbc07f1e6ffa185d4740803ee0a1c0bf2c1a69bee9ceb9512df357d940105c78e216a6b1b2fdc0147a7050171e00aacf2b968b69d33fd525be57c645bc2f8e5f65d6f4e1306fa8a8956ad14f8778fbf0f0d31089fe493df6686f7a45327288e765fdc78bcc8c715f1becb629d665cca909f50607c025da0521918491c67873c391a15355d4510b568b15bd9a65177107aa798719a78f24f73c356e3c4884d4740d9d2e3b1b0ab1c7cfaef4b6409c207327157842ddd58356890dea982c28dc68a03e5b3f2ecf461fa2de7e22c515fc92963989c554a7530535222b93956f0518adad8fd582701f51c3aa54d3e43104dd53dac748daaa2913d98351af2992611
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195218);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/09");

  script_cve_id("CVE-2024-30378");
  script_xref(name:"JSA", value:"JSA79109");
  script_xref(name:"IAVA", value:"2024-A-0232");

  script_name(english:"Juniper Junos OS Vulnerability (JSA79109)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA79109
advisory.

  - A Use After Free vulnerability in command processing of Juniper Networks Junos OS on MX Series allows a
    local, authenticated attacker to cause the broadband edge service manager daemon (bbe-smgd) to crash upon
    execution of specific CLI commands, creating a Denial of Service (DoS) condition. The process crashes and
    restarts automatically. (CVE-2024-30378)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://supportportal.juniper.net/JSA79109");
  # https://supportportal.juniper.net/s/article/2024-04-Security-Bulletin-Junos-OS-MX-Series-bbe-smgd-process-crash-upon-execution-of-specific-CLI-commands-CVE-2024-30378
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b66d99dc");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA79109");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30378");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^MX")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S5', 'model':'^MX'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S4', 'model':'^MX'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S3', 'model':'^MX'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5', 'model':'^MX'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S5', 'model':'^MX'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3', 'model':'^MX'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3', 'model':'^MX'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2', 'model':'^MX'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set system services subscriber-management enable", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because the Subscriber Management feature is not enabled');
  if (!preg(string:buf, pattern:"^set chassis redundancy graceful-switchover", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because the Graceful Routing Engine Switchover (GRES) feature is not enabled');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) 
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);

