#TRUSTED 0f4355769c451b67d43914c4273b7ade2e55c16800ba4086a148fd39a4c486f38d6c8b52230448c3032210d57c0be43eb90e54658348473c6203b773c78d103ad6ba28b46dd3439ed8ea55b6561cb973deed9de87ad21f972633927cfb74aa0e9368be6c9634c5c5b25bae79ecce550161364d33a0a4a3719a3d3f5ec2d78b69804c11fde535392124f58386d444a98ae365ee8c56248395a6c4656763ba341edb0ff77518b2fc6024f5cf84c76ea6142f54a815af3501e2c27c40fdaea0893971b831d1e0d816a00ac26e7d4f3642b9159ad98893375b4ff7b2bdc25016f6a228c538a3136a261dc78ffd67b026430716af1d6c364dc7db5145c2b17453616e0835f99bfdf744e7f1e9b06262bdeb776772119d3f90a75adbcbf5271601228ac77124a4402d3bc7c41219adab4247ad356fc7ea83f56c149ba2a36dab88b8b6e54bdd39c2e88347a0112aff2e7b7eeae7b6c70ff3c865f4467633bbf2d100da4c270e246a151581b7d3a9d6c955602d743c649b7d064da852bb279dbf7858ad5775379f9ac3e451a4baea393d5cdc2d92f6722a4a35ac659f1bfc5d409c675aae70b0e9490125d32d0835a5bc28d3587cc24813219ce8a68f05cf3a12ee2a2237a9d4c0f69140ab491370fcbf688b1a607f911856179f3326cc1d7f9103a44ec97a496435d25b8ce8bf413741739ceba2a0fe91acaff98e2ee206d709f40c6c
#TRUST-RSA-SHA256 576765a25563288794d4d536de88f139b63ae3465261fa2933e505d61208ee1f2d738d85d18fb6d216109efbc273d0fed7307858f9d8c80758fb338d95e9d6a486f18d9b5833499a33401ff72cc0d5394f9ad271780729e9a213008dbc266f5a7d801853fcab35355f5f8552677aac43abf16547c9883f73349510bafa03a03919dddbb36740b53d0aaf073d9389a9002e26b9b4143979351150914b03041f8a7e30470fc071796692e2f5b1520ef0d4c987afe083689ff881fb52cc1a5fae1dc80c77c154d159b4fe369876303d48fb1e09352c555fcc1fcb747172c586742c3463b7da3e4a146a8c3149b91b4ad663ebc8efea671ffc747abba043b6852ee1f7c6190a7bca13722f26ed160f30626bd54c6fdf9a750285b99e8db4261f81ea3cac52b8200aab5a128f131a7b0f0364516e5294748e70384c15bbb97da1a3352b0090d9993e45789fa1091991dea294fdc2fc4eea79404655b3648a463ffe14a59f41ac0664eaeac401d0ba64666a8cc546cf37df27c60e179cae46b70342828a49781f0a208f8d45a0efa6739257a35dda79beeb1f5a905baf3095d291408b4d97c6cf6c0151e61adeff1f305cece3f3a2cc0ff559520db267f7a9b32b1c28528efe764d51a061cb525cee3023cafb20fba862bbe9eb7ca7a1cf43a6ebe83e991e83f344aaf8dcbed98834c44bbdf397b7bee93a449ec55431915ef2fa8424
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159063);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/03");

  script_cve_id("CVE-2022-22156");
  script_xref(name:"JSA", value:"JSA11264");
  script_xref(name:"IAVA", value:"2022-A-0028");

  script_name(english:"Juniper Junos OS Improper Certificate Validation (JSA11264)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA11264
advisory. An Improper Certificate Validation weakness in the Juniper Networks Junos OS allows an attacker to perform
Person-in-the-Middle (PitM) attacks when a system script is fetched from a remote source at a specified HTTPS URL, which
may compromise the integrity and confidentiality of the device.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11264");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11264");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22156");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0', 'fixed_ver':'18.4R2-S9'},
  {'min_ver':'18.4R3', 'fixed_ver':'18.4R3-S9'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R2-S3'},
  {'min_ver':'19.1R3', 'fixed_ver':'19.1R3-S7'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S7'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S3'},
  {'min_ver':'19.3', 'fixed_ver':'19.3R3-S4'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S7'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R2-S2', 'fixed_display':'20.1R2-S2, 20.1R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R2-S1', 'fixed_display':'20.3R2-S1, 20.3R3'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R2'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R1-S1', 'fixed_display':'21.1R1-S1, 21.1R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set event-options event-script file .* source .* refresh", multiline:TRUE) &&
      !preg(string:buf, pattern:"^set system scripts (commit|event|extension-service|op|snmp) file .* refresh-from", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
