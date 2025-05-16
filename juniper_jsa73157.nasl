#TRUSTED 2273e5fb0edb54a8f0ef155294f0fcccc01c3995c152dcce4e0228b15b096221dfba8ff0cfc5ddce33cf813d890da949a136f0c88708f2f49c30da017640295d95ed91616d5429ec0e632c1e004006b3939a28b5f39f9bf3f3738ae40483004d5998350df52f5a97f8b677517207c3b78149d6de88a230532ef300a9f4a223179e0b469d897a02746bd0ae18807f65f3b2fc613e03239422b230daef731df7eb78734e1050d5a57c7f9955ed004d8d6f7eba95e2e486649aad5088f85b82f6eb1574e5f4c61976f1eb1e4e0d701b5feaffa436a946ca4b9138a8567e86d8368dc41b7779f02974ae98428fab355d04d87b1ed66f0f67511a7b7101306779ad169ccef1da8aa7a058f502ed4a632876d94620c9f4f2915eab2101c73e27036dda8e1a10a234041d9b347195b931522d5b09b924bf1ac1eb606c65d8aea9d1facab39a601d29578445ea77431a9269f54b403e1548b29a8125d28b6c549b4e3b5e6b2ba6dc743ad2b5deb1f5831c1f2080207f9ab672784ff23eccce39c989b228d0e754688c9d9d3b2877fc49ee89d26502411c31fe4a4b31753e95db9c90a802fed8ac570c1afef1d848182b4fc35986a70aebd18b1062813e8fc655175e109a0b4178ab6014dfc6f0dd59e80a6729d6634bad710c93e0ddd7e64be05bd8b2657d1a6392dd8d2edf4d32d18f3ec43ab96d62ee62a2dccab4b59a736111fd9405
#TRUST-RSA-SHA256 0d2a3f6431892ebb49079680c066bec6a72e0f670f8ba82294335967b6fdbdf6a9c5970d675dbeb1bb65f555aec5238dd3988dbd431371ff41b7fd22a5761b5d7ed758bfb0c80b3c53924919fd5d154e62b836650782fb4bd3fecc8d3eb9208ab6f833d104a8b4495c50950bb647e2ffd5f1b38334f561e37c05adf582d20a2aee7f3f8ca5963f639ed5eca96ab25906ec39c8d855fb640860cc6176d16fa51f65f60b8066171b57adfd8d2d96337956b50a561ee80de57d14dc196bee1970c5d72edde44f3c323ff43f7d18f762fea3937367b5b6e31f9bf80ff7730a1d1e02ec4d187183d0a29bc28abb6b257f6a8faa15b5a18df4c3db7dc6f0d2fa04ef74e9c41f1643995f22ca24474b0f78e6df81e53cff01c16502e24cb8f91ba08516fd202988fcd8dd326255c6705a60da39d48c72cdd79d05cd34cb1fdd41f96e3877114079dac2ccc9d2b7efa2bad9ab30928d30b234d7bc291b086dc611a8fb4984538f5151cc4577ea7340380d33bb86ffc8ad235d7af51439a47b5f36b069f86cd1d1d8ac55a07fc5e44ab2b912ffc6081f5fbc3f640e9af3b6f05e18f68ac99ae68aa4ae21b90e23da8aa5ebf6800582409542ad474c08024d1b920dca6e369bb8ef41a8555e1178ef84ba8a7170db8f1011a3558b89a2722cbb25926bc83b63213c883058da2b1113b86fd53300cca2797c177730cb5c604a5dc053e70a42
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187316);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/28");

  script_cve_id("CVE-2023-44193");
  script_xref(name:"JSA", value:"JSA73157");
  script_xref(name:"IAVA", value:"2023-A-0565");

  script_name(english:"Juniper Junos OS Vulnerability (JSA73157)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA73157
advisory.

  - An Improper Release of Memory Before Removing Last Reference vulnerability in Packet Forwarding Engine
    (PFE) of Juniper Networks Junos OS allows a local, low privileged attacker to cause an FPC crash, leading
    to Denial of Service (DoS). (CVE-2023-44193)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://supportportal.juniper.net/JSA73157");
  # https://supportportal.juniper.net/s/article/2023-10-Security-Bulletin-Junos-OS-MX-Series-An-FPC-crash-is-observed-when-CFM-is-enabled-in-a-VPLS-scenario-and-a-specific-LDP-related-command-is-run-CVE-2023-44193
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29c88fcc");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA73157");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-44193");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos_kb_cmd_func.inc');
include('debug.inc');

##
# Duplicate of junos_check_config() with changes to return a list of matches
##
function junos_check_config_match(buf, pattern)
{
  var statements, lines, line;
  var deactivate_pat, disable_pat;

  var matches = make_list();

  if (isnull(pattern))
  {
    err_print("junos_check_config_match: 'pattern' must be specified");
    exit(1);
  }

  statements = pgrep(string:buf, pattern:pattern);
  if (statements == '')
    return matches;

  lines = split(statements, sep:'\n', keep:FALSE);
  foreach line (lines)
  {
    # Look for deactivated statement in the config
    deactivate_pat = str_replace(string:line, find:"set", replace:"deactivate", count:1);
    if (preg(string:buf, pattern:deactivate_pat, multiline:TRUE)) continue;

    # Look for disable statement in the matching statements
    if (line =~ " disable$") continue;

    disable_pat = "^" + line +  " disable$";
    if (preg(string:statements, pattern:disable_pat, multiline:TRUE)) continue;

    var match = pregmatch(string:line, pattern:pattern, multiline:TRUE);
    if (!empty_or_null(match) && !empty_or_null(match[1]))
    {
      append_element(var:matches, value:match[1]);
    }
  }

  return matches;
}

var model = get_kb_item_or_exit('Host/Juniper/model');
var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

check_model(model:model, flags:MX_SERIES, exit_on_fail:TRUE);

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'20.4R3-S7'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R3-S5'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S4'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S4'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S3'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S1'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R2-S1', 'fixed_display':'22.2R2-S1, 22.2R3'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R1-S2', 'fixed_display':'22.3R1-S2, 22.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

var override = TRUE;
var buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  override = FALSE;
  var vuln_config = FALSE;

  # Process of config checks
  # 1. Check for md-name vpls to get list of md-names
  # 2. Check md-name and get list of interface1 that are valid
  # 3. Check ldp interface, flexible-vlan-tagging, vlan-vpls for that same interface1
  # 4. Check for md-name matching with interface2 with connectivity-fault-management (interface2 must be different from interface1)

  var md_list = junos_check_config_match(buf:buf, pattern:"^set routing-instances (.+) instance-type vpls");
  if (empty_or_null(md_list))
  {
    dbg::detailed_log(lvl:1, msg:'No VPLS maintenance domains found. Config not vulnerable.');
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
  }

  dbg::detailed_log(lvl:1, msg:'Maintenance Domains Found: ' + obj_rep(md_list));

  # Must check each md-name separately
  foreach var md (md_list)
  {
    dbg::detailed_log(lvl:1, msg:'Processing MD: ' + md);
    # Exit if we find the workaround
    if (junos_check_config(buf:buf, pattern:"^set protocols oam ethernet connectivity-fault-management maintenance-domain " + md + " mip-half-function none"))
    {
      dbg::detailed_log(lvl:1, msg:'Found workaround for MD. Skipping.');
      continue;
    }

    var interface_1_list = junos_check_config_match(buf:buf, pattern:"^set routing-instances " + md + " interface (.+)");
    if (empty_or_null(interface_1_list))
    {
      dbg::detailed_log(lvl:1, msg:'No interfaces associated with MD. Skipping.');
      continue;
    }

    dbg::detailed_log(lvl:1, msg:'Interfaces associated with ' + md + ': ' + obj_rep(interface_1_list));
    
    foreach var interface_1 (interface_1_list)
    {
      dbg::detailed_log(lvl:1, msg:'Processing interface: ' + interface_1);
      # All three settings must be present for interface_1
      if (!junos_check_config(buf:buf, pattern:"^set ldp interface " + interface_1))
      {
        dbg::detailed_log(lvl:1, msg:'Interface "' + interface_1 + '" is not an ldp interface. Skipping.');
        continue;
      }
      if (!junos_check_config(buf:buf, pattern:"^set interfaces " + interface_1 + " flexible-vlan-tagging"))
      {
        dbg::detailed_log(lvl:1, msg:'Interface "' + interface_1 + '" does not have flexible-vlan-tagging. Skipping.');
        continue;
      }
      if (!junos_check_config(buf:buf, pattern:"^set interfaces " + interface_1 + " encapsulation vlan-vpls"))
      {
        dbg::detailed_log(lvl:1, msg:'Interface "' + interface_1 + '" does not have vlan-vpls encapsulation. Skipping.');
        continue;
      }

      var interface_2_list = junos_check_config_match(buf:buf, pattern:"^set protocols oam ethernet connectivity-fault-management maintenance-domain " + md + " interface (.+)");
      if (empty_or_null(interface_2_list))
      {
        dbg::detailed_log(lvl:1, msg:'No interfaces with connectivity-fault-management enabled associated with MD "' + md + '". Skipping.');
        continue;
      }

      dbg::detailed_log(lvl:1, msg:'Interfaces with connectivity-fault-management associated with MD "' + md + '": ' + obj_rep(interface_2_list));
      # Just need one interface not to match and we have a vuln config
      foreach var interface_2 (interface_2_list)
      {
        if (tolower(interface_1) != tolower(interface_2))
          vuln_config = TRUE;
      }
    }
  }

  if (!vuln_config)
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');

  override = FALSE;
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
