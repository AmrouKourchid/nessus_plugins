#TRUSTED 0cab78619db72c866073e5a81ed43aa4a7032fad4ed1b2ccebcfcd235470d59b5659302eef1fed6ad733c0c6c2de1d38750ad5f0f018d1b7cd7d303e9762ffefa9e5b02004f9a021deaf9a3dae04032d7b1047faaf984d209d3d23af11abb7f252507d3e36ac03e7712c05d2dd6981e4fceeb824b366b11bb66fa3afe2a3aaffd000609f56fe965f6645fa9c3b9a66014239ec651ff6dc617e4b605e65c0dc8bf454d44bf4353217391b3fe92d6f837286a8e21095f5ebd56f09ff6f1b4821764d3dca8af9f8746ec96203de72e2903e018b7bf6ed7915f7c1dbf103a63d0bbca3bbfb410a4735936b51aab3017a18ce5a09bfac61d70ebdae510d7f4e9092c448fbf507f23730900073892d58061556b2ea93479a652022b4413714fb7370d518df56e310555894b4a0f80c9c1f1120e758329807db83cd09ad3406a31ed8a4d416d91e49867dda98aebc7969a4f7c624628b2a47d9c8e1b673cef466b0042876c1cfa9bf190b189973731fcc7bb9f91966df2a1ab014f6afd7d2e5bf4de62df671c2029e2b88d882b2ab5966e81e45a4f6e1b56b380e48df99f130fca845e09b025b90cbd65fee945acf92c07b1a73500ae0c2540220f98aac8c5ce2eb742de38c15bf426553124d2a58ebf18554f5abbf424ad90268f7c2857110f9588d5af0c0f96694935ed89542e1c36192da3d68013c73517a0b8e612ad37b2a1b7362
#TRUST-RSA-SHA256 9aeb560a163a4488c0274f5098a4e5fe206c162c9fec808f31fb7542002c293b60d809b8cf153ef547ff999f0c1808d21427730866cd24445e56eb5fb1165d008bb25db31343e5c69cf3166e1b39458618b5153329293d7ab9de185b9e90c6c99e5d5db8fb303c3392d5796abcc5fe4b94a02b2a9211e7448de28656993994a9587e18d9a32127ccf80b9c805374a124d8a50e2951d26ed8c40ee59ce10fb8eb82fc08a04dc118cde0a5e0690ded6d082df99be41e1c08fbf6dc332857416ab2c3710dbbe41a96aeaeb0631be1069141d886ebe2c760c0b1ddef94c24474c8b477348c628248bedd19656e71f4f2fd891220141c350a7ec20185a8b57ed2fe3a533de50daa50ab5034597a9b12c7a452738338df27bad748f3f82e139f6d3fd799ff0b2528e8d3a4dac13f359181ae683d220d9c6aa5ddf5f93d3694974292b83d8852dbbc0d8fe75e97af605474721cb56bbd686d5c62210d791ae103e1c4e8b755734d8131892a99e8adb28e5ca6d1dc221860a9efbc106c1b7ffc79c94b6c992181cfd6078d6b5ddc48323c37602d47b211182655928f56fcff768c9013932294f54302e0a01a2e75010efdf27390a6c3b2ac876574ca685e58d3dff132dfe1e50a857d29623dd143c67de65f7c5db8463b46cdd9a6377ba6bbfcddcadebff8fad1e3e67ddf82449931957217818f3f5720f22a775e5cfd25a17d473627ef
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211693);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id("CVE-2024-47505", "CVE-2024-47508", "CVE-2024-47509");
  script_xref(name:"IAVA", value:"2024-A-0650");
  script_xref(name:"JSA", value:"JSA88136");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA88136)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA88136 advisory.

  - An Allocation of Resources Without Limits or Throttling vulnerability in the PFE management daemon (evo-
    pfemand) of Juniper Networks Junos OS Evolved allows an authenticated, network-based attacker to cause an
    FPC crash leading to a Denial of Service (DoS).When specific SNMP GET operations or specific low-
    priviledged CLI commands are executed, a GUID resource leak will occur, eventually leading to exhaustion
    and resulting in FPCs to hang. Affected FPCs need to be manually restarted to recover. GUID exhaustion
    will trigger a syslog message like one of the following: evo-pfemand[<pid>]: get_next_guid: Ran out of
    Guid Space ... evo-aftmand-zx[<pid>]: get_next_guid: Ran out of Guid Space ... The leak can be monitored
    by running the following command and taking note of the values in the rightmost column labeled Guids:
    user@host> show platform application-info allocations app evo-pfemand/evo-pfemand In case one or more of
    these values are constantly increasing the leak is happening. This issue affects Junos OS Evolved: * All
    versions before 21.4R3-S7-EVO, * 22.1 versions before 22.1R3-S6-EVO, * 22.2 versions before 22.2R3-EVO, *
    22.3 versions before 22.3R3-EVO, * 22.4 versions before 22.4R2-EVO. Please note that this issue is similar
    to, but different from CVE-2024-47508 and CVE-2024-47509. (CVE-2024-47505)

  - An Allocation of Resources Without Limits or Throttling vulnerability in the PFE management daemon (evo-
    pfemand) of Juniper Networks Junos OS Evolved allows an authenticated, network-based attacker to cause an
    FPC crash leading to a Denial of Service (DoS).When specific SNMP GET operations or specific low-
    priviledged CLI commands are executed, a GUID resource leak will occur, eventually leading to exhaustion
    and resulting in FPCs to hang. Affected FPCs need to be manually restarted to recover. GUID exhaustion
    will trigger a syslog message like one of the following: evo-pfemand[<pid>]: get_next_guid: Ran out of
    Guid Space ... evo-aftmand-zx[<pid>]: get_next_guid: Ran out of Guid Space ... The leak can be monitored
    by running the following command and taking note of the values in the rightmost column labeled Guids:
    user@host> show platform application-info allocations app evo-pfemand/evo-pfemand In case one or more of
    these values are constantly increasing the leak is happening. This issue affects Junos OS Evolved: * All
    versions before 21.2R3-S8-EVO, * 21.3 versions before 21.3R3-EVO; * 21.4 versions before 22.1R2-EVO, *
    22.1 versions before 22.1R1-S1-EVO, 22.1R2-EVO. Please note that this issue is similar to, but different
    from CVE-2024-47505 and CVE-2024-47509. (CVE-2024-47508)

  - An Allocation of Resources Without Limits or Throttling vulnerability in the PFE management daemon (evo-
    pfemand) of Juniper Networks Junos OS Evolved allows an authenticated, network-based attacker to cause an
    FPC crash leading to a Denial of Service (DoS).When specific SNMP GET operations or specific low-
    priviledged CLI commands are executed, a GUID resource leak will occur, eventually leading to exhaustion
    and resulting in FPCs to hang. Affected FPCs need to be manually restarted to recover. GUID exhaustion
    will trigger a syslog message like one of the following: evo-pfemand[<pid>]: get_next_guid: Ran out of
    Guid Space ... evo-aftmand-zx[<pid>]: get_next_guid: Ran out of Guid Space ... The leak can be monitored
    by running the following command and taking note of the values in the rightmost column labeled Guids:
    user@host> show platform application-info allocations app evo-pfemand/evo-pfemand In case one or more of
    these values are constantly increasing the leak is happening. This issue affects Junos OS Evolved: * All
    versions before 21.4R2-EVO, * 22.1 versions before 22.1R2-EVO. Please note that this issue is similar to,
    but different from CVE-2024-47505 and CVE-2024-47508. (CVE-2024-47509)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-10-Security-Bulletin-Junos-OS-Evolved-Specific-low-privileged-CLI-commands-and-SNMP-GET-requests-can-trigger-a-resource-leak
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96c9571c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA88136");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/AU:Y/RE:M");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47509");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0-EVO', 'fixed_ver':'21.4R3-S7-EVO'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R3-EVO'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R3-EVO'},
  {'min_ver':'22.4-EVO', 'fixed_ver':'22.4R2-EVO'}
];

var override = FALSE;

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
