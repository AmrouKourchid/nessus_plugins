#TRUSTED 82562f997a8035eb976dd8de86c91aa1c3bc53b907907297fe23fc7f469619986b1aee586ca1c9e7d7ef4544e578b267e88c31dc2ef4194957e6504cfabf56c133399acd586745c32bdf9d1a61dc096cfbb8f407863584dcd262b57c907b53dffd7196bab2e348bf6d561ffb8bae71eb605296be734be5233faf0923e79b989295147c03dbca9d2d44ee3f7083d0828ba5498b8754f58f5f0c3a521f20b7765d4212ab2db7b5893312835706d28a5f5bd20e43947bd6c64295a3ba7cb9216cfb2445d4e351d16b87f5b2d49ee4d3f187e40cfef25911f51115f79ddfd9ce82a1ad543da3b4449a147189f0a22add812e95bf407d1a9aa02248912e5eb3d9ee054cc01d57ef71503dcbb1fd25998adf1bd070f7e9d8a56dbc5591fb5c5c34be28cc009a2954884f9a9ced128ea4d6154beb7bb5fe8ca37ea1611d829ccd3c42c425dbc4c13b5c0eb28a244ff188e79ddbbe7f1e3b7f9e22a08b54bc0d5fdb8aa4e6b767acea5b4835075f9ad8204fde3b08c6405eaa6e5914bf56a59ceb84a7e6920d40a00133ff7260803d2d479688993addcb41001eab1c43b43f3e8ad9d1ad5fc56b3b50034a380f6003ee1eac0e71405f7670c8d027cd6650e9ab749652fe5a897e32520270fd42e99a779b9ea76a2a75a1b78077ea1d488f6245b95b37da9c73aa56665f3be38de7eff1c0d358c8614b8342bbde59a2aecf92d8294fef1e
#TRUST-RSA-SHA256 7258315efb76e627def2f3907f27bd1c0fd9b16b665d5daa2e6b4acf86171cfaec6b61985a4b8fa28f95478c48c68003693451b93fff2f5ba09a27723fafea0b9e7a4bfb763e989232ff44d21957d1ed0a18ec624678ed73ae83e1a46392bca3c3730bdbbdb56c9eb571613fff6955813a1fda62819b6f6f22fc88ac7928aa8fc8853d762d510149e31614919e244ed154968659f5c5d58905f8c980c3944c469769ef7ab00ad4ef792cf66fea71c86b328074bf14bce8bbf95dba8636b00c9fd154426d8a191157c8c4ce5bc8e5c19e7681be766825785287e76f9b90719fef656b930d4ac86b200618600697f94629412ee9a9493a9eaf1cf56be773a3fc1a426717498f1f7bf81ee9a8f3d761dfada37b7f7b136457a2091c43fde9c1462af076998e0ef29fd41c6ac147790ffaa94374aa5bdc7d87370ac74b62e200a39a580ff219046c201957e5bad661586cd7fa5f3558ae777cca33d638cfd8d0785befa255954a059518a540a01d0ea0421810239059a75d521605377976835f0f8a2fb9ee4f8a81ae25f5cb9b188eeb0011ea076816ceeed1fcd4739105f4cb799833738b0929cd96c2f9a3828ca7516cec630b0f03ab36180d88698d64778aeda61bf5cfb64cdc249a12f1e5a602a5aacc103be44ff190a9372a260ffe47ce8af6c6e9836322bafbb7f9b17b03bf6c6e0d8e792dcc587cc349c8f134a9c1f21788
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78919);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2014-3409");
  script_bugtraq_id(70715);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq93406");

  script_name(english:"Cisco IOS XE Software Connectivity Fault Management (CFM) DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco device is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is affected by a denial of service
vulnerability due to due to improper parsing of malformed Ethernet
Connectivity Fault Management (CFM) packets. A remote, unauthenticated
attacker, using specially crafted CFM packets, could trigger a denial
of service condition, resulting in a reload of the device.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=36184
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8080ca42");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Notice.

Alternatively, disable Ethernet Connectivity Fault Management (CFM).");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2024 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# Check model
model = get_kb_item("Host/Cisco/IOS-XE/Model");

if (!model)
{
  # If no model, just do ver checks per Alert page
  # 3.1S .0, .1, .2, .3
  if (version =~ "^3\.1\.[0-3]S$") flag++;
  # 3.2S .0, .1, .2
  else if (version =~ "^3\.2\.[0-2]S$") flag++;
  # 3.3S .0, .1, .2
  else if (version =~ "^3\.3\.[0-2]S$") flag++;
  # 3.4S .0, .1, .2, .3, .4, .5, .6
  else if (version =~ "^3\.4\.[0-6]S$") flag++;
  # 3.5S Base, .0, .1, .2
  # 3.6S Base, .0, .1, .2
  # 3.7S Base, .0, .1, .2, .3, .4, .5, .6
  else if (version =~ "^3\.[5-7]S$") flag++;
  else if (version =~ "^3\.[5-7]\.[0-2]S$") flag++;
  else if (version =~ "^3\.7\.[4-6]S$") flag++;
  # 3.9S .0, .1, .2
  else if (version =~ "^3\.9\.[0-2]S$") flag++;
  # 3.10S .0, .0a, .1, .2, .3, .4
  else if (version =~ "^3\.10\.(0a|[0-4])S$") flag++;
  # 3.11S .1, .2
  else if (version =~ "^3\.11\.[0-2]S$") flag++;
  # 3.12S .0
  else if (version == '3.12.0S') flag++;
  # 3.13S .0
  else if (version == '3.13.0S') flag++;
}
else
{
  # If model is present, do ver check per model per Bug page note
  if ('ASR901' >< model && version =~ "^3\.3\.") flag++;
  else if ('ASR903' >< model && version =~ "^3\.5\.") flag++;
  else if ('ASR920' >< model && version =~ "^3\.13\.") flag++;
  else if (('ASR1k' >< model || model =~ '^ASR 10[0-9][0-9]($|[^0-9])') && version =~ "^3\.2\.") flag++;
}

if (get_kb_item("Host/local_checks_enabled") && flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"ethernet cfm", string:buf)) flag = 1;
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCuq93406' +
      '\n  Installed release : ' + version +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
