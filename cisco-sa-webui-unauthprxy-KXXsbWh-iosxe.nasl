#TRUSTED 053f3b6e64729c20478377d9bd5e36d761e012da5b77bdae414d8d41fe033ec318101bc1f114628f97cca652d784eca1c8a6e72bcee255730793c8f089410b2f1a04fc95a5a88e73eb38d97b6267ab8020c2d6e9ce7d42b9f1c4f87c3c7a663ee6a6b21d116cdefb35532825e5ca0b2dd03eee24bd255ff6c1ddcfa8392db19eedbe7a0923357d91295f3283c089260364b64039f343adaa6b8cfe4e7af11340fb4db80c6db4ea11ac635c099ca1cd511c2fa852bc558ead431de3f8b360f3c372df3054d1ff43cccec8e3d5d389d98d1e290d845a7834a926a485222dc6f898cf55f58c03fd65c3359711597c0889cd591310c95569c763320c6305015f38162dd2fb6fef16067596eec4a17bc1f04a572f0d39c4e5d656bb41b93fe97f600840ee2c52ee036adbfef321c45d8234707720843ddb84fc2c2f39515b38063f6af568a726800168ad2b20771917e24409299d25dc7666c86976da69ea2b4f72b67ead118cc2be05f8f9fa4695365a95aff569bd7aa9206bdadf6376a6f2c20556c310965f9db980f1b966b46da52e80f92a12e492d7097aa31810bb5984fb38c25233f66fe1af5923d4fd5fe255e54cf49308005d592f8d588a3cddd24e82aafc7520fa91e88734f4b8cbd4fa3e0c585d7878dfd1bafac5231ddca8640cdfc86dc188ffd9202c5406cf47e29ea691d10b23b3ee097526db7c03d383fee4824eb0
#TRUST-RSA-SHA256 2a1e51901b4a9e7954050c398fb743b0e0c718daa77f171fe6f0ef65dae563ec09266b080b1ed92c833f5dd881e29577a3ed2d90a3511ec3f1ef03f665ee70e5ad52dc62f6e127b9ff80f9e526d6992f3be98de16a37580a206bb3d0df41b3023508577ebe6c8886ae261aa93b9128cec9932ee4705d65cdc0fb999f307d7b52538ac6a13105dfe0c69c72c3bb90c1c88456dd817dff139b380570807bc5ec74f8c14877df71ccf0e9415a3d846673d2a5df944b8f2281a35012fda5914e1fc5ab9ac406a2a293eb03c8ea9811a3d893eacf0f9d9be7373f22aa1bafd57d3ebfa3032987c8779c7a863e00170468f171552bc64cef5c36b4418bc18b41e10ee7983e32642eadc1fb06086700d0a04836c868b3b6d66893b5be0d7a7f3b59fc69c326e782c595a0a1cefb1ab85f3a6be23f487188c265ee58a2d7e5b70d9e4a4b0d6aefeb45b8ca5cacce88dac98822124eb565e9b8a03ae4373fd73fed590a971cb4e27ab1eece739521e8cccc74ce330e3d8640cbaca67e35eaf62e30fe7a4fd3c4ce3f43b63863b71b23cc5599b5069c0da7d80b0cf546b080b1c33293cbdfc4df9df0b417b0b1bc9a322d9f79261602dc46ac75da2f28c292317151bdd1780fd2a5ca8232642f8a0c754e32fa9051226ab563e398c448848f3455f080cc24d33fdc16bd236f581583cdc18b05fc6ecd1dd6d6b9c97869160bcc47664813e0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139327);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2020-3222");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq90862");
  script_xref(name:"CISCO-SA", value:"cisco-sa-webui-unauthprxy-KXXsbWh");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Web UI Unauthenticated Proxy Service (cisco-sa-webui-unauthprxy-KXXsbWh)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a UI unauthenticated proxy service
vulnerability. The vulnerability is due to the presence of a proxy service at a specific endpoint of the web UI.
An attacker could exploit this vulnerability by connecting to the proxy service. An exploit could allow the attacker
to bypass access restrictions on the network by proxying their access request through the management network of the
affected device. As the proxy is reached over the management virtual routing and forwarding (VRF), this could reduce
the effectiveness of the bypass.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-unauthprxy-KXXsbWh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3014ccae");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq90862");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvq90862");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(17);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '16.12.1y',
  '16.12.1w',
  '16.12.1t',
  '16.12.1s',
  '16.12.1c',
  '16.12.1a',
  '16.12.1',
  '16.11.1s',
  '16.11.1c',
  '16.11.1b',
  '16.11.1a',
  '16.11.1',
  '16.10.2',
  '16.10.1s',
  '16.10.1g',
  '16.10.1f',
  '16.10.1e',
  '16.10.1d',
  '16.10.1c',
  '16.10.1b',
  '16.10.1a',
  '16.10.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['HTTP_Server_iosxe']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvq90862',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);