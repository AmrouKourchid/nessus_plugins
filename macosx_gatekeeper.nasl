#TRUSTED 3a8b3b9a0b54f6d1875105fe1aaca9e21b7cd4d2fd7dd6e017b3d75f597cc57705f25ebd45ea0a3b302ad6c5fe5dcbcbbe82280ebea4b62b023cc6cf9f5fbc19356c1ab264742e2d348870e62bb2db72164c818763671352d9a74d78fa58df313c267a0688d11fbf210a717dfc8c2f152f3419343825541c3e12a147facf15829dc17b138953d471e35b9992ebb6634e3a6f8de53d3580f18dc3776eb80c53562cfa0f6518304d97e2db07853217c1b9e65ba4feb6b01dc3e3e70c2dff882fb1e34455b415272014ac88044648e1c409aca78f808cf69f0f70839ab73d3df7a090cdd30ac10ce06bed531d099c2bb174e5b3f16d0497a7e09076c9f3fbb8f6a3121015785ad5fef619e9dc81aa57e8f2edca2e54048952410e06a52257a498894580c7ddd7fb6cb15af22a7373fbc5d87e2029097d7c8eac2263b0d7ba31d4ce61c23346e4b7bb844a0b64ef01e2b451332eba6f7589d8a8411c46da4e2b6892ca241e966b058eb3b942e93199a2c80a336602d5dddfc6a5511ff19a4ed4d8b759a4f5a24dd27d7b48c26dde6d4d304cc00cf73f30f915d88c2aa415311cc16bd9968ae271fb2de7479c7f8eee6715657dbd9d3c9cdd94d9a00ff3d1f380ca78d18e5fb47c9a0f17e57e08050b693fb3f89ef05e7973769f6a22e41ca8adfbc9beb0407b317a714bb6dc45b7ae8fc7278f3873b1a9510089037797ebe668ad8c
#TRUST-RSA-SHA256 8800aa36ba582a195e3481c2f276cba0a3cf7ae59197c76d3a974578fe446e33ecd1dad9c85d63f83d18e245323cd0fe6fa2ec9633149356495e609a0410fb932043e7bcbd530f71dbd8c0c223c7554f8e0069c4c393b98ecfff20d99f71a0ba1b74f51038f02794a148b12086b93de1a631df3c421c122225bc7ebfdea39c69c6c56641a1ed7294940f707ac2e32162bf1fefd0516d88902bd30a11f259f24300e82039042ca8367854aa983a802e34bad442303c39f68e11581ac1e212e1886a79c0e9b9a72c344403c6d7b47f98a2b0425b4beee0a2716ec4a9e651f53e7ff97a2f5387c8fae16701fa6cd970eb57b2889df80c7259fff3310668cbbd5db5f9c9e9b6196232a9a7acb52144528c2bdaa5e587ce738df39bfb37d91139ee9b761ff9284e62b06d36e992961cf09ea1ef4b5c155581c77ebbb46bc39b000a721f0b025dddc85e660170ac0df72c2a06356bf7e74285291e809da7e114ff9de94fc34d3f57ae07b8ccd2008016da21b2e6a122f119e38f59407b9cc8af0e78e8e598aa639e8a9a050c10b349685dec0204ef466df422de190cbd77186ab4b4f05a5b96d38dcdd6b5bee2a7c06ad3bded6e6507a2991296ad3ee3ac039b9477179062d377dac9ec950a0ad1cd9b83addfb9f9a9d29743b377ec2f977437b3cb6b2dc3f569eb4f279caea9109451de0f5b37efc313591b74718eb055fa3460b6e7
#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(89924);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Mac OS X Gatekeeper Disabled");
  script_summary(english:"Checks that Gatekeeper is enabled.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host has Gatekeeper disabled.");
  script_set_attribute(attribute:"description", value:
"Mac OS X Gatekeeper, a protection service that guards against
untrusted software, is disabled on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-ca/HT202491");
  script_set_attribute(attribute:"solution", value:
"Ensure that this use of Gatekeeper is in accordance with your security
policy.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os)
  audit(AUDIT_OS_NOT, "Mac OS X");

extract = eregmatch(pattern:"^Mac OS X ([\d.]+)$", string:os);
if (!isnull(extract))
  version = extract[1];
else
  exit(1, "Error extracting Mac OS X version.");

# Gatekeeper arrived in OS X 10.7.5
 # audit-trail:success: The remote host's OS is Mac OS X 10.7.5, which is required for Gatekeeper, not Mac OS X 10.7.4.
if (ver_compare(ver:version, fix:"10.7.5", strict:FALSE) < 0)
  audit(AUDIT_OS_NOT, "Mac OS X 10.7.5, which is required for Gatekeeper", os);

cmd = 'spctl --status';

res = exec_cmd(cmd:cmd);

if ( "assessments enabled" >!< res && "assessments disabled" >!< res)
  exit(1, "Unexpected output from '" + cmd + "'.");

if ( "assessments enabled" >< res )
{
  set_kb_item(name:"Host/MacOS/Gatekeeper/enabled", value:TRUE);
  exit(0, "Gatekeeper is enabled.");
}
else
{
  report = '\n  Mac OS X Gatekeeper is disabled. Ensure this is in accordance' +
           '\n  with your security policy.' +
           '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
  exit(0);
}
