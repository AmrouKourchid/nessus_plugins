#TRUSTED 1d3efc208e4871f15cc0b999209e7cd9dcc80e788d8ebffa3d15e0ceab528f1c4cb5a5187a127d4ca7288b58f1091e737ab7e5951e079afa96d7489a39b9c09c3e23c9a124a14c9e26211e55883c5be7431b2f7183708517578e7db7fd8c760ea19d79881513fccc2dbca52f8d1dc15cdb0ac5043b3aff4e8e21ba592e321e6599d49a3486b83fa01b0da5fa6be6ad187828c87dcc897d6d0df5bc0bb14a9fce558b024ae0087a7f711b8cf1015fd62389959e6a911d70f5cb88e7fada3f95d0d1f0aab29b39f83d330454fce078aeff14255142d5c096c33320d48ea160398890e976b2a5258d4461bf3f1a23fbcce85f4ea8655e195ef5970040dd1d7eb170d128369a881de825cea8e0303627fbe9b8e545ba998457834e3cb4c96fe74440fe0cd44d2cf126206865dc819ae590c350fd1225069be297b1e87f53ec4545ba91d67c47271c0e25118ff8d587eed5ac5e4bbbba8065ed41e3a73ce23d4ab1e2f201ca47c3989af09a1486b6fae4c33d44ec764e9b66d790029652b7db1df3e8ecf57ff2e0832d031d3285de52242633fcbbafcc115e3483120a6381b56d2b2fe66e1d45a8ea4835c5be508e5c0aeb12b9966154ed2ca760709fe3e097fc6cc082941abcd08bae76dba7cdd5c9f4616024e7b2d41b3a2c9ae35f4073916da33d5f37bd64cba7dc289eb6c9f4507313d5bde529f20cb77b287f0231af86e62ce2
#TRUST-RSA-SHA256 54dcd941c85ebc31f02294daf2aa4b081a967ea5f97191a9dfe02221bd67333bdc0d6f2829b1c8f4a9db3520070c821db93aa23ac01445451257b1343f1318b98933186bc77f2c197223cfb5e85a60741f3630b95753c212f9c9bf5df1a6c07b1aaf1284be35e7560936fca804f0e7dbd14edf736a38f0c88d9c6a03e6f15b4a52370f590ba99d2e0382bddcb2897abcdc2b7da8cc8ecfc8b5b57754b0ff8f9845b1e07bc422f068db627d83b61324898980430399a23680a300fc34f45276a5d2b1072260a6ae11bf8e1fed80c818b1f84f68506d6396cfbec6fd05f528c42cf0d9926ebd8c9a53a17a766d208972b40cb1883cb0275f05d109c3578870d6f78e2eb373f8e31087410d20a8d13bb6bb48e3de1860a4147351f81df37ea246c2b0f4f6be9c1e95f92e2bf0917415e1f961bdb9cb60468474711de1a0cf1ad8f6d4c56cf02d263c23cb34e59f1661ac6354a7083b02578f8abf26751e68c6cb5feddfc70ed6bdbc5467fafe13226867ffeba234b3ca185245af6059118ca3054e475bb27d02144d122faf334c459b557b804edf0f9ff90810053420078702ee5769d9c42ea170e6e2eb80f348ca21a18e6583b305d575fd95ce3b686881c22e08daef23e13d0847e1c0dad0236320dfe7377ec3324ca9879972614303acb00f458410387d8cb274c95a94a54b628f8b06b56cee554fdc49e1a828d04b6e8c1c38

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(161455);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/12");

 script_name(english:"Supersedence Data Builder");
 script_summary(english:"Builds a table of supersedence data used to determine what is reported.");

 script_set_attribute(attribute:"synopsis", value:"Supersedence data.");
 script_set_attribute(attribute:"description", value:
"Collects and stores supersedence patch data for various patch types.");
 script_set_attribute(attribute:"solution", value:"N/A");
 
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/24");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();
 script_category(ACT_END2);
 script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"General");
 script_exclude_keys("Host/dead");

 exit(0);
}

include('global_settings.inc');
include('spad_log_func.inc');
include('supersedence_builder.inc');

if (get_kb_item("Host/dead")) exit(0, "The remote host was found to be dead.");

if (!can_query_report()) exit(1, 'Can\'t run query_report().');

if (!supersedence::any_patch_types_available()) exit(0, "No supported patch types found.");

var DEBUG = get_kb_item('global_settings/enable_plugin_debugging');
var found_patch_data = FALSE;
var report = 'Supersedence patch data summary :\n';

# Gather and store patch supersedence data for each patch type.
foreach var patch_type (keys(supersedence::patch_types))
{
  spad_log(name: supersedence::log_name, message:'Gather and store ' + patch_type +' patch supersedence data.');
  if (typeof(supersedence::patch_data_functions[patch_type]) == 'function')
  {
    cnt = supersedence::patch_data_functions[patch_type](type: patch_type);
    if (cnt)
    {
      found_patch_data = TRUE;
      spad_log(name: supersedence::log_name, message:'Inserted ' + cnt + ' ' + patch_type + ' patches.');
    }
    else
    {
      spad_log(name: supersedence::log_name, message:'No ' + patch_type + ' values found.');
    }
    report += '  - ' + patch_type + ' : ' + cnt + '\n';
  }
  else
  {
    spad_log(name: supersedence::log_name, message:'Patch type (' + patch_type + ') data function not defined.');
  }
}

if(!found_patch_data)
{
  report = 'No patch supersedence data found.';
}

var port = 0;

if (DEBUG)
{
  var log = spad_log_get_script_report_attachment(name: supersedence::log_name);

  if (!isnull(log))
  {
    report += '\n\nPlugin debug log has been attached.';
    security_report_with_attachments(
     port        : port,
     level       : SECURITY_NOTE,
     extra       : report,
     attachments : log
    );
    exit(0);
  }
  else
  {
    report += '\n\nUnable to retrieve plugin debug log "' + supersedence::log_name + '".';
    security_report_v4(severity:SECURITY_NOTE, port:port, extra:report);
  }
}