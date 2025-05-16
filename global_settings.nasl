#TRUSTED 83d3cc075b8088bab50b9483da890afe9ba8e275cb45c59d523fcf97b50e65c0ee8ca112c17cdee74725748cc7be9bd8a06d1ce307c96011087dece28fcdb360983e5da5a9acde8c9ce99527fe233c4b5cd722181014defb82cccec3d7bef1e08709d4d61519cfc94ca005f6240cea3135aa77486e180218a26f8c33b51670db2d5ee93084fd484b170fff905fd7e9d3a6aa59e02ad5448fdddfa80a39085f9b0f06cecdc9656a8b9e47e0e5ddff25020a832feb946b12f86053e97f0f20fd65e8738b4a784b788f3ed06110adecc0690375ebf427e0edd147b3051b06449161c17a69f4381eb10278e096594dba516abe527eb7bd71481c7672f1cb541bfb685eab102725417d15bc2a6c654782c4ea1fd05728ab94aab7048caa7cba9844f64642fe7049884a6de73b2e92cf57912145feb5eb6d16c65f4c548530d895464939b32e27411ed6139fed0d10bd37dba1a406a87810b8d9d8d4b309aff9be50ed42c36a55c2b155e4d8e80e2be62df150100882e28ff8a78c9c9bb1b9c1a6667a76970acc11378df409a211077567c6da9fd8e29e6009d0c6276adbf4589ed11d59a44e0dec8a8731652c87fc577e5ce4ff984e13a1916e7a5d087bc39877051f7ecb3455cea9034910984725260534bc5bbb6e1802d29d709577693036c2dc702fb05ce6d58d940009a086bc3e2f7eee6d512dbe8dc9190e9acdfb7490bce23c
#TRUST-RSA-SHA256 5b6cf908de93738a2539026a5b3dddfcf779a6f120faf8901d0cf4444b472b5153ef08fb0489e730ee405b64430eeda7aba5da1c79b167fe5d72f343abd7bc02d417902e6d76e0504dfb424ff535928375541554daba7fde5922fedb595bc3f22f8a8ab87f0c01fe99b285d8c1f8a7c76cf7c9b726c18c2546882497801c3ab092e6602ce59103588d1ea4628e770d75f5217276209a618b4d9c298c10e8a7d07b746ddc6f48a91b0055dcf1b1b15919a4132410d52f8438272e76713218c88fa6c98befbcf40e5eb12e5326806ced13f31aa858f2c4c2e98cd88b69f4cc7806bc81a8074274f6db4a668d11df44cfbdc9e1d9b965af7a4a200c63ca8baebf0050c02fd8fff6945c58d470a1904aed5a59b59197681e430478b9bcae0e1b8a99db1c42c34e0bcbc13b9c666471e7ed0d730446fe4572751dbc8b91df5aa86679e52ac85f7dd0d75b915147757d59c4e78ade94b245b57fc9a3a385f2713f6f4720ee90cc741ff569696c0a5768616dca6c87da4dfa4cc78801fabc5656fbda309d371842f237677e85c9d25219b051624c8490b146ef32f0af0e07f3a08bfbf93732675389418955df39e00a19a42e0790e0977391826929d1cfec34d23f5caba6c2e82bbda21723c8b3d0319f2e3efef9ebe38c422e2b424af8b36d154d6c209bdc727d7e4de8cda19752b2abbf893951de84ec082c7b5ffcf14d66f9b4fa58
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12288);
 script_version("1.63");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/12");

 script_name(english:"Global variable settings");
 script_summary(english:"Global variable settings.");

 script_set_attribute(attribute:"synopsis", value:
"Sets global settings.");
 script_set_attribute(attribute:"description", value:
"This plugin configures miscellaneous global variables for Nessus
plugins. It does not perform any security checks but may disable or
change the behavior of others.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/29");

 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_set_attribute(attribute:"agent", value:"all");
 script_end_attributes();

 script_category(ACT_SETTINGS);

 script_copyright(english:"This script is Copyright (C) 2004-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Settings");

 if ( NASL_LEVEL >= 3200 )
   script_add_preference(name:"Probe services on every port", type:"checkbox", value:"yes");
 script_add_preference(name:"Do not log in with user accounts not specified in the policy", type:"checkbox", value:"yes");
 if ( NASL_LEVEL >= 4000 )
  script_add_preference(name:"Enable CGI scanning", type:"checkbox", value:"no");
 else
  script_add_preference(name:"Enable CGI scanning", type:"checkbox", value:"yes");

 script_add_preference(name:"Network type", type:"radio", value:"Mixed (use RFC 1918);Private LAN;Public WAN (Internet)");
 script_add_preference(name:"Enable experimental scripts", type:"checkbox", value:"no");
 script_add_preference(name:"Thorough tests (slow)", type:"checkbox", value:"no");
 script_add_preference(name:"Report verbosity", type:"radio", value:"Normal;Quiet;Verbose");
 script_add_preference(name:"Report paranoia", type:"radio", value:"Normal;Avoid false alarms;Paranoid (more false alarms)");
 script_add_preference(name:"HTTP User-Agent", type:"entry", value:"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)");
 script_add_preference(name:"SSL certificate to use : ", type:"file", value:"");
 script_add_preference(name:"SSL CA to trust : ", type:"file", value:"");
 script_add_preference(name:"SSL key to use : ", type:"file", value:"");
 script_add_preference(name:"SSL password for SSL key : ", type:"password", value:"");
 script_add_preference(name:"Enumerate all SSL ciphers", type:"checkbox", value:"yes");
 script_add_preference(name:"Enable CRL checking (connects to Internet)", type:"checkbox", value:"no");
 script_add_preference(name:"Enable plugin debugging", type:"checkbox", value:"no");
 script_add_preference(name:"Java ARchive Detection Path : ", type:"entry", value:"");

 exit(0);
}

var is_scan_sc, cert, ciph, key, ca, opt, pass, b;

if(isnull(get_kb_item("/tmp_start_time")))
  replace_kb_item(name: "/tmp/start_time", value: unixtime());

if ( get_kb_item("global_settings/disable_service_discovery")  ) exit(0);
if ( script_get_preference("SSL certificate to use : ") )
 cert = script_get_preference_file_location("SSL certificate to use : ");

if ( script_get_preference("SSL CA to trust : ") )
 ca = script_get_preference_file_location("SSL CA to trust : ");

ciph = script_get_preference("Enumerate all SSL ciphers");
if ( ciph == "no" ) set_kb_item(name:"global_settings/disable_ssl_cipher_neg", value:TRUE);

if ( script_get_preference("SSL key to use : ") )
 key = script_get_preference_file_location("SSL key to use : ");

pass = script_get_preference("SSL password for SSL key : ");

if ( cert && key )
{
 if ( NASL_LEVEL >= 5000 )
 {
  mutex_lock("global_settings_convert");
  if ( get_global_kb_item("/tmp/global_settings_convert") == NULL )
  {
   if ( file_stat(cert) )
   {
    b = fread(cert);
    unlink(cert);
    fwrite(data:b, file:cert);
   }

   if ( file_stat(key) )
   {
    b = fread(key);
    unlink(key);
    fwrite(data:b, file:key);
   }

   if ( !isnull(ca) && file_stat(ca) )
   {
    b = fread(ca);
    unlink(ca);
    fwrite(data:b, file:ca);
   }
   set_global_kb_item(name:"/tmp/global_settings_convert", value:TRUE);
  }
  mutex_unlock("global_settings_convert");
 }

 set_kb_item(name:"SSL/cert", value:cert);
 set_kb_item(name:"SSL/key", value:key);
 if ( !isnull(ca) ) set_kb_item(name:"SSL/CA", value:ca);
 if ( !isnull(pass) ) set_kb_item(name:"SSL/password", value:pass);
}

opt = script_get_preference("Enable CRL checking (connects to Internet)");
if ( opt && opt == "yes" ) set_global_kb_item(name:"global_settings/enable_crl_checking", value:TRUE);

opt = script_get_preference("Enable plugin debugging");
if ( opt && opt == "yes" ) replace_kb_item(name:"global_settings/enable_plugin_debugging", value:TRUE);

opt = script_get_preference("Always log SSH commands");
if ( opt && opt == "yes" ) set_kb_item(name:"global_settings/always_log_ssh_commands", value:TRUE);

opt = script_get_preference("Probe services on every port");
if ( opt && opt == "no" ) set_kb_item(name:"global_settings/disable_service_discovery", value:TRUE);

opt = script_get_preference("Do not log in with user accounts not specified in the policy");
if (! opt || opt == "yes" ) set_kb_item(name:"global_settings/supplied_logins_only", value:TRUE);

opt = script_get_preference("vendor_unpatched");
if ( opt && opt == "yes" ) set_kb_item(name:"global_settings/vendor_unpatched", value:TRUE);

opt = script_get_preference("Enable CGI scanning");
if ( opt == "no" ) set_kb_item(name:"Settings/disable_cgi_scanning", value:TRUE);

opt = script_get_preference("Enable experimental scripts");
if (! opt || ";" >< opt ) opt = "no";
set_kb_item(name:"global_settings/experimental_scripts", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/ExperimentalScripts", value:TRUE);

opt = script_get_preference("Thorough tests (slow)");
if (! opt || ";" >< opt ) opt = "no";
replace_kb_item(name:"global_settings/thorough_tests", value:opt);

if ( opt == "yes" ) replace_kb_item(name:"Settings/ThoroughTests", value:TRUE);

opt = script_get_preference("Report verbosity");
if (! opt || ";" >< opt ) opt = "Normal";
set_kb_item(name:"global_settings/report_verbosity", value:opt);

opt = get_preference("sc_version");
if ( opt )
{
  set_kb_item(name:"Product/SecurityCenter", value:TRUE);
  is_scan_sc = 1;
}

opt = script_get_preference("Debug level");
# If isnull, UI is missing Debug level entirely (T.sc), default to 3.
# Still won't run without plugin debugging enabled.
if ( is_scan_sc && ! opt ) opt = "3";
if (! opt || ";" >< opt ) opt = "0";

# Don't set the debug_level KB if using nasl CLI and the KB is already set
if (! isnull(get_preference("plugins_folder")) || isnull(get_kb_item("global_settings/debug_level")))
  replace_kb_item(name:"global_settings/debug_level", value:int(opt));

opt = script_get_preference("Report paranoia");
if (! opt || ";" >< opt ) opt = "Normal";
set_kb_item(name:"global_settings/report_paranoia", value:opt);
if (opt == "Paranoid (more false alarms)")
  set_kb_item(name:"Settings/ParanoidReport", value: TRUE);

opt = script_get_preference("Network type");
if (! opt || ";" >< opt ) opt = "Mixed (RFC 1918)";
set_kb_item(name:"global_settings/network_type", value:opt);

opt = script_get_preference("HTTP User-Agent");
if (! opt) opt = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)";
set_kb_item(name:"global_settings/http_user_agent", value:opt);
if ( NASL_LEVEL >= 3000 )	# http_ids_evasion.nasl is disabled
  set_kb_item(name:"http/user-agent", value: opt);

opt = get_preference("auto_accept_disclaimer");
if (! opt || ";" >< opt ) opt = "no";
set_kb_item(name:"global_settings/automatically_accept_disclaimer", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/automatically_accept_disclaimer", value:TRUE);

opt = script_get_preference("Host tagging");
if (! opt || ";" >< opt ) opt = "no";
var opt2 = get_preference("host_tagging");
if (! opt2 || ";" >< opt2 ) opt2 = "no";

if (opt == "yes" || opt2 == "yes") opt = "yes";
set_kb_item(name:"global_settings/host_tagging", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/HostTagging", value:TRUE);

opt = script_get_preference("Java ARchive Detection Path : ");
if ( opt ) set_kb_item(name:"global_settings/jar_detect_path", value:opt);

opt = get_preference("Patch Report[checkbox]:Display the superseded patches in the report");
if (! opt || ";" >< opt ) opt = "no";
set_kb_item(name:"global_settings/report_superseded_patches", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/report_superseded_patches", value:TRUE);
