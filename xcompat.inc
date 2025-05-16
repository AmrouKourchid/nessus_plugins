#TRUSTED 63df505274ace1d05ed590fd65d8ae4662db6b13e490d0857c7dd99fb79c5105b6ac353513df1c3b21fee96232c9f4261f6abace7d890f565dbb141f3d614feaead6e3683c043adb7a937ccad8c12877890ac31d57fb1b7560759a55ee70fa1dd73e4447bae949cfd23dc9a413c8f93cd237ba998ead6333cec7f9c7f8721ec7c75dbe9c26a8bc37eafd1874a6b981b28a599e1c5d2eb15c8c59abc088a3a87ebd1c20c1c57ab4988320610fb7161f2ecff7456400801b792d4dd7ce21bad5979cf61d8e329168c8beb0cf71d9ac81a6d22efc4fa388081349defd10ac1119b2bb936bf1aca2b1df92857f1d72d5ff71779f7df66736a6bb0daf4a8320b16b70ef537b2a707971e82733b417d71b866d93bac40f4cf19b6031747de2c3044d0d0765f483bb4e55bdd241d92eb1e860f2ef0a7870159b0a5dd6cff409f3b9281fb94bc69bcfabaa78686ae58ba25443469d76123e3a38fb616f2ea6e1a575f260f484f1af68d361381068cea813ae34874a1d64e7693b6efe0c17d6b20f2363cae5ea25a7e7c46c243e987394a7742c603f1e6c9fd76fd2fecc6d6b106bd82442937a65782edcb4cd2751c1ba4c85d7e2d19ffac739d9ca6a644bb7b58e91b44cfd47100108f1d8229d0923e0dff62c1da5eecab6a658664d775954db2f5bb9c52c2589516ce2f2e790d706278a431538ef8975c989314ea50658c5f66d9c4222
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# xcompat.inc
# Revision 1.7

include("compat_shared.inc");

#
# Backward compatibility functions
#
global_var __desc_buf = NULL;



function cvss_vector_to_temporal_score(vector, base_score)
{
 local_var str;
 local_var Exploitability, RemediationLevel, ReportConfidence;
 local_var base;
 local_var score;
 
 str = vector;
 base_score = split(base_score, sep:'.');
 base = int(base_score[0]) * 1000 + int(base_score[1]) * 100;

 if ( "E:U/" >< str )
     Exploitability = 1176; # 0.85
 else if ( "E:POC/" >< str )
     Exploitability = 1111; # 0.9 
 else if ( "E:F/" >< str )
     Exploitability = 1052; # 0.95
 else if ( "E:H/" >< str )
     Exploitability = 1000; # 1.00
 else #if ( "E:/" >< str || "E:ND/" >< str )
     Exploitability = 1000; # 1.00

 if ( "/RL:OF/" >< str )
     RemediationLevel = 1149; # 0.87
 else if ( "/RL:TF/" >< str )
     RemediationLevel = 1111; # 0.90
 else if ( "/RL:W/" >< str )
     RemediationLevel = 1052; # 0.95
 else if ( "/RL:U/" >< str )
     RemediationLevel = 1000; # 1.00
 else #if ( "/RL:/" >< str || "/RL:ND/" >< str )
     RemediationLevel = 1000; # 1.00

 if ( "/RC:UC" >< str )
     ReportConfidence = 1111; # 0.90 
 else if ( "/RC:UR" >< str )
     ReportConfidence = 1052; # 0.95
 else if ( "/RC:C" >< str )
     ReportConfidence = 1000; # 1.00
 else #if ( "/RC:" >< str || "/RC:ND" >< str )
     ReportConfidence = 1000; # 1.00

 
 score = (base  * 1000)/Exploitability;
 score = (score * 1000)/RemediationLevel;
 score = (score * 1000)/ReportConfidence;
 if ( score % 100 >= 50) score += ( 100 - (score % 100) ); # Rounding
 if ( score / 1000 < 2 )  # If the value is small, more generous rounding
 {
 	if ( score % 100 >= 40) score += ( 100 - (score % 100) ); 
 }
 
 score = (score/10)*10;
 return strcat(score / 1000, ".", (score % 1000)/100);
}

function cvss_vector_to_base_score()
{
 local_var str;
 local_var c,i,a;
 local_var AccessVector, AccessComplexity, Authentication;
 local_var q,z;
 local_var cvss_score;

 str = _FCT_ANON_ARGS[0];
 if ( "AV:L/" >< str )
   AccessVector = 2532;
 else if ( "AV:A/" >< str )
   AccessVector = 1548;
 else if ( "AV:N/" >< str)
   AccessVector = 1000;
 else 
 {
   #display("Unknown CVSS access subvector (", str, ")!\n");
   return NULL;
 }

 if ( "AC:L/" >< str )
   AccessComplexity = 1408;
 else if ( "AC:M/" >< str )
   AccessComplexity = 1639;
 else if ( "AC:H/" >< str )
   AccessComplexity = 2857;
 else 
 {
   #display("Unknown CVSS access complexity subvector (", str, ")!\n");
   return NULL;
 }

 if ( "Au:N/" >< str )
   Authentication = 1420;
 else if ( "Au:S/" >< str )
   Authentication = 1786;
 else if ( "Au:M/" >< str )
   Authentication = 2222;
 else 
 {
   #display("Unknown CVSS authentication subvector (", str, ")!\n");
   return NULL;
 }

 if ( "C:N/" >< str )
   c = 1000;
 else if ( "C:P/" >< str )
   c = 725;
 else if ( "C:C/" >< str )
   c = 340;
 else 
 {
   #display("Unknown CVSS confidentiality subvector (", str, ")!\n");
   return NULL;
 }

 if ( "I:N/" >< str )
   i = 1000;
 else if ( "I:P/" >< str )
   i = 725;
 else if ( "I:C/" >< str )
   i = 340;
 else 
 {
   #display("Unknown CVSS integrity subvector (", str, ")!\n");
   return NULL;
 }

 if ( "/A:N" >< str )
   a = 1000;
 else if ( "/A:P" >< str )
   a = 725;
 else if ( "/A:C" >< str )
   a = 340;
 else 
 {
   #display("Unknown CVSS availability subvector (", str, ")!\n");
   return NULL;
 }

 if ( c + i + a == 3000 )
   return "0.0";

 z = (c*1000)/( (1000*1000)/i);
 z = (z*1000)/( (1000*1000)/a);
 z = 1000 - z;
 z = (1000*1000)/z;
 z = (10410*1000)/z;
 z = (z*1000)/1666;

 q = ( AccessComplexity  * 1000 ) / (( 1000 * 1000 )/Authentication );
 q = ( q * 1000 ) / ( ( 1000 * 1000 ) / AccessVector );
 q = ( 1000 * 1000 ) / q;
 q = q * 20000;
 q = q / 2500;

 z = ( z + q ) - 1500;
 z = (z * 11760)/10000;
 if ( z % 100 >= 50) z += ( 100 - (z % 100) ); # Rounding
 if ( z / 1000 < 2 )  # If the value is small, more generous rounding
 {
 	if ( z % 100 >= 40) z += ( 100 - (z % 100) ); 
 }
 
 z = (z/10)*10;
 cvss_score = strcat(z / 1000, ".", (z % 1000)/100);
 return cvss_score;
}



function xscript_set_attribute(attribute, value)
{
 local_var s, e;
 local_var i;

 if ( defined_func("script_set_attribute") )
 {
  script_set_attribute(attribute:attribute, value:value);
  return;
 }
 if ( isnull(attribute) || isnull(value) ) return;
 value = '' + value;
 e = strlen(value);
 for ( i = 0 ; value[i] >< ' \t\n\r' && i < e ; i ++ ) { };
 for ( e = strlen(value) - 1; value[e] >< ' \t\n\r' && e > 0 ; e -- ) { };
 value = substr(value, i, e);
 if ( strlen(__desc_buf[attribute]) ) __desc_buf[attribute] += '\n';
 __desc_buf[attribute] += value;
}

function xscript_set_cvss3_base_vector()
{
  local_var vector;
  vector = _FCT_ANON_ARGS[0];
  xscript_set_attribute(attribute:"cvss3_vector", value:vector);
}

function xscript_set_cvss3_temporal_vector()
{
  local_var vector;
  vector = _FCT_ANON_ARGS[0];
  xscript_set_attribute(attribute:"cvss3_temporal_vector", value:vector);
}

function xscript_set_cvss_base_vector()
{
 local_var vec;
 vec = _FCT_ANON_ARGS[0];
 xscript_set_attribute(attribute:"cvss_vector", value:vec);
}

function xscript_set_cvss_temporal_vector()
{
 local_var base_score;
 local_var vec;
 vec = _FCT_ANON_ARGS[0];
 xscript_set_attribute(attribute:"cvss_temporal_vector", value:vec);

}

function xscript_end_attributes()
{
 local_var r;
 local_var buf;

 if ( defined_func("script_end_attributes") )
 {
  script_end_attributes();
  return;
 }

 if ( isnull(__desc_buf["cvss_base_score"]) && !isnull(__desc_buf["cvss_vector"]) )
  __desc_buf["cvss_base_score"] = cvss_vector_to_base_score(__desc_buf["cvss_vector"]);


 if ( isnull(__desc_buf["risk_factor"]) )
 {
  if ( isnull(__desc_buf["cvss_base_score"]) )
	__desc_buf["risk_factor"] = "None";
  else {
   if ( int(__desc_buf["cvss_base_score"]) == 10 ) __desc_buf["risk_factor"] = "Critical";
   else if ( int(__desc_buf["cvss_base_score"]) >= 7 ) __desc_buf["risk_factor"] = "High";
   else if ( int(__desc_buf["cvss_base_score"]) >= 4 ) __desc_buf["risk_factor"] = "Medium";
   else if ( int(__desc_buf["cvss_base_score"]) > 0 ) __desc_buf["risk_factor"] = "Low";
   else __desc_buf["risk_factor"] = "None";
  }
 }



 buf = "";
 r = __desc_buf["synopsis"];
 if ( strlen(r) )
 {
   buf += 'Synopsis :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["description"];
 if ( strlen(r) )
 {
   buf += 'Description :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["see_also"];
 if ( strlen(r) )
 {
   buf += 'See also :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["solution"];
 if ( strlen(r) )
 {
   buf += 'Solution :\n\n';
   buf += r;
   buf += '\n\n';
 }
 r = __desc_buf["risk_factor"];
 if ( strlen(r) )
 {
   buf += 'Risk factor :\n\n';
   buf += r;
   r = __desc_buf["cvss_base_score"];
   if ( r ) {
	buf += " / CVSS Base Score : " + r;
	r = __desc_buf["cvss_vector"];	
	if ( r ) buf += '\n(' + r + ')\n';
    	else buf += '\n';
    }
    else buf += '\n';
 }
 

 script_description(buf);
}

function xscript_osvdb_id()
{
  local_var	i;

  foreach i (_FCT_ANON_ARGS)
    script_xref(name:"OSVDB", value: i);
}

function xscript_cwe_id()
{
  local_var	i;
  foreach i (_FCT_ANON_ARGS)
    script_xref(name:"CWE", value: i);
}

function xscript_cvs_date()
{
  local_var	v;

  v = split(_FCT_ANON_ARGS[0], sep: ' ', keep: 0);
  if ( isnull(v) || isnull(v[1]) || v[1] !~ "^2[0-9]+/[0-9]+/[0-9]+$" ) return;
  xscript_set_attribute(attribute:"plugin_modification_date", value: v[1]);
}

# This lets the dependencies be .nasl when we're testing and .nbin
# when the code is running as .nbin on customer scanners.
# In other words, it lets us test everything without compiling anything to
# .nbin.
function script_dependencies_copy_extension()
{
  local_var extension, basename;
  if (SCRIPT_NAME =~ "\.nasl$")
    extension = ".nasl";
  else
    extension = ".nbin";

  foreach basename (_FCT_ANON_ARGS)
    script_dependencies(basename + extension);
}
