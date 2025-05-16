#TRUSTED 24d887570dbfd8c8b77761866c92fc3d6a28b2c6812b8ec25661ec3dda46f519b59c832720358fe05cc5fbcf1d1e8dcbf14ae005bc4573d1908bf13aa394961df3db86aca05929f228c1e1cd6909398684c7fd0704c6fe3c4b3b343bc0718d37b5b59d91b6a91f258c1149bce606c7e1e9a84cc195c58b7f3c479149bb0cd95b669d0daf57445713e547a57239b5c72b14562eb3f97e6d0a7f201ac6ab80c976c271039ff991c53bca894e414a76d27033efe54896742a572c42b041094e42acaf7f5f936b38b291fbd740c0caecb1c2ac26bed878765d7a92054382cef8c3a870c7d493cbce768a2c6921d35b96a02bab343cab6ddc1954d849c2dd18eeaec6768a924625fe847bfc3ebc0849b3883f4d4a25678d7b0877142223d0a0b4d310b14d9d59b4d9a25ca3db41035c1a57f595d3dd372fd3516aef0f421cfacee4a28af0343b3f94298b79dbf41ada64b357924b80c72018d3e525173001e39e4d2b745c7751887b43efc312f640f7b7c9deadf7d3d1f5ebb73cb7450c95095a4c078d9fc899243d8e145e436cf0442d6921142169bf91b6dc4277b2f0ef5862334636a191108ec62de7c077cb3c873366fcaa05b9763d310f5d70ac23c1d23cdb0bd4407c1bbc2e7518874c3d6822ffa303302938f56486ac54c9fe5157daa2bf62ae1dc6bbc870a0d943644b3061ec89f0e51276cdfc0d3412cf0ba704c4c9860f
#TRUST-RSA-SHA256 9db74e6a031da21f5b2220747c2bf56cfdc74a529b6d0b0734d0d780e10dc2f8646a33fa54b5fd9e765bdd06893f4da0c30edafb46240340ff43b7ddfd40c5f4d2a0dd472b009506f95bf329e62888fe1f82fbc83530361019f7d3fda2b199e4d35035dfdabf50ba5e0bf81f92671a2ecf8d7875d90f8f6c3a92f501fb9f6ab2d8ea84ab1c671f05b56ca4907d7925f4a1e3e50a41824b1f56d8f165cf0b13b921617259cd8abdc30f6c9ab0a71a6e6dff5d31182a74db067c9411b9923a99d92a5e2cb2f3405cfad321ac86305ff426b6dfa70204bd2c1639216f35590ac75e36a455dc5a8db807063107f2f1d3193920646f7f05811bd14c429797942c81ba70669507943f1ff141201230a1040f40ae7395ec0f95afc36945fd9a96aa55e300dfd28f9ccdb3c6137a9922d95bb091d1b4c06c46bbd210c49ad7a325f7708a863e28a8fdb724995039bc8eed76ebc65e9bc2a1af012e09575b8c77be1bcde5216e4dc6db4138a79c6a197db6b9bc254891c74c5eef5c7b07aa443f5c9f4e64ae5902afe5c339481463d539ffae4cb61c4d70e87d36f2e93ae4a63ad7c3aff649934728750da4f66bb2811c91f7fa8cd4d680935a4bfd6261f85054fe67308f9423ad7605a04970d82d10d8fbc0152cc9060e015390b3408f67d871f60d6fe8cc78856c365879496f0241a255191efc3c329c04cb1b3da78f7aae9f7973e296
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.2
###

include("compat_shared.inc");

##
# What is minimum host os confidence?
#
# @return integer minimum host os confidence possible
##
function get_host_os_confidence_min()
{
  return 0;
}

##
# What is maximum host os confidence?
#
# @return integer maximum host os confidence possible
##
function get_host_os_confidence_max()
{
  return 100;
}

##
# What is default host os confidence threshold?
#
# Values less than this threshold are considered uncertain.
#
# @return integer host os confidence certain / uncertain threshold
##
function get_host_os_confidence_default()
{
  return 80;
}

##
# KB key for all things Host OS
#
# @param [method:string] optional string for method
#
# @return string KB key for grouping Host OS elements
##
function get_host_os_kb_key( method )
{
  if ( empty_or_null( method ) )
  {
    method = "";
  }
  else
  {
    method = "/" + method;
  }
  return "Host/OS" + method;
}

##
# KB key for Host OS Confidence
#
# @param [method:string] optional string for method
#
# @return string KB key for Host OS Confidence
##
function get_host_os_confidence_kb_key( method )
{
  return get_host_os_kb_key( method:method ) + "/Confidence";
}

##
# KB key for Host OS Type
#
# @param [method:string] optional string for method
#
# @return string KB key for Host OS Type
##
function get_host_os_type_kb_key( method )
{
  return get_host_os_kb_key( method:method ) + "/Type";
}

##
# KB key for Host OS Version
#
# @param [method:string] optional string for method
#
# @return string KB key for Host OS Version
##
function get_host_os_version_kb_key( method )
{
  return get_host_os_kb_key( method:method ) + "/Version";
}

##
# Answers the question "is host os id certain?"
#
# Allows centralized control of what a confident OS ident is (or is not).
#
# @anonparam confidence number 0 to 100 to use as comparison (instead of default)
#
# @return boolean true if OS ident is certain, false if OS ident is uncertain
##
function host_os_id_certain( )
{
  # set default confidence threshold
  local_var confidence_threshold = get_host_os_confidence_default();
  local_var caller_confidence = _FCT_ANON_ARGS[0];

  # did the caller specify a confidence threshold?
  # and is specified confidence an int?
  if ( !isnull( caller_confidence ) && ( typeof( caller_confidence ) == "int" ) )
  {
    # yes, caller specified threshold, is it valid range?
    if ( ( caller_confidence >= get_host_os_confidence_min() ) &&
         ( caller_confidence <= get_host_os_confidence_max() ) )
    {
      # caller specified confidence is valid, use caller specified confidence
      confidence_threshold = caller_confidence;
    }
    # else bad range specified using default
  }
  # else caller specified confidence is absent or wrong type using default

  # get host os confidence (use strict fetch of only one confidence)
  local_var kb_confidence_list = get_kb_list(get_host_os_confidence_kb_key());
  local_var kb_confidence = kb_confidence_list[get_host_os_confidence_kb_key()];
  # certain of confidence when:
  #   KB entry exist for confidence
  #   KB entry is equal or greater than specified threshold
  return ( !isnull(kb_confidence) && ( kb_confidence >= confidence_threshold ) );
}

##
# Answers the question "is host os id uncertain?"
#
# @return boolean opposite of host_os_id_certain
##
function host_os_id_uncertain( )
{
  return ! host_os_id_certain( _FCT_ANON_ARGS[0] );
}

##
# Adds values to Host/OS decision dataset.
#
# @param [method:string] required, string for method
# @param [os:string] required, string describing OS
# @param [confidence:integer] required, confidence of data
# @param [type:string] required, string categorizing type
# @param [extra:array] optional, any additional KB items

# @return [boolean] TRUE indicates success, otherwise FALSE
##
function host_os_add( method, os, confidence, type, extra )
{
  if ( empty_or_null( method ) || typeof( method ) !~ '(data|string)' ||
       empty_or_null( os ) || typeof( os ) !~ '(data|string)' ||
       empty_or_null( type ) || typeof( type ) !~ '(data|string)' ||
       isnull( confidence ) || typeof( confidence ) != 'int' ||
       confidence < get_host_os_confidence_min() ||
       confidence > get_host_os_confidence_max() ||
       ( !isnull(extra) && typeof(extra) != 'array' ) )
  {
    return FALSE;
  }
  replace_kb_item( name: get_host_os_kb_key( method:method ), value: os );
  replace_kb_item( name: get_host_os_confidence_kb_key( method:method ), value: confidence );
  replace_kb_item( name: get_host_os_type_kb_key( method:method ), value: type );
  local_var key;
  foreach key ( keys( extra ) )
  {
    replace_kb_item( name: get_host_os_kb_key( method:method ) + "/" + key, value: extra[key] );
  }
  return TRUE;
}

