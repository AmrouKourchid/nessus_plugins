#TRUSTED 0a74814bd63d8002c484ebb49f40cbe84d44834edf11b7c57cd92762cf88d03d943ea7d402c54595f2a00a6236dbb59a8ff4d2340b086668989b42960a168dfd4cfa8cd798816f678a3b2d4d194b083183a1b5baeca6d935ef6617632e07809cad89406543276fbfa3aef163d830657792aec59ae0e92e82bcd0117904d7c82630968c6ad0707ca4bc5984cd709ec620e60bc37d34dc053e7eb3ba3819a1ad6408622ce23ab9013b77e0e373719de45aecc9acaf92034f5ad447319b0dee84898c9ae7dadbb0a6f422aee3cefddcd0b974a72bec64323da7b77c0aa091d51c647eb9dae6e7db18d5e9b9ec86259ba774fe5279fcf6370f79a2d25a421f2f9fa50ae01f1b701f271c02f9bfa603b5090ba772b9212cc9cb27dc0fa0a879e2ca77b2745a5374b89ee4fe9a77c43058ed900c2087f3ad8372b7f6cb0ea08eaf6428762865eaac2fbaf8a0e43149307ca188e6f3d8eabde69c88dc83ec8713697dce5fbcc61447abd48dbdd2710b54c9b39a6256a49148caeb9c910380eb576d125b464b22fff53cd62a1d88eb2b863fbcdd7d44f7863de652620e1afea888490630d0e4f18c25c33d78ddd387e2112a25358269092e405842946a7b08238ad1ab34b2d1343672ec9742ff11382fe7c5f4ad3b3eae5f90481aaa0396e84781ea191e250922dcf0aec440e3b82bcdce09147b0aaeea4d7410ed4535707ce0cdc71e95
#TRUST-RSA-SHA256 387b4bd745631d8191807058708a5c56cf408dc295b1727b045c67d514b6326b4ad32e4602273253403b6c80899b34c1a4bda433498c9ab35e4e0f2ef8348d19ef99f369e35fe15facd1b38119decf75cd2300bc6baed4bc194bb87194b193d424a3baaf86295a01ebefc4257a83ef8f06845cb5874a85553612ad17bed496389ccba69d0fea1210fa15f697fb44c2194c231bc785db6b830abc7403c054d5dab60874dd7404f93720b434bd9b2926d92ebce72c5df7f48fe21f4bee7ac9d20dc90dcc5964c90457a0e6cf256be57f986cb4157d65878d99bfe71960d7e2c02def9fd7f1a7994febcfd2fc172de8cc58ffe0a2dfc41e1b687a8e07bc676157e5c7c02303da8ed8c271697fee60e716b5f79e690ff846ee3507b38c1ffbddf2b55f7f7c35da956593452f021b671ce5d26711efe01a1a8f012f75b8e585c3315b9200c76cfa55d614413cfee37d8264bbe376fb0331d4939e21b5ccd2013f6e96f37840ad4128d76e9f09bdae4cc2b84388a9c4f63ca585a03908648203f4c0e535997b253ca5c72822abee663da8fd24d83db9c61c4e7458d9dcd5ec5092ae7ed6488db70bc617c58a95fc03b1ab6838eb77ec6c2e7cdd2ee8ab9542138aa03da33ac280328bb7cf35a7d90f3bac03a78b37ee7d8e05d088213fea5d1e93630262f7c07d92c6ee200f37f9545144b41095d9693f1a6b4760949f87cbe7c963b9
#------------------------------------------------------------------------------
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# smb_globals.inc
# Revision: 1.4

include ('debug.inc');
include ('compat_shared.inc');

# NTLMSSP FLAGS
global_var NTLMSSP_NEGOTIATE_UNICODE              = 0x00000001;
global_var NTLMSSP_NEGOTIATE_OEM                  = 0x00000002;
global_var NTLMSSP_REQUEST_TARGET                 = 0x00000004;
global_var NTLMSSP_NEGOTIATE_SIGN                 = 0x00000010;
global_var NTLMSSP_NEGOTIATE_SEAL                 = 0x00000020;
global_var NTLMSSP_NEGOTIATE_LM_KEY               = 0x00000080;
global_var NTLMSSP_NEGOTIATE_00000100             = 0x00000100;
global_var NTLMSSP_NEGOTIATE_NTLM                 = 0x00000200;
global_var NTLMSSP_NEGOTIATE_00000400             = 0x00000400;
global_var NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED      = 0x00001000;
global_var NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED = 0x00002000;
global_var NTLMSSP_NEGOTIATE_ALWAYS_SIGN          = 0x00008000;
global_var NTLMSSP_TARGET_TYPE_DOMAIN             = 0x00010000;
global_var NTLMSSP_TARGET_TYPE_SERVER             = 0x00020000;
global_var NTLMSSP_TARGET_TYPE_SHARE              = 0x00040000;
global_var NTLMSSP_NEGOTIATE_NTLM2                = 0x00080000;
global_var NTLMSSP_NEGOTIATE_TARGET_INFO          = 0x00800000;
global_var NTLMSSP_NEGOTIATE_128                  = 0x20000000;
global_var NTLMSSP_NEGOTIATE_KEY_EXCH             = 0x40000000;
global_var NTLMSSP_NEGOTIATE_56                   = 0x80000000;

# NTLMSSP Header in DCE/RPC over TCP Auth header
global_var DCERPC_AUTHN_NONE = 1;
global_var DCERPC_AUTHN_CONNECT = 2;
global_var DCERPC_AUTHN_CALL = 3;
global_var DCERPC_AUTHN_PACKET = 4;
global_var DCERPC_AUTHN_PKT_INTEGRITY = 5;
global_var DCERPC_AUTHN_PKT_PRIVACY = 6;

# DCERPC Authentication Service Constants
global_var DCERPC_AUTHN_SVC_NONE = 0;
global_var DCERPC_AUTHN_SVC_DCE_PRIVATE = 1;
global_var DCERPC_AUTHN_SVC_DCE_PUBLIC = 2;
global_var DCERPC_AUTHN_SVC_DEC_PUBLIC = 4;
global_var DCERPC_AUTHN_SVC_GSS_NEGOTIATE = 9;
global_var DCERPC_AUTHN_SVC_WINNT = 10;
global_var DCERPC_AUTHN_SVC_GSS_SCHANNEL = 14;
global_var DCERPC_AUTHN_SVC_GSS_KERBEROS = 16;
global_var DCERPC_AUTHN_SVC_DPA = 17;
global_var DCERPC_AUTHN_SVC_MSN = 18;
global_var DCERPC_AUTHN_SVC_DIGEST = 21;
global_var DCERPC_AUTHN_SVC_NEGO_EXTENDER = 30;
global_var DCERPC_AUTHN_SVC_MQ = 100;
global_var DCERPC_AUTHN_SVC_DEFAULT = 0xffffffff;

# DCE / RPC
global_var DCE_RPC_ACK          = 0x07;
global_var DCE_RPC_ALTER        = 0x0E;
global_var DCE_RPC_ALTER_RESP   = 0x0F;
global_var DCE_RPC_AUTH3        = 0x10;
global_var DCE_RPC_BIND         = 0x0B;
global_var DCE_RPC_BIND_ACK     = 0x0C;
global_var DCE_RPC_BIND_NACK    = 0x0D;
global_var DCE_RPC_CANCEL_ACK   = 0x0A;
global_var DCE_RPC_CL_CANCEL    = 0x08;
global_var DCE_RPC_CO_CANCEL    = 0x12;
global_var DCE_RPC_FACK         = 0x09;
global_var DCE_RPC_FAULT        = 0x03;
global_var DCE_RPC_NOCALL       = 0x05;
global_var DCE_RPC_ORPHANED     = 0x13;
global_var DCE_RPC_PING         = 0x01;
global_var DCE_RPC_REJECT       = 0x06;
global_var DCE_RPC_REQUEST      = 0x00;
global_var DCE_RPC_RESPONSE     = 0x02;
global_var DCE_RPC_SHUTDOWN     = 0x11;
global_var DCE_RPC_WORKING      = 0x04;

global_var MICROSOFT_KERBEROS_OID = "1.2.840.48018.1.2.2";
global_var MICROSOFT_NEGOEX_OID   = "1.3.6.1.4.1.311.2.2.30";

#==================================================================#
# Logging Shortcuts                                                #
#==================================================================#

function _debug_smb_status_not_success(fname, status, level)
{
  if(empty_or_null(status)) status = 'success';
  if(empty_or_null(level)) level = 1;
  dbg::detailed_log(lvl:level, family:'SMB', src:fname, msg:
    'Status is not ' + status + '!');
}

function _debug_smb_null_return(fname, label, value, level)
{
  if(empty_or_null(level)) level = 1;
  if (empty_or_null(value))
    value = 'NULL';
  dbg::detailed_log(lvl:level, family:'SMB', src:fname, msg:
    value + ' return from ' + label + '!');
}

function _debug_smb_unsupported_transport(fname, label, level, transport)
{
  if(empty_or_null(level)) level = 1;
  if(!empty_or_null(transport)) transport = ' ' + transport;
  if (empty_or_null(label))
    label = 'SMB_SERVICE or SMB_NSX or unknown';
  dbg::detailed_log(lvl:level, family:'SMB', src:fname, msg:
    'Unsupported SMB transport' + transport + ' is ' + label + '!');
}

function _debug_smb_length(fname, varname, second, length, operator, level)
{
  var msg;
  if(empty_or_null(level))
    level = 1;
  if (empty_or_null(operator))
    operator = 'less than';
  if (!empty_or_null(varname))
    msg = varname + ' length ';
  else
    msg = 'Length ';
  msg += operator + ' ';
  if (!empty_or_null(second))
    msg += second + ' ';
  msg += length + ' bytes!';
  dbg::detailed_log(lvl:level, family:'SMB', src:fname, msg:msg);
}
