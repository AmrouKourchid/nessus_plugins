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
# mswsp.inc
# Revision: 1.5

include("compat_shared.inc");
include("smb_func.inc");
include("crypto_func.inc");

############
## Header ##
############

global_var CPMConnect     = 0xc8;
global_var CPMCreateQuery = 0xca;
global_var CPMFreeCursor  = 0xcb;
global_var CPMSetBindings = 0xd0;
global_var CPMGetRows     = 0xcc;

global_var S_OK          = 0;
global_var S_ENDOFROWSET = 0x00040ec6;
global_var S_INVALIDARG  = 0x80070057;
global_var S_DBEXCEPTION = 0x80040718;

global_var RTNone            = 0;
global_var RTAnd             = 1;
global_var RTOr              = 2;
global_var RTNot             = 3;
global_var RTContent         = 4;
global_var RTProperty        = 5;
global_var RTCoerce_Absolute = 0xc;

global_var GUID_Query      = raw_string( raw_dword(d:0x49691c90), raw_word(w:0x7e17), raw_word(w:0x101a), raw_dword(d:0x00081ca9), raw_dword(d:0xa9cd2e2b) );
global_var GUID_Storage    = raw_string( raw_dword(d:0xb725f130), raw_word(w:0x47ef), raw_word(w:0x101a), raw_dword(d:0x6002f1a5), raw_dword(d:0xaceb9e8c) );
global_var GUID_Document   = raw_string( raw_dword(d:0xf29f85e0), raw_word(w:0x4ff9), raw_word(w:0x1068), raw_dword(d:0x000891ab), raw_dword(d:0xd9b3272b) );
global_var GUID_XXX        = raw_string( raw_dword(d:0xde35258c), raw_word(w:0xc695), raw_word(w:0x4cbc), raw_dword(d:0xb03882b9), raw_dword(d:0xd0ce24ad) );

global_var PRSPEC_PROPID = 1;

global_var VT_I4      = 3;
global_var VT_VARIANT = 0xc;

global_var GENERATE_METHOD_EXACT   = 0;
global_var GENERATE_METHOD_PREFIX  = 1;
global_var GENERATE_METHOD_INFLECT = 2;

global_var PRNE = 5;
global_var PREQ = 4;

global_var FSCTL_PIPE_WAIT        = 0x00110018;

# Global var to track GUID and structure 2, 4 and 8 byte alignment
global_var wsp_msg_idx;

#############
## Include ##
#############

function WSP_CPMGetRows(c,s)
{
  local_var data, pkt;
  local_var num_rows;
  
  num_rows = 1;
  wsp_msg_idx = 0x14; # 14h header bytes
  
  data =  raw_dword(d:c);           # hCursor
  data += raw_dword(d:num_rows);    # cRowsToTransfer
  data += raw_dword(d:s);           # cbRowWidth
  data += raw_dword(d:0x14);        # cbSeek
  data += raw_dword(d:0x2020);      # cbReserved
  data += raw_dword(d:0x4000);      # cbReadBuffer
  data += raw_dword(d:1000*num_rows); # ulClientBase
  data += raw_dword(d:0);           # fBwdFetch
  data += raw_dword(d:2);           # eType
  data += raw_dword(d:0);           # chapt
  
  # Seek Description (var)
  data += raw_dword(d:0xffffffff);  # bmkOffset
  data += raw_dword(d:0);           # cskip
  data += raw_dword(d:0);           # hRegion
  
  pkt = WSP_Header(msgid:CPMGetRows, data:data);
  pkt += data;
  return pkt;
}

function WSP_MakeColumnSet(lst)
{
  local_var ret, itm;
  ret = '';
  foreach itm (lst)
  {
    ret += raw_dword(d:itm);
  }
  ret = raw_dword(d:max_index(lst)) + ret;
  return ret;
}

function WSP_MakeRestrictionArray(h,path)
{
  local_var ret;
  ret = raw_byte(b:1) + # Count
        raw_byte(b:1) + # Present
        raw_byte(b:0);  # Padding
  
  wsp_msg_idx += strlen(ret);
  
  ret += WSP_RTAnd(w:1000, rw:2);
    ret += WSP_RTProperty(w:1000);
      ret += PropertyRestriction(op:PREQ);
        ret += Property(g:GUID_Storage,kind:PRSPEC_PROPID,id:0x16, v:"file://"+h+"/"+path,l:0x409);
    ret += WSP_RTContent();
      ret += Property_phrase(g:GUID_Query,kind:PRSPEC_PROPID,id:6, v:"TextFile",l:0x409,meth:GENERATE_METHOD_EXACT);

  return ret;
}

function Property_phrase(g,kind,id,v,l,meth)
{
  local_var ret;

  ret = '';
                              # pad to 8
  if ((wsp_msg_idx + strlen(ret)) % 8 != 0)
  {
    ret += crap(data:'\x00', length:(8 - ((wsp_msg_idx + strlen(ret)) % 8)));
  }
  
  ret += g;                   # CFullPropSpec (GUID)
  ret += raw_dword(d:kind);   # ulKind
  ret += raw_dword(d:id);     # propid
  
  ret += MakeCString(s:v);      # prval
  if ((wsp_msg_idx + strlen(ret)) % 4 != 0)
  {
    ret += crap(data:'\x00', length:(4 - ((wsp_msg_idx + strlen(ret)) % 4)));
  }
  
  ret += raw_dword(d:l);      # lcid
  ret += raw_dword(d:meth);   # method
  
  wsp_msg_idx += strlen(ret);     # pad to 4
  return ret;
}

function WSP_CTableColumn(g,kind,id,vt,valoffset,valsize,statusoffset,lengthoffset)
{
  local_var ret, value_used, status_used, length_used;

  if (isnull(valoffset) || isnull(valsize)) value_used = FALSE;
  else value_used = TRUE;
  if (isnull(statusoffset)) status_used = FALSE;
  else status_used = TRUE;
  if (isnull(lengthoffset)) length_used = FALSE;
  else length_used = TRUE;
  
  ret = '';
  ret += pad8(l:strlen(ret) + wsp_msg_idx); # pad to 8
  
  ret += g;                       # CFullPropSpec (GUID)
  ret += raw_dword(d:kind);       # ulKind
  ret += raw_dword(d:id);         # propid
  
  ret += raw_dword(d:vt);         # vType
  ret += raw_byte(b:1);           # AggregateUsed / AggregateStored
  ret += raw_byte(b:0);           # AggregateType
  
  if (value_used)
  {
    ret += raw_byte(b:1);                 # ValueUsed
    ret += pad2(l:strlen(ret) + wsp_msg_idx); # padding1
    ret += raw_word(w:valoffset);         # ValueOffset
    ret += raw_word(w:valsize);           # ValueSize
  }
  else
  {
    ret += raw_byte(b:0);                 # ValueUsed
  }
  
  if (status_used)
  {
    ret += raw_byte(b:1);                 # StatusUsed
    ret += pad2(l:strlen(ret) + wsp_msg_idx); # padding2
    ret += raw_word(w:statusoffset);      # StatusOffset
  }
  else
  {
    ret += raw_byte(b:0);                 # StatusUsed
  }
  
  if (length_used)
  {
    ret += raw_byte(b:1);                 # LengthUsed
    ret += pad2(l:strlen(ret) + wsp_msg_idx); # padding3
    ret += raw_word(w:lengthoffset);      # LengthOffset
  }
  else
  {
    ret += raw_byte(b:0);                 # LengthUsed
  }
  
  wsp_msg_idx += strlen(ret);
  
  return ret;
}

function Property(g,kind,id,v,l)
{
  local_var ret;

  ret = '';
                              # pad to 8
  if ((wsp_msg_idx + strlen(ret)) % 8 != 0)
  {
    ret += crap(data:'\x00', length:(8 - ((wsp_msg_idx + strlen(ret)) % 8)));
  }
  
  ret += g;                   # CFullPropSpec (GUID)
  ret += raw_dword(d:kind);   # ulKind
  ret += raw_dword(d:id);     # propid
  
  ret += MakeVTStr(s:v);      # prval
  if ((wsp_msg_idx + strlen(ret)) % 4 != 0)
  {
    ret += crap(data:'\x00', length:(4 - ((wsp_msg_idx + strlen(ret)) % 4)));
  }
  
  ret += raw_dword(d:l);      # lcid
  
  wsp_msg_idx += strlen(ret);     # pad to 4
  return ret;
}

function PropertyRestriction(op)
{
  local_var ret;
  ret = raw_dword(d:op);   # relop
  wsp_msg_idx += strlen(ret);
  return ret;
}

function WSP_RTNot(w)
{
  local_var ret;
  ret = raw_dword(d:RTNot)  + # ulType
        raw_dword(d:w);       # Weight
  wsp_msg_idx += strlen(ret);
  return ret;
}

function WSP_RTContent(w)
{
  local_var ret;
  ret = raw_dword(d:RTContent)  + # ulType
        raw_dword(d:w);           # Weight
  wsp_msg_idx += strlen(ret);
  return ret;
}

function WSP_RTNone(w)
{
  local_var ret;
  ret = raw_dword(d:RTNone) + # ulType
        raw_dword(d:w);    # Weight
  wsp_msg_idx += strlen(ret);
  return ret;
}

function WSP_RTOr(w,rw)
{
  local_var ret;
  ret = raw_dword(d:RTOr)   + # ulType
        raw_dword(d:w)   + # Weight
        raw_dword(d:rw);       # CNodeRestriction, weight
  wsp_msg_idx += strlen(ret);
  return ret;
}

function WSP_RTAnd(w,rw)
{
  local_var ret;
  ret = raw_dword(d:RTAnd)   + # ulType
        raw_dword(d:w)       + # Weight
        raw_dword(d:rw);       # CNodeRestriction, weight
  wsp_msg_idx += strlen(ret);
  return ret;
}

function WSP_RTCoerce_Absolute(w,rv)
{
  local_var ret;
  
  ret = raw_dword(d:RTCoerce_Absolute)  + # ulType
        raw_dword(d:w)                  + # Weight
        raw_dword(d:rv);                  # value (IEEE float, 880)

  wsp_msg_idx += strlen(ret);
  return ret;
}

function WSP_RTProperty(w)
{
  local_var ret;
  ret = raw_dword(d:RTProperty)   + # ulType
        raw_dword(d:w);             # Weight
  wsp_msg_idx += strlen(ret);
  return ret;
}

function WSP_MakeRTProperty(weight, guid, propid, val)
{
  local_var ret;
  
  ret = raw_dword(d:RTProperty)   + # ulType
        raw_dword(d:weight);        # Weight
  
  ret +=raw_dword(d:4);             # relop
  
  if ((wsp_msg_idx + strlen(ret)) % 8 != 0)
  {
    ret += crap(data:'\x00', length:(8 - ((wsp_msg_idx + strlen(ret)) % 8)));
  }
  
  ret +=guid                    + # GUID
        raw_dword(d:PRSPEC_PROPID)  + # ulKind
        raw_dword(d:propid)     + # propid
        MakeVTStr(s:val)        + # prval
        raw_dword(d:0x409);       # lcid
  
  wsp_msg_idx += strlen(ret);
  return ret;
}

function WSP_MakeRTContent(weight, name)
{
  local_var ret;
  
  ret = raw_dword(d:RTContent)  + # ulType
        raw_dword(d:weight);      # Weight
  
  if ((wsp_msg_idx + strlen(ret)) % 8 != 0)
  {
    ret += crap(data:'\x00', length:(8 - ((wsp_msg_idx + strlen(ret)) % 8)));
  }
  
  ret +=GUID_Query              + # GUID
        raw_dword(d:PRSPEC_PROPID)  + # ulKind
        raw_dword(d:6)          + # propid
        MakeCString(s:name)     + # phrase
        raw_dword(d:0x409)      + # lcid
        raw_dword(d:0);           # method

  wsp_msg_idx += strlen(ret);
  return ret;
}

function MakeVTStr(s)
{
  return  raw_word(w:0x1f)  + # vType
          raw_byte(b:0)     + # vData1
          raw_byte(b:0)     + # vData2
          MakeCString(s: s+'\x00');
}

function MakeCString(s)
{
  local_var ret;
  ret = raw_dword(d:strlen(s))  + # Length
        mk_unicode(str:s);
  ret += pad4(l:strlen(ret) + wsp_msg_idx);
  return ret;
}

function pad2(l)
{
  if (l % 2 != 0)
  {
    return crap(data:'\x00', length: 2 - (l % 2));
  }
  return '';
}

function pad4(l)
{
  if (l % 4 != 0)
  {
    return crap(data:'\x00', length: 4 - (l % 4));
  }
  return '';
}

function pad8(l)
{
  if (l % 8 != 0)
  {
    return crap(data:'\x00', length:(8 - (l % 8)));
  }
  return '';
}

function WSP_FreeCursor(c)
{
  local_var data, pkt;
  data = raw_dword(d:c);
  wsp_msg_idx = 4;
  
  pkt = WSP_Header(msgid:CPMFreeCursor, data:data, ck:FALSE);
  pkt += data;
  return pkt;
}

function WSP_ParseOutput(d)
{
  local_var msgid, status;
  if (strlen(d) >= 16)
  {
    msgid = get_dword(blob:d, pos:0);
    status = get_dword(blob:d, pos:4);
    
    return make_list(msgid, status);
  }
  
  return NULL;
}

function WSP_CPMSetBindings(c,s)
{
  local_var data, pkt;
  local_var num_cols, col_data;
  
  num_cols = 1;
  wsp_msg_idx = 0x14; # 14h header bytes
  col_data = WSP_CTableColumn(g:GUID_Storage,kind:PRSPEC_PROPID,id:0xb,vt:VT_VARIANT,valoffset:8,valsize:0x18,statusoffset:2,lengthoffset:4); # Path
  col_data += pad4(l:wsp_msg_idx);
  
  data =  raw_dword(d:c);                     # hCursor
  data += raw_dword(d:s);                     # cbRow
  data += raw_dword(d:strlen(col_data) + 4);  # cbBindingDesc
  data += raw_dword(d:0xff0b0b07);            # dummy
  data += raw_dword(d:num_cols);              # cColumns
  
  data += col_data;                 # aColumns (var)
  
  
  pkt = WSP_Header(msgid:CPMSetBindings, data:data);
  pkt += data;
  return pkt;
}

function WSP_CPMCreateQuery(host,share)
{
  local_var data, pkt;
  
  wsp_msg_idx = 4; # Size will be prepended
  data =  raw_byte(b:1)               + # CColumnSetPresent
          crap(data:'\x00', length:3);  # Padding
  data += WSP_MakeColumnSet(lst:mklist(0));
  data += raw_byte(b:1);                # CRestrictionPresent
  wsp_msg_idx += strlen(data);
  
  data += WSP_MakeRestrictionArray(h:host,path:share);
  
  data += raw_byte(b:0)               + # CSortPresent
          # SortSet
          raw_byte(b:0);                # CCategorizationSetPresent
          #CCategorizationSet
  
  data += pad4(l:strlen(data) + wsp_msg_idx);
  wsp_msg_idx = strlen(data)+4;
  
  data += WSP_DefaultRowSet();
  wsp_msg_idx = strlen(data)+4;
  data += WSP_DefaultPidMapper();
  wsp_msg_idx = strlen(data)+4;
  data += WSP_NullGroupArray();
  data += raw_dword(d:0x409);           # Lcid

  data =  raw_dword(d:strlen(data)+4)   + # CreateQuery size
          data;
          
  pkt = WSP_Header(msgid:CPMCreateQuery, data:data);
  pkt += data;
  return pkt;
}

function WSP_DefaultRowSetProperties()
{
  return 
    raw_dword(d:0x804003) + # uBooleanOptions
    raw_dword(d:0)        + # ulMaxOpenRows
    raw_dword(d:0)        + # ulMemUsage
    raw_dword(d:0)        + # cMaxResults
    raw_dword(d:0);         # cCmdTimeout
}

function WSP_MinimalPidMapper(l)
{
  local_var ret;
  ret =
    raw_dword(d:1);               # PidMapper count

  if ((l + strlen(ret)) % 8 != 0)
  {
    ret += crap(data:'\x00', length:(8 - (l + strlen(ret)) % 8));
  }
  
  ret +=
    GUID_Storage                + # PropSpec[0] GUID
    raw_dword(d:PRSPEC_PROPID)  + # PropSpec[0] ulKind
    raw_dword(d:0xA);             # PropSpec[0] propid
  return ret;
}

function WSP_DefaultPidMapper()
{
  local_var ret;
  
  ret = raw_dword(d:3);                 # PidMapper count
  ret += pad8(l:strlen(ret) + wsp_msg_idx); # padding to 8
  ret +=
    GUID_Storage                + # PropSpec[0] GUID
    raw_dword(d:PRSPEC_PROPID)  + # PropSpec[0] ulKind
    raw_dword(d:0xB);             # PropSpec[0] propid    Windows path
    
  ret += pad8(l:strlen(ret) + wsp_msg_idx); # padding to 8
  ret +=
    GUID_Storage                + # PropSpec[1] GUID
    raw_dword(d:PRSPEC_PROPID)  + # PropSpec[1] ulKind
    raw_dword(d:0x16);            # PropSpec[1] propid    Windows scope

  ret += pad8(l:strlen(ret) + wsp_msg_idx); # padding to 8
  ret +=
    GUID_Query                  + # PropSpec[2] GUID
    raw_dword(d:PRSPEC_PROPID)  + # PropSpec[2] ulKind
    raw_dword(d:6);               # PropSpec[2] propid    all properties

  return ret;
}

function WSP_DefaultRowSet()
{
  local_var ret;
  
  ret =  raw_dword(d:1);    # uBooleanOptions
  ret += raw_dword(d:0);    # ulMaxOpenRows
  ret += raw_dword(d:0);    # ulMemoryUsage
  ret += raw_dword(d:0);    # cMaxResults
  ret += raw_dword(d:0x1e); # cCmdTimeOut
  
  return ret;
}

function WSP_NullGroupArray()
{
  return raw_dword(d:0);  # GroupArray count
}

function WSP_CPMConnect()
{
  local_var data, pkt;
  data = get_cpmconnectin();
  pkt = WSP_Header(msgid:CPMConnect, data:data);
  pkt += data;
  return pkt;
}

function WSP_Header(msgid, data, ck)
{
  local_var hdr, cksum;
  if (isnull(ck)) cksum = TRUE;
  else cksum = ck;
  hdr = raw_dword(d:msgid)       + # Message Id
         raw_dword(d:S_OK);        # Status (S_OK)
  if (cksum)
    hdr += raw_dword(d:WSP_Checksum(msg:msgid, d:data));   # CRC
  else
    hdr += raw_dword(d:0);        # CRC
  hdr += raw_dword(d:0);          # Reserved
  return hdr;
}

function get_cpmconnectin()
{
  return
  '\x00\x07\x01\x00\x01\x00\x00\x00\x60\x01\x00\x00\x00\x00\x00\x00' +
  '\x24\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x4E\x00\x45\x00\x53\x00\x53\x00\x55\x00\x53\x00\x00\x00\x6F\x00' +
  '\x76\x00\x65\x00\x72\x00\x66\x00\x6C\x00\x6F\x00\x77\x00\x69\x00' +
  '\x6E\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x26\x15\xbd\xa9' +
  '\x80\x6a\xd0\x11\x8c\x9d\x00\x20\xaf\x1d\x74\x0e\x04\x00\x00\x00' +
  '\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x1f\x00\x00\x00\x14\x00\x00\x00\x57\x00\x69\x00' +
  '\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x5c\x00\x53\x00\x79\x00' +
  '\x73\x00\x74\x00\x65\x00\x6d\x00\x49\x00\x6e\x00\x64\x00\x65\x00' +
  '\x78\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00' +
  '\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x10\x00\x00' +
  '\x01\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x10\x00\x00' +
  '\x01\x00\x00\x00\x02\x00\x00\x00\x2f\x00\x00\x00\xa5\xac\xaf\xaf' +
  '\xd1\xb5\xd0\x11\x8c\x62\x00\xc0\x4f\xc2\xdb\x8d\x01\x00\x00\x00' +
  '\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x08\x00\x00\x00\x1c\x00\x00\x00\x30\x00\x2e\x00' +
  '\x32\x00\x35\x00\x35\x00\x2e\x00\x32\x00\x35\x00\x35\x00\x2e\x00' +
  '\x32\x00\x35\x00\x35\x00\x00\x00\x04\x00\x00\x00\xb0\xe6\x6e\xaa' +
  '\x28\xe8\xd0\x11\xb2\x3e\x00\xaa\x00\x47\xfc\x01\x0d\x00\x00\x00' +
  '\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x08\x00\x00\x00\x06\x00\x00\x00\x45\x00\x4e\x00' +
  '\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00' +
  '\x02\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00' +
  '\x02\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00' +
  '\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00' +
  '\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x00\x00\x00' +
  '\x00\x00\x00\x00\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00' +
  '\x00\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00' +
  '\x00\x00\x00\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00' +
  '\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00' +
  '\x00\x00\x00\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00' +
  '\x00\x00\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00' +
  '\xff\xff\xed\x77\xac\xa7\xd7\xf8\xce\x11\xa7\x98\x00\x20\xf8\x00' +
  '\x80\x25\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00' +
  '\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00' +
  '\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00' +
  '\xff\xff\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00' +
  '\x00\x00\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00' +
  '\x02\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00' +
  '\x00\x00\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00' +
  '\x00\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00' +
  '\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00' +
  '\x00\x00\x00\x00\x0d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00' +
  '\x00\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00' +
  '\x00\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00' +
  '\xff\xff\xa5\xac\xaf\xaf\xd1\xb5\xd0\x11\x8c\x62\x00\xc0\x4f\xc2' +
  '\xdb\x8d\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00' +
  '\x1c\x00\x00\x00\x30\x00\x2e\x00\x32\x00\x35\x00\x35\x00\x2e\x00' +
  '\x32\x00\x35\x00\x35\x00\x2e\x00\x32\x00\x35\x00\x35\x00\x00\x00' +
  '\x26\x15\xbd\xa9\x80\x6a\xd0\x11\x8c\x9d\x00\x20\xaf\x1d\x74\x0e' +
  '\x03\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x20\x00\x00' +
  '\x01\x00\x00\x01\x08\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00' +
  '\x04\x00\x00\x00\x2f\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00' +
  '\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x20\x00\x00' +
  '\x01\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
  '\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00' +
  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00' +
  '\x28\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00' +
  '\x73\x00\x5c\x00\x53\x00\x79\x00\x73\x00\x74\x00\x65\x00\x6d\x00' +
  '\x49\x00\x6e\x00\x64\x00\x65\x00\x78\x00\x00\x00\x00\x00\x00\x00';
}

function WSP_Checksum(msg, d)
{
  local_var i, ret;
  ret = 0;
  for (i = 0; i < strlen(d); i+=4)
  {
    ret += get_dword(blob:d, pos:i);
  }
  ret = (ret & 0xffffffff) ^ 0x59533959;
  ret -= msg;
  return ret;
}

function mk_unicode(str)
{
  local_var i, l, null, res;

  l = strlen(str);
  null = '\x00';
  res = "";

  for (i=0; i < l; i++)
    res += str[i] + null;

  return res;
}

function dword_to_string(d,le)
{
  if (isnull(le) || le == 0)
  {
    return raw_string((d & 0xff000000) >> 24, (d & 0xff0000) >> 16, (d & 0xff00) >> 8, d & 0xff);
  }
  else if (le == 1)
  {
    return raw_string(d & 0xff, (d & 0xff00) >> 8, (d & 0xff0000) >> 16, (d & 0xff000000) >> 24);
  }
}

function dword_to_hex(d,le)
{
  if (isnull(le)) le = 0;
  return hexstr(dword_to_string(d:d,le:le));
}

function wsp_smb_send_recv(fid,data)
{
  local_var ret;
  
  ret = smb2_ioctl(
                  fid:fid,
                  code:FSCTL_PIPE_TRANSCEIVE,
                  data:data
                  );

  if (isnull(ret) || max_index(ret) < 12) return NULL;
  ret = WSP_ParseOutput(d:ret[11]);
  if (isnull(ret) || max_index(ret) < 2) return NULL;
  
  # Return header status
  return ret[1];
}
