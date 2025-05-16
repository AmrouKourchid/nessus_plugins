#TRUSTED 3bcb047d95660a065e2169071e880dd2d5cd86dc076cab36a0e069ba020691cc5be5fea3470535c1132035902eb50f305926c4006d25e110d9d3889f6d294e21c74a6902def4a5b6c170ba04424eb61ba4fe36dbed442ddf23c459e0a5e56ccbffde1a349175e10899b885abe12ff99fd3623eb4276939e3874b0bf00b1be1b4a34c3e9932254795564773a2b2b3135258ec093668d2344aa3c3700c199a779f774adba547190c453f9bb66105686920ecd8285b95dcc68022405caa39eac497bbb7a66ebd1235b7a342f91444c29d6846f48a21c10285e182996043ce797aacd4669364245fde316a04272fcc95f83b47e6b0473512f2c8365b95864283754160c66ce873322e300f708732bcd84f0a164acebb52f429c793fe9773a77b324cd308f7f68c6d39eb9499e88cf438c0ae26134fe805a9bd7c13f9633d71fe7d58e8993e1fb66304228f96e28a2904355c90d3c5bef36e6d68e60025770dcd878e90240d56b7b68b4c6f21c8dba23569ab8de0321cd216b02732d650aa1dc907d8891ffd8f4a31422e612ee72c2197181b387e136628e3a961379e0dcc217e3c4292dcadb83639ba3cb1f317ba46dc777e339668ea5243136dd09586d3136a99482833f722a6d73e232a982c466b6c8c457a95855f2bead673a4eb4ac1fe9872b3db7fdfc8321f42445b4b4ff0a43d5f4daaee9983d11c148f046ae6eb3eb57d29
#TRUST-RSA-SHA256 4ff1dbffb7b332a9541db9834d69817956309c10309d944be8c85aa5f3577774b7ae852a9c248d4d8d2101cb8a0c0bb5bb6db849528757f8d81cfba04ec8f30975131d13739296eaa4d2f2c7a29139549d715ac461eeb4a1844c80ae8b93153f80408cf16f6dd144b46300435cdbd7780afee417749989d0bfb7a570f85eb5d5bf64547602d7144e2b889a61bd2d1646054377b3bbaaa766a967e4fcad18939f1030d52c63b77883a93f8d5646c70f272fdf2264b4053e1dc18a72e5d9442f55c56083018be3aa57e75f12811d2b646e9f6d231d72812eb40fb3680d1dd4961092e9aa89340eaa847fcf8d216e543a812a58c1721f10a3c59f70653e7aaeab3165b2f117ba5cae07b7d40fc4c966eec07055bb36ae4d66a95ba41d098f8709444d67f6ec3b14567d976f2052e8b79e7753855d207646d6b5499ab7d95e0efd79a8156c56c5f05ab0a97136e58bab75f5cc89fafffc547e67a68411205cd2a893609046eb120d7e1ca9e1e2638cca584afe99e7fced91721123ef729b130ee067fb9839ece7ecc007132f39318d7a22a7b0431190d9d8f99217116721992a551709900be6fb223907da414fad17e4a8c14b47a861e5ca8377bc4b0e0dbc5f6cad9a1c6a4be469599674d7003516eb9ebe2ef49e53da5635fcd1cbd3ca12378739c51d0c3221c70ee2f2ad603d66c1d25ebec8dd8758459d8f80f85fc097e2bc6f
# -*- Fundamental -*-
###
# Functions for handling URIs
#
# (C) Tenable Network Security, Inc.
#
# uri_func.inc
# Revision: 1.13
#
# @NOGPL@
#
###

include("compat_shared.inc");

##
# URL decodes the given string
#
# This function assumes 'estr' is encoded per RFC 3986 and decodes it.
#
# @param [estr:string] URL encoded string
# @return [string] decoded version of "estr"
##
function urldecode(estr)
{
  local_var ch, len, i, str;

  str = "";
  len = strlen(estr);

  i = 0;
  while (i < len)
  {
    ch = estr[i];
    if (ch == "+") ch = " ";

    if (ch == "%" && substr(estr, i+1, i+2) =~ "^[0-9a-fA-F]{2}$")
    {
      # nb: hex2raw() expects only lowercase hex digits!
      str += hex2raw(s:tolower(substr(estr, i+1, i+2)));
      i += 2;
    }
    else str += ch;
    i++;
  }

  return str;
}


global_var HEX_LOWERCASE, HEX_UPPERCASE;

HEX_LOWERCASE = 1;
HEX_UPPERCASE = 2;

##
# URL encodes the given string
#
# 'str' is encoded per RFC 3986
#
# @param [str:string] string to URL encode
# @param [unreserved:string] a string containing characters that should not be encoded. this parameter
#        is optional - if no argument is provided, the default is used (alphanumeric and _.~-)
# @param [case_type:int] if HEX_UPPERCASE, specifies hex of encoded characters should be upper case. otherwise, all hex is lowercase
#
# @return [string] URL encoded version of "str"
##
function urlencode(str, unreserved, case_type)
{
  local_var ch, estr, len, i;

  estr = "";
  len = strlen(str);
  if (isnull(unreserved)) unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.~-";
  if (isnull(case_type)) case_type = HEX_LOWERCASE;

  for (i=0; i<len; i+=1)
  {
    ch = str[i];

    if (ch >< unreserved) estr += ch;
    # the rest are escaped.
    else
    {
      ch = hexstr(ch);
      if (case_type == HEX_UPPERCASE)
        ch = toupper(ch);
      estr += "%" + ch;
    }
  }

  return estr;
}

##
# Purl components that are not percent encoded are governed by a set of rules.
# These rules specify that the segment must contain only letters, numbers, or
# the period, plus or dash characters.  They must not start with a number and
# cannot contain spaces.  This function evaluates the input Purl string against
# these rules.
#
# @param [pstr:string] The string to be evaluated.
# @return [TRUE|FALSE] Returns TRUE if the string is conformant, FALSE otherwise.
##
function is_purl_clean(pstr)
{
  if(pstr =~ "^[a-zA-Z.+-][a-zA-Z0-9.+-]*$")
    return TRUE;

  return FALSE;
}

##
# Generates a package url (purl) that is compliant with the purl spec:
# https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst
#
# @param [type:string]       The purl type
# @param [nspace:string]     (optional) Purl namespace; hierarchical elements separated by '/'
# @param [name:string]       Name of the package target of this purl
# @param [version:string]    (optional) Version of the package target
# @param [qualifiers:array] (optional) Name/value pairs in a query string separated by '&', no leading '?'
#
# @return [string|NULL] Returns a compliant purl that resolves to particular package version
##
function generate_purl(type, nspace, name, version, qualifiers)
{
  var purl = "pkg:";

  if(empty_or_null(type) || empty_or_null(name))
    return NULL;

  if(!is_purl_clean(pstr:type))
    return NULL;

  purl += type + "/";

  var nspaces = split(nspace, sep:'/', keep:FALSE);
  for(var n of nspaces)
  {
    if(empty_or_null(n))
      continue;

    purl += urlencode(str:n) + "/";
  }

  purl += urlencode(str:name);

  if(!empty_or_null(version))
    purl += "@" + urlencode(str:version);

  if(!empty_or_null(qualifiers) && typeof(qualifiers) == "array")
  {
    var qname, value;
    var pqs = '';
    for(qname of keys(qualifiers))
    {
      if(!empty_or_null(pqs))
        pqs += "&";

      if(typeof(qualifiers[qname]) != "string" &&
         typeof(qualifiers[qname]) != "int" &&
         typeof(qualifiers[qname]) != "data")
        return NULL;

      value = string(qualifiers[qname]);
      if(!is_purl_clean(pstr:qname))
        return NULL;

      pqs += qname + "=" + urlencode(str:value);
    }

    if(!empty_or_null(pqs))
      purl += "?" + pqs;
  }

  return purl;
}

