#TRUSTED 11cc8199e3798c9ec86660e0276c67c2cf3f53ed2dfe1212990e4759cde3de5a928559608b4a94525a663772a2e2bb12922f0af6709a752f0973454ea4c54f9bde593b7e52c6ef5a22e12dff32b81940cba6c97a7ff553fed9f829b1490921a3235dd5e8f8675749395b0aeadcbfb85a81daf719d30ea371d9a8b567e306ebaff740610ceed57766828ccbf1ddcebe7dfcf456917da7455d7808bc08e764e4e06fd65b40851ef9ddaf9ca68ab01234c3de4ad6c275bcd4de13382b948627a5cd0067f036525f1865dc965bef18f0c2afc6c2dcbe59387bb7ecb2633bbb0b8f35810af4ec1361a4e206a252e25a110c580b714b9368e1cbbcc8ce284cb1fbf19cdccc7e32eba08188dcd6e8a2c5af75303b06cd1faa7d696d547f55a1f9c07e7e8841e9d9a98f6ff1adaca2661934a6e789b60e8dc09e3c5cf31ce239acf85e607193761416ea2175a004ea9dc0940ab796e6c39dcdb8936a5c1816899ad3df4ffe0eed4130cdf63eb244a1e03c4ed39a05018578d055e1c7e939a9dbb81eed50559f19cc6b97fcc262af5613dfca20cc83c870c8c8cb94690bb3af5a4c633fa15db6fe01263062c6d02dece78caab8efb0da53502b771bfca173bbe962d1b03f54d118f3e6687c3d7b3460ec4de32581971292543d1c07b52428fdd54193d3c780787fd6770d3628fdf2d55b43c6e9b1da4eae01cd26d710155718c388a27b70
#TRUST-RSA-SHA256 8a5da0f5a1a2d48bcf19090299cf557c9c0e6a25c13bd40d31fa5e26c043f532548b1e7be430a3e4ead2ceac30eceaffc682d31da01a0fc27c37e2b9d6193231fad6de74d994dda269af95a382d056a0a79863d211f80263a6e1aeba0e460d6e3324999e9a6a0b45ee96af996b3291eddd3c1c2404a7c1217d2e5562910dc6581f80776939e352d82932c4034247e46b107556d05838ac597170b85a534ed1c549ad855dc37afd16b57ec69f73059dd916f3fb6f75b222f0772518d1759e0f7506686b69b9e031005d0052841730f69ca91c64499191aa505d3c3cffcf59ac55a84c0e8df0ed581e64e017695fd6c322cf3a558cfae059bb03e9f8f4a710223cf70d924a42e23588d0d79ea249e432703301c2f722a776e0f88a04511023d8a6029393c7dfaa271bbb8f5b083c4a5c3e49fc1237395b1a02c23b29b8b99667c7b772dbc38f7f7eacb6310c970b9e4206a7fd019e099c94f9b4674618e71d20abdd16b160cbf19d893dc34bb4762df96fa7b3e4082260bff68db4e9d7772cb3c12e1c7e94d164162c0c9b0f6b3320540b2c28eecd19ffab1c66e14f75f0909773fa6959a27afd93efb478607698765b5f1d71a4cac5d03888fa9a07267b79c6fb0387ba0f17065bd69d7002a4cc7f042260e5b11a0d8097aabbef13c9ba39b12d4bb4c46074a840de37766bea69ebb8d7bf7a5371fc35703666cd4df862d6ac1a
# -*- Fundamental -*-
# 
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# dns_func.inc 
#
# Revision: 1.16
#

include("compat_shared.inc");
include("byte_func.inc");
include("raw.inc");

global_var DNS_QTYPE_PTR         = 12;
global_var DNS_QTYPE_SRV         = 33;
global_var DNS_QTYPE_TXT         = 16;
global_var DNS_QTYPE_A           = 1;
global_var DNS_QTYPE_AAAA        = 28;
global_var DNS_QTYPE_HINFO       = 13;
global_var DNS_QTYPE_ANY         = 255;
global_var DNS_QTYPE_RRSIG       = 46;
global_var DNS_QTYPE_NSEC        = 47;
global_var DNS_QTYPE_DNSKEY      = 48;

global_var DNS_QCLASS_IN         = 1;
global_var DNS_QCLASS_CH         = 3;

# https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
global_var DNS_RCODES = [
  'NoError',  # 0
  'FormErr',
  'ServFail',
  'NXDomain',
  'NotImp',
  'Refused',
  'YXDomain',
  'YXRRSet',
  'NXRRSet',
  'NotAuth',
  'NotZone',  # 10
  'DSOTYPENI',
  '',         # Unassigned
  '',         # Unassigned
  '',         # Unassigned
  '',         # Unassigned
  'BADVERS / BADSIG',
  'BADKEY',
  'BADTIME',
  'BADMODE',
  'BADNAME', # 20
  'BADALG',
  'BADTRUNC',
  'BADCOOKIE'
];

global_var dns_struct = make_list("transaction_id",
		       "flags",
			"q",
			"an_rr",
			"au_rr",
			"ad_rr");


global_var dns_sizes = make_array("transaction_id",     16,
			"flags",	     16,
			"q",		     16,
			"an_rr",	     16,
			"au_rr",	     16,
			"ad_rr",	     16);


function get_query_txt()
{
 local_var s, l;
 s = _FCT_ANON_ARGS[0];
 if ( isnull(s) ) return NULL;
 l = ord(s[0]);
 return substr(s, 1, l);
}


function get_full_query_txt()
{
 local_var s, l;
 local_var ret;

 s = _FCT_ANON_ARGS[0];
 if ( isnull(s) ) return NULL;
 
 while ( strlen(s) )
 { 
 l = ord(s[0]);
 if ( strlen(ret) > 0 ) ret += ".";
 ret += substr(s, 1, l);
 s = substr(s, l + 1, strlen(s) - 1 );
 }
 return ret;

}

function mk_query_txt()
{
 local_var i, ret;
 for ( i = 0 ; _FCT_ANON_ARGS[i] ; i ++ )
 {
   ret += raw_string(strlen(_FCT_ANON_ARGS[i])) + _FCT_ANON_ARGS[i];
 }
 return ret + raw_string(0);
}

function mk_query(txt, type, class)
{
 return txt + raw_string(type >> 8,  type & 0xff, class >> 8, class & 0xff); 
}

function mk_dns_request(str, type, class, flags, dnssec, is_tcp)
{
 local_var tmp;

 if(isnull(is_tcp)) is_tcp = FALSE;

 # By default assume a standard query.
 if ( isnull(flags) ) flags = 0x100;

 # By default assume class IN as it is nearly universal. 
 if ( isnull(class) ) class = DNS_QCLASS_IN;

 # By default do not request a DNSSEC response.
 if ( isnull(dnssec) ) dnssec = FALSE;

 local_var dns, query;
 dns = make_array("transaction_id", rand() % 65536,
                  "flags",          flags,
                  "q",              1);
 query = mk_query(txt:dns_str_to_query_txt(str), class:class, type:type);

 if(is_tcp)
 {
   tmp = mkdns(dns:dns, query:query, dnssec:dnssec);
   return mkword(strlen(tmp)) + tmp; 
 }
 else
   return mkdns(dns:dns, query:query, dnssec:dnssec);
}

function mkdns(dns, query, dnssec)
{
 # If dnssec is requested, we add an additional RR.
 if ( isnull(dns["ad_rr"]) ) dns["ad_rr"] = 0;
 if ( dnssec ) dns["ad_rr"] = dns["ad_rr"] + 1;

 local_var item, ret;
 foreach item ( dns_struct )
 {
  ret += raw_string(dns[item] >> 8, dns[item] & 0xff);
 }

 ret += query;

 # Add the RR that declares our acceptance of DNSSEC.
 if ( dnssec )
 {
  ret += raw_string(
    0,        # Name: <Root>
    0, 0x29,  # Type: OPT (EDNS0 option)
    0x10, 0,  # UDP payload size: 4096
    0,
    0,        # EDNS0 version: 0
    0x80, 0,  # Accept DNSSEC security RRs
    0, 0      # Data length: 0
  ); 
 }

 return ret;
}

function dns_comp_get(str, offset, rec)
{
 local_var i, o, l, ret;


 if ( ! rec ) rec = 0;
 if ( rec > 4 ) exit(0);

 o = offset;

 while ( TRUE )
 {
  if ( o >= strlen(str) ) break;
  l = ord(str[o]);
  if ( (l & 0xc0) == 0xc0 && (o + 1) < strlen(str) ) {
	o = ord(str[o+1]);
	ret += dns_comp_get(str:str, offset:((l & ~0xc0) << 8) | o, rec:rec+1);
	break;
	}
  else
  {
   if ( o + l > strlen(str) ) return NULL;
   ret += substr(str, o + 1, o + l);
   if ( ord(str[o+l]) == 0 ) break;
   else ret += '.';
   o += l + 1;
  }
 }
 return ret;
}

function dns_str_get(str, blob)
{
 local_var ret, l, offset;

 offset = 0;
 while ( TRUE )
 {
  if ( ( ord(str[offset]) & 0xc0 ) == 0xc0 ) 
	{
	offset = ord(str[offset+1]);
	if ( ret ) return ret + '.' + dns_comp_get(str:blob, offset:offset);
	else return dns_comp_get(str:blob, offset:offset);
	}
   
   l = ord(str[offset]);
   if ( offset + l > strlen(str) ) return ret;
   if( ret) ret += '.' + substr(str, offset + 1, offset + l ); 
   else     ret +=       substr(str, offset + 1, offset + l ); 
   if ( ord(str[offset+l]) == 0 ) break;
   offset += l + 1;
 }
 return ret;
}

# The section arg is one of an, ad, or au (answer, additional, authorized)
function dns_data_get(type, section, response)
{
 local_var contents, ret;
 local_var i, j;
 contents = dns_split(response);
 if (isnull(contents))
 {
   err_print("dns_data_get: response argument must be a valid DNS response");
   return NULL;
 }
 ret = make_list();
 
 j = 0;
 for (i = 0; i < contents[section+"_rr"]; i++)
 {
   local_var actual_type;
   actual_type = contents[section+'_rr_data_'+i+'_type'];
 
   if (actual_type == type)
     ret[j++] = contents[section+"_rr_data_"+i+"_data"];
 }
 
 return ret;
}

function dns_str_to_query_txt()
{
 local_var p, ret;
 ret = "";
 foreach p (split(_FCT_ANON_ARGS[0], sep:".", keep:FALSE))
  ret += raw_string(strlen(p) % 255) + p;
 return ret + raw_string(0);
}


function dns_split()
{
 local_var ret, n, m, item, ptr, p, cur, t, l;
 local_var names, offset, i, tmp, o;


 if ( isnull(_FCT_ANON_ARGS[0])) exit(0);
 p   = _FCT_ANON_ARGS[0];

 ptr = 0;
 foreach item ( dns_struct )
 {
  if ( ptr >= strlen(p) ) return NULL;
  ret[item] = getword(blob:p, pos:ptr);
  ptr += 2;
 }

 foreach item ( make_list("q", "an_rr", "au_rr", "ad_rr") )
 {
  for ( n = 0 ; n < ret[item] ; n ++ )
  {
   t = '';
   cur = item + "_data_" + n;
   while ( TRUE )
   {
    if ( ptr >= strlen(p) ) return ret;
    m = ord(p[ptr]);
    if ( (m & 0xc0) == 0xc0 ) # Compression
     {
      if ( strlen(t) ) t += ".";
      t += dns_comp_get(str:p, offset:ptr);
      ptr ++;
      m  = 0;
     }

    if ( m == 0 ) {
		ptr ++;
		ret[cur + "_name"] = t;
		if ( ptr + 2 >= strlen(p) ) break;
		ret[cur + "_type"] = getword(blob:p, pos:ptr);
		ptr += 2;
		if ( ptr + 2 >= strlen(p) ) break;
		ret[cur + "_class"] = getword(blob:p, pos:ptr);
		ptr += 2;
		if ( item != "q" )
		{
		 if ( ptr >= strlen(p) ) break;
		 ret[cur + "_ttl"] = getdword(blob:p, pos:ptr);
		 ptr += 4;
		 if ( ptr + 4>= strlen(p) ) break;
		 l = getword(blob:p, pos:ptr);
		 ptr += 2;
		 ret[cur + "_data"] = substr(p, ptr, ptr + l - 1);
		 ret[cur + "_data_offset"] = ptr;
		 ptr += l;
		}
		t = NULL;
		break;   
	}
    else {
	 if ( t ) t += ".";
	 else offset = ptr;

	 ptr ++;
	 t += substr(p, ptr,ptr +  m - 1);
	 ptr = ptr + m;
	}
    }
  }
 }

 return ret;
}
