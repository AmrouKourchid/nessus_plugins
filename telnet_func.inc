#TRUSTED 2e9c03ea90a87337771f6004127b3467dc79dfdf831b2a696ac72497b0ade97d6fbfa03460bd7b2db57f70b2c739348cf68e48696bfe367e34c95ace7e14932a8f9de98f0f134baf0ae558c78d4f51a8ad30b534b93906aeadbc9c1da4d84946da6ccf5b9ccce4aba0f44bb4a86796f18ece789dc6b8d1b1c361ece9f4169c0eb853a52df5a0147868280f21cdeb9bd5d26342ae5c1460a5aa844817b74d27c3c5c6e873834ca5eae9ac27da5e3ffc21200e89b3c2b5c42436d4810d56464a4ff2056100b55d55d9c3f0dec9f3f13587b22dde5ee86754a3fe4b4e04aa89c5f1b05648b27e05bd4915c6bd0ae3b4b6faaa4773e655fb063d5a3a45624a54eaa0b53f7d6bd1af4f0c1f7c21cea612f5be70a1cf2309a64bc8db5443995e6389905f7d0220aab0e278507628283d77a6f3128912e5e9f4eb0b778f258e0c1f5be9a6bdb74ac443b727db8909b87299b8a2f1a85fc3abc51f1981f69e77cd6ab96819cc254276b4a0e7b69ad999a5fa717bd49ee3ffad3ada3be686f5fcdcbac4f6c144a27da5e0cc477ee2faacf5d5edbf1868949112ebf5299f9ad67350b75b9cbf4863292fafd0f8670c9acce8e230a6c902955a918a331f4aff862e43039e11107474fa4d6df41781bc8ec52086ac4e9ae2ac7ffe83035bfa5a9a9f41b4cbf597e9bad20ec68c64288f99e0232f4b5577d0d9ea99c90dc30db3a6dff773d951
#
# (C) Tenable Network Security, Inc.
#
#
# Revision: 1.25
#

var OPT_WILL 	= 0xfb;
var OPT_WONT 	= 0xfc;
var OPT_DO   	= 0xfd;
var OPT_DONT 	= 0xfe;

var OPT_SUBOPT 	= 0xfa;
var OPT_ENDSUBOPT 	= 0xf0;

function get_telnet_banner(port)
{
  local_var sb, banner, soc;
  sb = 'Services/telnet/banner/'+port;
  banner = get_kb_item(sb);
  if (banner) return(banner);

  soc = open_sock_tcp(port);
  if(!soc) return (0);
  banner = telnet_negotiate(socket:soc);
  close(soc);
  if(strlen(banner))
		replace_kb_item(name: sb, value: str_replace(find:raw_string(0), replace:'', string:banner));
  return(banner);
}


function telnet_negotiate(socket, pattern)
{
 local_var opt, code, s, counter, counter2, buf, prev, timeout;

 counter = 0;
 timeout = int(get_preference("checks_read_timeout"));
 if ( timeout <= 0 ) timeout = 5;

 while ( TRUE )
 {
  s   = recv(socket:socket, length:1, timeout:timeout);
  if ( !strlen(s) ) break;
  if ( ord(s[0]) != 0xff) {
	 buf += s;
         if ( pattern && egrep(pattern:pattern, string:buf) ) break;
	 }
  else {
   counter ++;
   s  = recv(socket:socket, length:2);

   if ( ord(s[0]) == OPT_DO ) send(socket:socket,data:raw_string(0xff, OPT_WONT) + s[1]);
   else if ( ord(s[0]) == OPT_WILL ) send(socket:socket,data:raw_string(0xff, OPT_DONT) + s[1]);
   else if ( ord(s[0]) == OPT_SUBOPT )
	{
	 prev = recv(socket:socket, length:1);
         counter2 = 0;
	 while ( ord(prev) != 0xff && ord(s[0]) != OPT_ENDSUBOPT )
	   {
	    prev = s;
 	    # No timeout - the answer is supposed to be cached
	    s    = recv(socket:socket, length:1, timeout:0);
	    if ( ! strlen(s) ) return buf;
	    counter2++;
	    if ( counter2 >= 100 ) return buf;
	   }
	}

   # Not necessary and may introduce endless loops
   #if ( ord(s[0]) == OPT_DONT ) send(socket:socket,data:raw_string(0xff, OPT_WONT) + s[1]);
   #if ( ord(s[0]) == OPT_WONT ) send(socket:socket,data:raw_string(0xff, OPT_DONT) + s[1]);
  }
  if ( counter >= 100 || strlen(buf) >= 4096 ) break;
 }

 return buf;
}

function set_telnet_banner(port, banner)
{
  replace_kb_item(name:'Services/telnet/banner/' + port, value: str_replace(find:raw_string(0), replace:'', string:banner));
}

# (C) Tenable Security

function recv_until(socket, pattern)
{
 local_var r, i, l, buf;
 i = 0; l = 0;

#debug_print('recv_until(pattern=', pattern, ')\n');
 while ( TRUE )
 {
  i ++;
  if ( i > 1024*1024 ) return NULL;
  r = recv(socket:socket, length:1);
  if ( strlen(r) == 0 ) break;
  if (r == '\0') continue;
  l ++;
  buf += r;
  # Regex size is limited?
  if (l <= 256)
  {
   if ( egrep(pattern:pattern,string:buf) ) return buf;
  }
  else
  {
   if (egrep(pattern:pattern,string:substr(buf, l - 256))) return buf;
  }
 }
#dump(ddata: buf, dtitle: 'telnet');
#debug_print('recv_until(pattern=', pattern, ') = NULL !\n');
#dump(dtitle: 'telnet', ddata: buf);
 return NULL;
}
