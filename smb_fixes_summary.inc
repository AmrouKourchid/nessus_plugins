#TRUSTED 21b316644d561df9420aad2a0faa3beb77d5c114ca1c40de501a466f629024fb1de6b17572b016210efbec3501eb945ec23ffe3d930367a9fc63a3630b206ba5990464479add47241a6e740cbcd5c582eb30493338fe54e7acf467f9984e5a4613dba54591f42c9469ddca01f45dc081875c37df4f55140dd2b6f9721ec815f94ed1f8d7d2e380f019fb2bf41ea077013ec3e47240437c32682103c688a2d5e43bc80e14eea7e754112a9a82325bb33eeee42893951e6eb37968195f77d4adc620ab591faa66555d92475a8372ebaed61c349936353c098dfe916ada8ba890fa76ea4e6511f9e71641c0511200a83e77b1cec99ff649ab0a838deb15f3c370f8931ce96ec7c9ef2a4d3d192e4114f14691443c2e6727d5350f0d887197978148027434c2867568c3d48e12a6c0cbc5c20d84f7d1ad52ffd08a7e5d28cad85c9e60576608365be6bc4d4ec6f331b16720a58662beee793d3bea038f2015ccc84ca609259f8497410c8737ca92dbf02275c3e8b0d2b77e7549ffc9e8685c54aa89655fe3f9bde688a90f35c9447b3c0a166c3c349e6a9dc7a9e01bbc67312e8af97c3079d74dfaf4558a57c2f089366ad745c88b1d1bf49ec2834592f8b40ad7daf090ab0019a467d614a6327d92ab7fd8d6d81b6ce4ca91b6a523bb0cbf9f4f21596c699256bfacf8a828e56a405f0f9089865b5803a6596462c72cf0f9a75950
#TRUST-RSA-SHA256 91342f1cbd170856877b513ca864b68b9e48575f673deb88948c2fd0482addd4b757befee4f22a7ad375b3aabfddca18970053e5c11b02b9a2ae0e1ac7bb5b0984e6ffc1463b5533634889209d603a532cf7ed02e2dbeb78121b82894ad96d258f14bd896c0dded6c6cf85d67108c4bd9f35413bca6a159524711b9f14a17a55ec31d17e0a76336269649175860a647de51d91d32913fabb421e1351238a78f08dfcec938024e1252f01a5d04c015cc7703cf898eaffa0b8587b63ce86804ad418a28c7a6139fde8592922b9fa3293d86bcf4d6b532a8465cd1505fefb709d1275018fc0c1ec7d08584a3ffd1ae5250eea12cdd71063e69393ae1266b28e36d961130185d1c4cd062491aac939f26679d5d7de36c28e0a2be1ebf6a9c6062f3ec071ef81ec43e2ab9a39fc9a3367792b1499b1dfb6182ce88f5f5f792ede464f0f967aae35522f0ea89f7f8cfad8744a60c3f6ac3b7a7204cf2960957bcb9ae5d7285868c7af321b878100006fbd55db27638b575aa4121b9287a5ad34e63b870f8207b251d099ce48be4b6e97bd9a80dc12e184e29819732fc613d09863d54413dfe2501e8d46cefd5b4afadbc01e36eb3b39d12412e952ec2911aabc7054eb3ab705f6f9dcb9ab1844c56164c94a5501b84eabd89bc2797952eded63340b428b6f2f2b9c78e6b959f04a252c2ed046e8d00c74a22c6678e18eafbfcfa30b98
#
# Revision: 1.3
#
include('compat_shared.inc');
include('spad_log_func.inc');
include('supersedence_builder.inc');

global_var smb_hf_add_table_created = false;
global_var smb_hf_add_cache = make_array();

function smb_hf_add_create_table()
{
  query_scratchpad('CREATE TABLE IF NOT EXISTS SMB_HF ( bulletin text, kb text, script_name text, CONSTRAINT hf_primary_key PRIMARY KEY (bulletin, kb, script_name) ON CONFLICT IGNORE )');
  query_scratchpad('CREATE INDEX IF NOT EXISTS SMB_HF_KbIndex ON SMB_HF(kb)');
  query_scratchpad('CREATE INDEX IF NOT EXISTS SMB_HF_BulletinIndex ON SMB_HF(bulletin)');
  smb_hf_add_table_created = true;
}

function smb_hf_add(os, sp, file, version, bulletin, kb)
{
  var res;
  if (!defined_func('query_scratchpad') ) return;
  if (!defined_func('nasl_level') ) return;
  if (!strlen(bulletin) && !strlen(kb) ) return;
  if (!smb_hf_add_table_created) smb_hf_add_create_table();

  query_scratchpad('INSERT INTO SMB_HF (bulletin, kb, script_name) VALUES (?, ?, ?)', bulletin, kb, SCRIPT_NAME);

  # Check script cache before inserting into supersedence data
  var insert = true;

  if(isnull(smb_hf_add_cache[SCRIPT_NAME]))
  {
    smb_hf_add_cache[SCRIPT_NAME] = [];
  }

  foreach var entry(smb_hf_add_cache[SCRIPT_NAME])
  {
    if(entry == kb)
    {
      insert = false;
      break;
    }
  }

  if (insert && !isnull(kb))
  {
    # Supersedence data not found in cache. Cache and store into scratchpad.
    append_element(var:smb_hf_add_cache[SCRIPT_NAME], value:kb);
    var data = make_array('vendor_patch_id',string(kb));
    supersedence::scratchpad_insert_data(plugin_name:SCRIPT_NAME, host_ip: get_host_ip(), type:'MSKB', data:data);
  }
}
