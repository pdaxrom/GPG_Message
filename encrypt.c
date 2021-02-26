#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gpgme.h>

int main (int argc, char *argv[])
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_data_t in, out;
  gpgme_key_t key[3] = { NULL, NULL, NULL };
  gpgme_encrypt_result_t result;

  init_gpgme (GPGME_PROTOCOL_OpenPGP);
    
  err = gpgme_new (&ctx);
  fail_if_err (err);
  gpgme_set_armor (ctx, 1);

  /* Generate test keys. */
  char *fprs[2];
  err = generate_test_keys (ctx,2,fprs,NULL);
  fail_if_err (err);

  err = gpgme_data_new_from_mem (&in, "Hallo Leute\n", 12, 0);
  fail_if_err (err);

  err = gpgme_data_new (&out);
  fail_if_err (err);

  err = gpgme_get_key (ctx,fprs[0],&key[0],0);
  fail_if_err (err);
  err = gpgme_get_key (ctx,fprs[1],&key[1],0);
  fail_if_err (err);

  err = gpgme_op_encrypt (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
  fail_if_err (err);
  result = gpgme_op_encrypt_result (ctx);
  if (result->invalid_recipients)
    {
      fprintf (stderr, "Invalid recipient encountered: %s\n",
	       result->invalid_recipients->fpr);
      exit (1);
    }
  print_data (out);

  free(fprs[0]);
  free(fprs[1]);
  delete_test_key(ctx,key[0]);
  delete_test_key(ctx,key[1]);
  gpgme_data_release (in);
  gpgme_data_release (out);
  gpgme_release (ctx);
  return 0;
}
