#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>

#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#endif

#include <gpgme.h>

static void init_gpgme_basic(void)
{
    gpgme_check_version(NULL);
    setlocale (LC_ALL, "");
    gpgme_set_locale(NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifndef HAVE_W32_SYSTEM
    gpgme_set_locale(NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif
}


static int init_gpgme(gpgme_protocol_t proto)
{
    gpg_error_t err;

    init_gpgme_basic();
    err = gpgme_engine_check_version(proto);
    if (err) {
	fprintf(stderr, "%s:%d: %s: %s\n",
		__FILE__, __LINE__, gpgme_strsource (err),
		gpgme_strerror (err));
	return 0;
    }

    return 1;
}

static char *get_encrypted_text(gpgme_data_t dh)
{
#define BUF_SIZE 512
    char buf[BUF_SIZE + 1];
    int ret;
    char *txt = NULL;
    int txt_size = 0;

    ret = gpgme_data_seek (dh, 0, SEEK_SET);
    if (ret) {
	int err = gpgme_err_code_from_errno(errno);
	if (err) {
	    fprintf(stderr, "%s:%d: %s: %s\n",
		__FILE__, __LINE__, gpgme_strsource (err),
		gpgme_strerror (err));

	    return NULL;
	}
    }

    while ((ret = gpgme_data_read (dh, buf, BUF_SIZE)) > 0) {
	txt = (char *)realloc(txt, txt_size + ret);
	memcpy(txt + txt_size, buf, ret);
	txt_size += ret;
    }

    if (ret < 0) {
	int err = gpgme_err_code_from_errno(errno);
	if (err) {
	    fprintf(stderr, "%s:%d: %s: %s\n",
		__FILE__, __LINE__, gpgme_strsource (err),
		gpgme_strerror (err));

	    if (txt) {
		free(txt);
		txt = NULL;
	    }
	}
    } else {
	txt = realloc(txt, txt_size + 1);
	txt[txt_size] = 0;
    }

    return txt;
}

static gpgme_error_t passphrase_cb(void *opaque, const char *uid_hint, const char *passphrase_info,
	int last_was_bad, int fd)
{
  int res;
  char pass[] = "\n";
  int passlen = strlen (pass);
  int off = 0;

  (void)opaque;
  (void)uid_hint;
  (void)passphrase_info;
  (void)last_was_bad;

fprintf(stderr, "Want get passphrase\n");

  do
    {
      res = gpgme_io_write(fd, &pass[off], passlen - off);
      if (res > 0)
	off += res;
    }
  while (res > 0 && off != passlen);

  return off == passlen ? 0 : gpgme_error_from_errno (errno);
}

char *encrypt(char *gpg_text, char *msg_text)
{
    char *ret = NULL;
    gpgme_ctx_t ctx;
    gpgme_error_t err;
    gpgme_data_t in, out;
    gpgme_key_t key[3] = { NULL, NULL, NULL };
    gpgme_encrypt_result_t result;
    gpgme_import_result_t import_result;


//fprintf(stderr, "gpg key: [%s]\n", gpg_text);
//fprintf(stderr, "message: [%s]\n", msg_text);

    if (!init_gpgme(GPGME_PROTOCOL_OpenPGP)) {
	return NULL;
    }

    err = gpgme_new(&ctx);

//    gpgme_set_protocol (ctx, GPGME_PROTOCOL_CMS);
    gpgme_set_armor (ctx, 1);

    err = gpgme_data_new_from_mem(&in, gpg_text, strlen(gpg_text), 0);
    if (err) {
	fprintf(stderr, "%s:%d: %s: %s\n",
		__FILE__, __LINE__, gpgme_strsource (err),
		gpgme_strerror (err));

	gpgme_release(ctx);
	return NULL;
    }

    err = gpgme_op_import(ctx, in);
    if (err) {
	fprintf(stderr, "%s:%d: %s: %s\n",
		__FILE__, __LINE__, gpgme_strsource (err),
		gpgme_strerror (err));

	gpgme_data_release(in);
	gpgme_release(ctx);
	return NULL;
    }

    import_result = gpgme_op_import_result(ctx);

    fprintf(stderr, "fpr [%s]\n", import_result->imports->fpr);

    gpgme_data_release(in);

    err = gpgme_data_new_from_mem(&in, msg_text, strlen(msg_text), 0);
    if (err) {
	fprintf(stderr, "%s:%d: %s: %s\n",
		__FILE__, __LINE__, gpgme_strsource (err),
		gpgme_strerror (err));

	gpgme_release(ctx);
	return NULL;
    }

    err = gpgme_data_new(&out);
    if (err) {
	fprintf(stderr, "%s:%d: %s: %s\n",
		__FILE__, __LINE__, gpgme_strsource (err),
		gpgme_strerror (err));

	gpgme_data_release(in);
	gpgme_release(ctx);
	return NULL;
    }

    gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);

    err = gpgme_get_key(ctx, import_result->imports->fpr, &key[0], 0);
    if (err) {
	fprintf(stderr, "%s:%d: %s: %s\n",
		__FILE__, __LINE__, gpgme_strsource (err),
		gpgme_strerror (err));

	gpgme_data_release(in);
	gpgme_data_release(out);
	gpgme_release(ctx);
	return NULL;
    }

    err = gpgme_op_encrypt (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    if (err) {
	fprintf(stderr, "%s:%d: %s: %s\n",
		__FILE__, __LINE__, gpgme_strsource (err),
		gpgme_strerror (err));
    } else {
	result = gpgme_op_encrypt_result (ctx);
	if (result->invalid_recipients) {
	    fprintf(stderr, "Invalid recipient encountered: %s\n",
		    result->invalid_recipients->fpr);
	} else {
	    ret = get_encrypted_text(out);
//fprintf(stderr, "ecrypted [%s]\n", ret);
	}
    }

    err = gpgme_op_delete (ctx, key[0], 1);
    gpgme_key_unref(key[0]);
    gpgme_data_release (in);
    gpgme_data_release (out);
    gpgme_release (ctx);

    return ret;
}
