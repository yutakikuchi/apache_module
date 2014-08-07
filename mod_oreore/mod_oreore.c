/**
 * Cookie Uer Tracking
 *
 * @file  mod_oreore.c
 * @brief mod_oreore is user tracking module
 * @author yutakikuchi(@yutakikuc)
 * @date  2014.08.06
 * @version 0.1
 */

//include http
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_request.h"
#include "http_log.h"
//include apr
#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_network_io.h"
#include "apr_want.h"
#include "apr_base64.h"
//include crypto
#include "util_md5.h"
#include "evp.h"
#include "aes.h"
//include pid
#include "sys/types.h"
#include "unistd.h"
//define
#define TIME_SEC 1
#define TIME_MIN   TIME_SEC * 60
#define TIME_HOUR  TIME_MIN * 60
#define TIME_DAY   TIME_HOUR * 24
#define TIME_WEEK  TIME_DAY * 7
#define TIME_MONTH TIME_DAY * 30
#define TIME_YEAR  TIME_DAY * 365

module AP_MODULE_DECLARE_DATA oreore_module;

/**
 * @var cookie_style Cookie Styleの定数
 */
typedef enum {
	CT_UNSET,
	CT_NETSCAPE,
	CT_COOKIE,
	CT_COOKIE2
} cookie_style;

/**
 * @var cookie_struct Cookieのデータ構造体
 */
typedef struct {
	int secret_flag;
	char *name;
	char *domain;
	char *expires;
	char *path;
	cookie_style style;
	unsigned char *secret_key;
} cookie_struct;

/**
 * AES-16Bit-ECBで暗号化する
 *
 * @param  apr_pool_t    *p          Memory Pool
 * @param  const char    *src        暗号化したい文字列のポインタ
 * @param  char          *key        暗号化に利用するkeyのポインタ
 * @param  integer       *len        暗号化する文字列の長さを示すポインタ
 * @return unsigned char *ciphertext 暗号化した文字列のポインタ
 */
/* Todo 後で暗号化処理を追加する
static unsigned char *gen_aes_128_ecb(apr_pool_t *p, unsigned char *src, unsigned char *key, int *len){
	EVP_CIPHER_CTX *en;
	en = (EVP_CIPHER_CTX*)apr_pcalloc(p, sizeof(EVP_CIPHER_CTX));
	EVP_CIPHER_CTX_init(en);
	int clen = (int)strlen((const char*)src) + EVP_MAX_BLOCK_LENGTH, olen = 0;
	unsigned char *ciphertext = NULL;
	if (!EVP_EncryptInit_ex(en, EVP_aes_128_ecb(), NULL, key, NULL)) {
		return NULL;
	}
	clen = *len + EVP_MAX_BLOCK_LENGTH;
	ciphertext = (unsigned char *)apr_pcalloc(p, clen);
	if (!EVP_EncryptUpdate(en, ciphertext, &clen, src, *len)) {
		return NULL;
	}
	if (!EVP_EncryptFinal_ex(en, ciphertext+clen, &olen)) {
		return NULL;
	}
	EVP_CIPHER_CTX_cleanup(en);
	return ciphertext;
}
*/

/**
 * Base64encodeをURLSafe形式で変換する
 *
 * @param  apr_pool_t     *p       Memory Pool
 * @param  const char     *src     変換したい文字列のポインタ
 * @param  integer        *len     変換したい文字列の長さ
 * @return unsigned char  *enc     変換した文字列のポインタ
 */
static unsigned char *base64_urlsafe_encode(apr_pool_t *p, unsigned char *src, int len){
	int enc_len = apr_base64_encode_len(len);
	unsigned char *enc = (unsigned char *)apr_pcalloc(p, enc_len);
	apr_base64_encode((char *)enc, (const char *)src, len);
	int i = 0;
	while (enc[i] != '\0') {
		if (enc[i] == '+') enc[i] = '-';
		if (enc[i] == '/') enc[i] = '_';
		if (enc[i] == '=') enc[i] = '.';
		i++;
	}
	return enc;
}

/**
 * Cookieを生成する
 *
 * @param  request_rec  *r   request_rec構造体
 */
static void set_cookie(request_rec *r) {
	cookie_struct *cs = ap_get_module_config(r->per_dir_config, &oreore_module);
	unsigned char *id = (unsigned char *)apr_psprintf(r->pool, "%s%10lu%06lu%u%u", r->connection->local_ip, apr_time_sec(r->request_time), apr_time_usec(r->request_time), htonl(getpid()), htonl(r->connection->id));
	int len;
	/* Todo 後で暗号化処理を追加する
	if (cs->secret_flag) {
		len = (int)strlen((const char*)id);
		unsigned char *tmpid = gen_aes_128_ecb(r->pool, id, cs->secret_key, &len);
		if (tmpid != NULL) {
			id = tmpid;
		}
	}
	*/
	len = (int)strlen((const char*)id);
	id = base64_urlsafe_encode(r->pool, id, len);
	unsigned char *cookie_format = (unsigned char *)apr_psprintf(r->pool, "%s=id=%s&v=1; path=/;", cs->name, id);
	if (cs->expires != 0) {
		if ((cs->style == CT_UNSET) || (cs->style == CT_NETSCAPE)) {
			apr_time_exp_t tms;
			apr_time_exp_gmt(&tms, r->request_time + atoi(cs->expires) * APR_USEC_PER_SEC);
			cookie_format = (unsigned char *)apr_psprintf(r->pool, "%s expires=%s, %.2d-%s-%.4d %.2d:%.2d:%.2d GMT;", cookie_format, apr_day_snames[tms.tm_wday], tms.tm_mday, apr_month_snames[tms.tm_mon], 1900 + tms.tm_year, tms.tm_hour, tms.tm_min, tms.tm_sec);
		} else {
			cookie_format = (unsigned char *)apr_psprintf(r->pool, "%s max-age=%s;", cookie_format, cs->expires);
		}
	}
	if (cs->domain != NULL) {
		cookie_format = (unsigned char *)apr_psprintf(r->pool, "%s domain=%s;%s", cookie_format, cs->domain, (cs->style == CT_COOKIE2 ? " version=0;" : ""));
	}
	apr_table_setn(r->headers_out, (cs->style == CT_COOKIE2 ? "Set-Cookie2" : "Set-Cookie"), (const char *)cookie_format);
	return;
}

/**
 * Tracking Cookieを作成する
 *
 * @param  request_rec  *r   request_rec構造体
 * @return integer 状態値
 */
static int main_process(request_rec *r) {
	cookie_struct *cs = ap_get_module_config(r->per_dir_config, &oreore_module);
	const char *cookie, *find_key, *cookie_value;
	find_key = apr_psprintf(r->pool, "%s=", cs->name);
	if ((cookie = apr_table_get(r->headers_in, (cs->style == CT_COOKIE2 ? "Cookie2" : "Cookie")))) {
		if ((cookie_value = ap_strstr_c(cookie, find_key))) {
			return DECLINED;
		}
	}
	set_cookie(r);
	return OK;
}

/**
 * cookie_structの初期化
 *
 * @param  apr_pool_t   *p     requestのメモリpool
 * @param  char         *dummy (使用しない)
 */
static void *init_cookie_struct(apr_pool_t *p, char *dummy) {
	cookie_struct *cs;
	cs = (cookie_struct *) apr_pcalloc(p, sizeof(cookie_struct));
	cs->style = CT_UNSET;
	return cs;
}

/**
 * expireを設定
 *
 * @param  cmd_parms   *cmd       設定のパラメータ構造体
 * @param  void        *mconfig   引き継ぎする設定情報
 * @param  const char  *arg       expireの時間
 * @return const char             エラーもしくはNULL
 */
static const char *set_cookie_exp(cmd_parms *parms, void *mconfig, const char *arg) {
	cookie_struct *cs = (cookie_struct *) mconfig;
	unsigned int i, expires;
	char *value  = ap_getword_conf(parms->pool, &arg);
	char *period = ap_getword_conf(parms->pool, &arg);
	for (i=0; value[i] != '\0'; ++i) {
		if (!apr_isdigit(value[i])) {
			return "bad expires code, numeric value expected.";
		}
	}
	if (period == NULL) {
		return "bad expires code, missing <type>";
	}
	if (strcmp(period, "years") == 0) {
		expires = atoi(value) * TIME_YEAR;
	} else if (strcmp(period, "months") == 0) {
		expires = atoi(value) * TIME_MONTH;
	} else if (strcmp(period, "weeks") == 0) {
		expires = atoi(value) * TIME_WEEK;
	} else if (strcmp(period, "days") == 0) {
		expires = atoi(value) * TIME_DAY;
	} else if (strcmp(period, "hours") == 0) {
		expires = atoi(value) * TIME_HOUR;
	} else if (strcmp(period, "minutes") == 0) {
		expires = atoi(value) * TIME_MIN;
	} else if (strcmp(period, "seconds") == 0) {
		expires = atoi(value) * TIME_SEC;
	} else {
		return "bad expires code, unrecognized type";
	}
	cs->expires = (char *)apr_psprintf(parms->pool, "%u", expires);
	return NULL;
}

/**
 * 名前を設定する
 *
 * @param  cmd_parms   *cmd       設定のパラメータ構造体
 * @param  void        *mconfig   引き継ぎする設定情報
 * @param  const char  *name      cookieの名前
 * @return const char  NULL
 */
static const char *set_cookie_name(cmd_parms *cmd, void *mconfig, const char *name) {
	cookie_struct *cs = (cookie_struct *) mconfig;
	cs->name = apr_pstrdup(cmd->pool, name);
	return NULL;
}

/**
 * 有効domainを設定する
 *
 * @param  cmd_parms   *cmd       設定のパラメータ構造体
 * @param  void        *mconfig   引き継ぎする設定情報
 * @param  const char  *name      cookieの有効domain
 * @return const char             エラーもしくはNULL
 */
static const char *set_cookie_domain(cmd_parms *cmd, void *mconfig, const char *name) {
	cookie_struct *cs = (cookie_struct *) mconfig;
	if (strlen(name) == 0 || name == NULL) {
		return "CookieDomain values may not be null";
	}
	if (name[0] != '.') {
		return "CookieDomain values must begin with a dot";
	}
	cs->domain = ap_getword_conf(cmd->pool, &name);
	return NULL;
}

/**
 * formatを設定する
 *
 * @param  cmd_parms   *cmd       設定のパラメータ構造体
 * @param  void        *mconfig   引き継ぎする設定情報
 * @param  const char  *name      Cookieのstyle名
 * @return const char             エラーもしくはNULL
 */
static const char *set_cookie_style(cmd_parms *cmd, void *mconfig, const char *name) {
	cookie_struct *cs = (cookie_struct *) mconfig;
	if (strcasecmp(name, "Netscape") == 0) {
		cs->style = CT_NETSCAPE;
	} else if ((strcasecmp(name, "Cookie") == 0) || (strcasecmp(name, "RFC2109") == 0)) {
		cs->style = CT_COOKIE;
	} else if ((strcasecmp(name, "Cookie2") == 0) || (strcasecmp(name, "RFC2965") == 0)) {
		cs->style = CT_COOKIE2;
	} else {
		return apr_psprintf(cmd->pool, "Invalid %s keyword: '%s'",cmd->cmd->name, name);
	}
	return NULL;
}

/**
 * 暗号化を利用可能とするフラグを設定
 *
 * @param  cmd_parms   *cmd       設定のパラメータ構造体
 * @param  void        *mconfig   引き継ぎする設定情報
 * @param  integer     arg        ON/OFFのフラグ
 */
/* Todo 後で暗号化処理を追加する
static const char *set_cookie_secret_mode(cmd_parms *cmd, void *mconfig, int arg) {
	cookie_struct *cs = (cookie_struct *) mconfig;
	cs->secret_flag = arg;
	return NULL;
}
*/

/**
 * 暗号化Keyを設定する
 *
 * @param  cmd_parms   *cmd       設定のパラメータ構造体
 * @param  void        *mconfig   引き継ぎする設定情報
 * @param  const char  *name      暗号化keyの値
 * @return const char  NULL
 */
/* Todo 後で暗号化処理を追加する
static const char *set_cookie_secret_key(cmd_parms *cmd, void *mconfig, const char *name) {
	cookie_struct *cs = (cookie_struct *) mconfig;
	cs->secret_key = (unsigned char*)apr_pstrdup(cmd->pool, name);
	return NULL;
}
*/

/**
 * 初期関数群を呼び出すための設定
 */
static const command_rec cookie_cmds[] ={
	AP_INIT_TAKE1("Name",      set_cookie_name,        NULL, OR_FILEINFO, "name of the tracking cookie"),
	AP_INIT_TAKE1("Domain",    set_cookie_domain,      NULL, OR_FILEINFO, "domain to which this cookie applies"),
	AP_INIT_TAKE1("Style",     set_cookie_style,       NULL, OR_FILEINFO, "'Netscape', 'Cookie' (RFC2109), or 'Cookie2' (RFC2965)"),
	AP_INIT_TAKE1("Expires",   set_cookie_exp,         NULL, OR_FILEINFO, "an expiry date code"),
	//AP_INIT_TAKE1("SecretKey", set_cookie_secret_key,  NULL, OR_FILEINFO, "key of cookie secret"),
	//AP_INIT_FLAG("SecretMode", set_cookie_secret_mode, NULL, OR_FILEINFO, "flag of secret mode"),
	{NULL}
};

/**
 * hookするタイミングを設定
 *
 * @param  apr_pool_t  *p  requestのメモリpool
 */
static void register_hooks(apr_pool_t *p) {
	ap_hook_fixups(main_process, NULL, NULL, APR_HOOK_LAST);
}

/**
 * moduleを実行するにあたり初期化する関数の定義
 */
module AP_MODULE_DECLARE_DATA oreore_module = {
	STANDARD20_MODULE_STUFF,
	init_cookie_struct,         /* dir config creater */
	NULL,                       /* dir merger --- default is to override */
	NULL,                       /* server config */
	NULL,                       /* merge server configs */
	cookie_cmds,                /* command apr_table_t */
	register_hooks              /* register hooks */
};
