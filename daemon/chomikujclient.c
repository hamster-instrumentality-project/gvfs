/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* gvfs - extensions for gio
 *
 * Copyright (C) 2024 The GVfs Authors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

/*
 * Client for the Chomikuj.pl "Mobile API v3", as reverse engineered in the
 * sibling project chomikuj-android-re2 (see its MOBILE_PROTOCOL.md).
 *
 * Wire essentials:
 *   - Base URL    : https://mobile.chomikuj.pl
 *   - API prefix  : /api/v3
 *   - User-Agent  : android/3.8.4 (<deviceId>; <deviceName>)
 *   - Token header: md5( (path + ["?" + query] + body + SECRET).substring(1) )
 *   - Api-Key     : session key returned by /account/login
 *   - Listing Size: kilobytes (floored); a file name is split at the last dot
 *                   into FileName + FileType.
 *   - Upload      : partialUpload negotiation + 512 KiB multipart chunks.
 */

#include <config.h>

#include <string.h>
#include <glib/gstdio.h>
#include <json-glib/json-glib.h>

#include "chomikujclient.h"

#define CHOMIKUJ_BASE_URL      "https://mobile.chomikuj.pl"
#define CHOMIKUJ_API_PREFIX    "/api/v3"
#define CHOMIKUJ_CLIENT_VER    "3.8.4"
#define CHOMIKUJ_UPLOAD_CHUNK  (512 * 1024)
#define CHOMIKUJ_MAX_PAGE      50
/* Cheap retries of a single chunk (transient HTTP status or dropped
 * connection) and expensive full restarts (409, which discards everything
 * uploaded so far and starts again from byte 0). */
#define CHOMIKUJ_MAX_CHUNK_RETRIES 5
#define CHOMIKUJ_MAX_UPLOAD_RESETS 3
/* Bounds for the jittered exponential backoff used between chunk retries. */
#define CHOMIKUJ_RETRY_BASE_US     (500 * 1000)
#define CHOMIKUJ_RETRY_MAX_US      (8 * 1000 * 1000)

/*
 * BuildConfig.SECRET_KEY, verbatim from the APK.  It is a single, app-wide
 * constant (NOT per-account or per-session); it only feeds the weak request
 * integrity check below.  Kept isolated here so it can be swapped for a
 * runtime/build-time value later if desired.
 */
static const gchar chomikuj_buildconfig_secret_key[] =
  "4762,4883,4564,4765,3566,4687,3888,1449,1850,2731,3332,4053,2254,4615,"
  "4696,4297,1338,3859,1580,2021,4902,4704,4826,4471,4757,3502,4675,3848,"
  "1419,1758,2673,3298,4036,2183,4584,4660,4251,1231,3743,1527,1961,4874,"
  "4819,4898,4567,4776,3587,4689,3934,1536,1867,2723,3397,4073,2266,4603,"
  "4735,4352,1364,3879,1640,2025,4897,4775,4954,4596,4764,3611,4737,3933,"
  "1464,1894,2758,3333,4051,2260,4661,4711,4367,1351,3862,1638,2036,4943";

struct _ChomikujClient
{
  SoupSession *session;
  gchar *base_url;
  gchar *user_agent;
  gchar *account_name;
  gchar *account_id;
  gchar *api_key;
  gchar *avatar_url;
  guint max_retries;
};

/* ------------------------------------------------------------------ */
/*  Secret / signing                                                   */
/* ------------------------------------------------------------------ */

gchar *
chomikuj_decode_secret (const gchar *key_csv)
{
  gchar **parts;
  guint n, quarter, divisor, i;
  gint *values;
  gchar *out;

  parts = g_strsplit (key_csv, ",", -1);
  n = g_strv_length (parts);
  if (n == 0)
    {
      g_strfreev (parts);
      return g_strdup ("");
    }

  values = g_new0 (gint, n);
  for (i = 0; i < n; i++)
    values[i] = (gint) g_ascii_strtoll (parts[i], NULL, 10);
  g_strfreev (parts);

  quarter = (guint) ((gdouble) n * 0.25);
  if (quarter < 2)
    {
      g_free (values);
      return g_strdup ("");
    }

  for (i = 0; i < quarter; i++)
    values[i] = values[i] - ((gint) i + 2);

  divisor = (quarter - 1) * 2;
  if (divisor == 0)
    {
      g_free (values);
      return g_strdup ("");
    }

  out = g_malloc0 (quarter);
  for (i = 0; i + 1 < quarter; i++)
    out[i] = (gchar) (values[i] / (gint) divisor);
  out[quarter - 1] = '\0';

  g_free (values);
  return out;
}

const gchar *
chomikuj_secret (void)
{
  static gchar *secret = NULL;
  static gsize init = 0;

  if (g_once_init_enter (&init))
    {
      secret = chomikuj_decode_secret (chomikuj_buildconfig_secret_key);
      g_once_init_leave (&init, 1);
    }

  return secret;
}

gchar *
chomikuj_sign (const gchar *path,
               const gchar *query,
               const gchar *body)
{
  GString *raw;
  gchar *token;

  raw = g_string_new (path ? path : "");
  if (query != NULL && *query != '\0')
    {
      g_string_append_c (raw, '?');
      g_string_append (raw, query);
    }
  if (body != NULL)
    g_string_append (raw, body);
  g_string_append (raw, chomikuj_secret ());

  token = g_compute_checksum_for_string (G_CHECKSUM_MD5,
                                         raw->str + (raw->len > 0 ? 1 : 0),
                                         raw->len > 0 ? (gssize) (raw->len - 1) : 0);
  g_string_free (raw, TRUE);
  return token;
}

/* ------------------------------------------------------------------ */
/*  Names                                                              */
/* ------------------------------------------------------------------ */

void
chomikuj_split_name (const gchar  *full_name,
                     gchar       **base,
                     gchar       **extension)
{
  const gchar *last;

  last = full_name ? strrchr (full_name, '.') : NULL;
  if (last != NULL && last != full_name)
    {
      if (base)
        *base = g_strndup (full_name, last - full_name);
      if (extension)
        *extension = g_strdup (last + 1);
    }
  else
    {
      if (base)
        *base = g_strdup (full_name ? full_name : "");
      if (extension)
        *extension = NULL;
    }
}

gchar *
chomikuj_join_name (const gchar *base,
                    const gchar *extension)
{
  gchar *suffix;

  if (extension == NULL || *extension == '\0')
    return g_strdup (base ? base : "");

  suffix = g_strconcat (".", extension, NULL);
  /* The rename endpoint stores the full name including the dot; avoid
   * re-appending an extension that is already present. */
  if (base != NULL && g_str_has_suffix (base, suffix))
    {
      g_free (suffix);
      return g_strdup (base);
    }

  {
    gchar *res = g_strconcat (base ? base : "", suffix, NULL);
    g_free (suffix);
    return res;
  }
}

static gchar *
escape_filename (const gchar *name)
{
  GString *out;
  const gchar *p;

  out = g_string_new (NULL);
  for (p = name; p != NULL && *p != '\0'; p++)
    {
      if (strchr ("?:<>/*\"\\", *p) != NULL)
        g_string_append_c (out, '_');
      else
        g_string_append_c (out, *p);
    }
  return g_string_free (out, FALSE);
}

/* ------------------------------------------------------------------ */
/*  CRC32                                                              */
/* ------------------------------------------------------------------ */

static guint32
crc32_update (guint32 crc, const guint8 *buf, gsize len)
{
  static const guint32 table[256] = {
    0x00000000,0x77073096,0xee0e612c,0x990951ba,0x076dc419,0x706af48f,
    0xe963a535,0x9e6495a3,0x0edb8832,0x79dcb8a4,0xe0d5e91e,0x97d2d988,
    0x09b64c2b,0x7eb17cbd,0xe7b82d07,0x90bf1d91,0x1db71064,0x6ab020f2,
    0xf3b97148,0x84be41de,0x1adad47d,0x6ddde4eb,0xf4d4b551,0x83d385c7,
    0x136c9856,0x646ba8c0,0xfd62f97a,0x8a65c9ec,0x14015c4f,0x63066cd9,
    0xfa0f3d63,0x8d080df5,0x3b6e20c8,0x4c69105e,0xd56041e4,0xa2677172,
    0x3c03e4d1,0x4b04d447,0xd20d85fd,0xa50ab56b,0x35b5a8fa,0x42b2986c,
    0xdbbbc9d6,0xacbcf940,0x32d86ce3,0x45df5c75,0xdcd60dcf,0xabd13d59,
    0x26d930ac,0x51de003a,0xc8d75180,0xbfd06116,0x21b4f4b5,0x56b3c423,
    0xcfba9599,0xb8bda50f,0x2802b89e,0x5f058808,0xc60cd9b2,0xb10be924,
    0x2f6f7c87,0x58684c11,0xc1611dab,0xb6662d3d,0x76dc4190,0x01db7106,
    0x98d220bc,0xefd5102a,0x71b18589,0x06b6b51f,0x9fbfe4a5,0xe8b8d433,
    0x7807c9a2,0x0f00f934,0x9609a88e,0xe10e9818,0x7f6a0dbb,0x086d3d2d,
    0x91646c97,0xe6635c01,0x6b6b51f4,0x1c6c6162,0x856530d8,0xf262004e,
    0x6c0695ed,0x1b01a57b,0x8208f4c1,0xf50fc457,0x65b0d9c6,0x12b7e950,
    0x8bbeb8ea,0xfcb9887c,0x62dd1ddf,0x15da2d49,0x8cd37cf3,0xfbd44c65,
    0x4db26158,0x3ab551ce,0xa3bc0074,0xd4bb30e2,0x4adfa541,0x3dd895d7,
    0xa4d1c46d,0xd3d6f4fb,0x4369e96a,0x346ed9fc,0xad678846,0xda60b8d0,
    0x44042d73,0x33031de5,0xaa0a4c5f,0xdd0d7cc9,0x5005713c,0x270241aa,
    0xbe0b1010,0xc90c2086,0x5768b525,0x206f85b3,0xb966d409,0xce61e49f,
    0x5edef90e,0x29d9c998,0xb0d09822,0xc7d7a8b4,0x59b33d17,0x2eb40d81,
    0xb7bd5c3b,0xc0ba6cad,0xedb88320,0x9abfb3b6,0x03b6e20c,0x74b1d29a,
    0xead54739,0x9dd277af,0x04db2615,0x73dc1683,0xe3630b12,0x94643b84,
    0x0d6d6a3e,0x7a6a5aa8,0xe40ecf0b,0x9309ff9d,0x0a00ae27,0x7d079eb1,
    0xf00f9344,0x8708a3d2,0x1e01f268,0x6906c2fe,0xf762575d,0x806567cb,
    0x196c3671,0x6e6b06e7,0xfed41b76,0x89d32be0,0x10da7a5a,0x67dd4acc,
    0xf9b9df6f,0x8ebeeff9,0x17b7be43,0x60b08ed5,0xd6d6a3e8,0xa1d1937e,
    0x38d8c2c4,0x4fdff252,0xd1bb67f1,0xa6bc5767,0x3fb506dd,0x48b2364b,
    0xd80d2bda,0xaf0a1b4c,0x36034af6,0x41047a60,0xdf60efc3,0xa867df55,
    0x316e8eef,0x4669be79,0xcb61b38c,0xbc66831a,0x256fd2a0,0x5268e236,
    0xcc0c7795,0xbb0b4703,0x220216b9,0x5505262f,0xc5ba3bbe,0xb2bd0b28,
    0x2bb45a92,0x5cb36a04,0xc2d7ffa7,0xb5d0cf31,0x2cd99e8b,0x5bdeae1d,
    0x9b64c2b0,0xec63f226,0x756aa39c,0x026d930a,0x9c0906a9,0xeb0e363f,
    0x72076785,0x05005713,0x95bf4a82,0xe2b87a14,0x7bb12bae,0x0cb61b38,
    0x92d28e9b,0xe5d5be0d,0x7cdcefb7,0x0bdbdf21,0x86d3d2d4,0xf1d4e242,
    0x68ddb3f8,0x1fda836e,0x81be16cd,0xf6b9265b,0x6fb077e1,0x18b74777,
    0x88085ae6,0xff0f6a70,0x66063bca,0x11010b5c,0x8f659eff,0xf862ae69,
    0x616bffd3,0x166ccf45,0xa00ae278,0xd70dd2ee,0x4e048354,0x3903b3c2,
    0xa7672661,0xd06016f7,0x4969474d,0x3e6e77db,0xaed16a4a,0xd9d65adc,
    0x40df0b66,0x37d83bf0,0xa9bcae53,0xdebb9ec5,0x47b2cf7f,0x30b5ffe9,
    0xbdbdf21c,0xcabac28a,0x53b39330,0x24b4a3a6,0xbad03605,0xcdd70693,
    0x54de5729,0x23d967bf,0xb3667a2e,0xc4614ab8,0x5d681b02,0x2a6f2b94,
    0xb40bbe37,0xc30c8ea1,0x5a05df1b,0x2d02ef8d
  };
  guint32 c = crc ^ 0xffffffffu;
  gsize i;

  for (i = 0; i < len; i++)
    c = table[(c ^ buf[i]) & 0xff] ^ (c >> 8);

  return c ^ 0xffffffffu;
}

gchar *
chomikuj_crc32_hex (const gchar  *path,
                    GError      **error)
{
  GFile *file;
  GFileInputStream *stream;
  guint32 crc = 0;
  gchar *res;
  guint8 buf[65536];
  gssize n;

  file = g_file_new_for_path (path);
  stream = g_file_read (file, NULL, error);
  g_object_unref (file);
  if (stream == NULL)
    return NULL;

  while ((n = g_input_stream_read (G_INPUT_STREAM (stream), buf, sizeof buf,
                                   NULL, error)) > 0)
    crc = crc32_update (crc, buf, (gsize) n);

  g_input_stream_close (G_INPUT_STREAM (stream), NULL, NULL);
  g_object_unref (stream);

  if (n < 0)
    return NULL;

  res = g_strdup_printf ("%x", crc);
  return res;
}

/* ------------------------------------------------------------------ */
/*  HTTP                                                               */
/* ------------------------------------------------------------------ */

static gboolean
method_is_idempotent (const gchar *method)
{
  return g_strcmp0 (method, "GET") == 0 ||
         g_strcmp0 (method, "HEAD") == 0 ||
         g_strcmp0 (method, "DELETE") == 0 ||
         g_strcmp0 (method, "OPTIONS") == 0;
}

static GBytes *
chomikuj_http (ChomikujClient  *self,
               const gchar     *method,
               const gchar     *url,
               const gchar     *body,
               const gchar     *token,
               gboolean         send_api_key,
               gboolean         may_retry,
               guint           *out_status,
               GCancellable    *cancellable,
               GError         **error)
{
  gboolean idempotent = method_is_idempotent (method);
  /* A request may be retried when the method is safe to repeat, or when the
   * caller vouches for it (e.g. the upload negotiation). */
  gboolean retryable = idempotent || may_retry;
  guint attempt = 0;
  GBytes *bytes = NULL;

  *out_status = 0;

  while (TRUE)
    {
      SoupMessage *msg;
      SoupMessageHeaders *headers;
      GError *local_error = NULL;
      guint status;

      msg = soup_message_new (method, url);
      headers = soup_message_get_request_headers (msg);
      soup_message_headers_append (headers, "User-Agent", self->user_agent);
      soup_message_headers_append (headers, "Accept", "application/json");
      soup_message_headers_append (headers, "Token", token);
      if (send_api_key && self->api_key != NULL)
        soup_message_headers_append (headers, "Api-Key", self->api_key);

      if (body != NULL)
        {
          GBytes *req = g_bytes_new (body, strlen (body));
          soup_message_set_request_body_from_bytes (msg,
                                                    "application/json; charset=utf-8",
                                                    req);
          g_bytes_unref (req);
        }

      bytes = soup_session_send_and_read (self->session, msg, cancellable,
                                          &local_error);
      status = soup_message_get_status (msg);
      g_object_unref (msg);

      if (bytes == NULL)
        {
          if (retryable && !g_cancellable_is_cancelled (cancellable) &&
              attempt < self->max_retries)
            {
              attempt++;
              g_clear_error (&local_error);
              g_usleep (500 * 1000 * (1 << (attempt - 1)));
              continue;
            }
          g_propagate_error (error, local_error);
          return NULL;
        }

      if ((status == 429 ||
           (retryable && (status == 408 || status >= 500))) &&
          attempt < self->max_retries)
        {
          g_bytes_unref (bytes);
          bytes = NULL;
          attempt++;
          g_usleep (500 * 1000 * (1 << (attempt - 1)));
          continue;
        }

      *out_status = status;
      return bytes;
    }
}

static void
set_business_error (gint64       code,
                    const gchar *message,
                    GError     **error)
{
  GIOErrorEnum io_code;

  switch (code)
    {
    case 1:   /* SameName */
    case 5:   /* NameExistsAtDestination */
      io_code = G_IO_ERROR_EXISTS;
      break;
    case 2:   /* EmptyName */
    case 4:   /* EndsWithDot */
    case 8:   /* InvalidChars */
    case 2000:
    case 2001:
    case 2002:
    case 2003:
    case 2008:
    case 2010:
    case 3002:
    case 3004:
      io_code = (code == 5 || code == 2003) ? G_IO_ERROR_EXISTS
                                            : G_IO_ERROR_INVALID_ARGUMENT;
      break;
    case 11:
    case 3404:
    case 601:
      io_code = G_IO_ERROR_NOT_FOUND;
      break;
    case 12:
    case 602:
      io_code = G_IO_ERROR_PERMISSION_DENIED;
      break;
    case 605:
      io_code = G_IO_ERROR_NO_SPACE;
      break;
    default:
      io_code = G_IO_ERROR_FAILED;
      break;
    }

  g_set_error (error, G_IO_ERROR, io_code, "%s",
               message != NULL ? message : "Chomikuj business error");
}

static void
set_http_error (guint status, JsonObject *obj, GError **error)
{
  const gchar *message = NULL;
  GIOErrorEnum io_code;

  if (obj != NULL && json_object_has_member (obj, "Message"))
    message = json_object_get_string_member (obj, "Message");

  switch (status)
    {
    case 400: io_code = G_IO_ERROR_INVALID_ARGUMENT; break;
    case 401: io_code = G_IO_ERROR_PERMISSION_DENIED; message = message ? message : "Authentication failed"; break;
    case 403: io_code = G_IO_ERROR_PERMISSION_DENIED; break;
    case 404: io_code = G_IO_ERROR_NOT_FOUND; break;
    case 423: io_code = G_IO_ERROR_PERMISSION_DENIED; message = message ? message : "Account blocked"; break;
    case 503: io_code = G_IO_ERROR_FAILED; message = message ? message : "Service unavailable"; break;
    default:  io_code = G_IO_ERROR_FAILED; break;
    }

  g_set_error (error, G_IO_ERROR, io_code, "Chomikuj API error (HTTP %u)%s%s",
               status,
               message != NULL ? ": " : "",
               message != NULL ? message : "");
}

static JsonObject *
parse_json_object (GBytes *bytes)
{
  const gchar *data;
  gsize len;
  JsonParser *parser;
  JsonNode *root;
  JsonObject *obj = NULL;

  data = g_bytes_get_data (bytes, &len);
  if (data == NULL || len == 0)
    return NULL;

  parser = json_parser_new ();
  if (json_parser_load_from_data (parser, data, (gssize) len, NULL))
    {
      root = json_parser_get_root (parser);
      if (root != NULL && json_node_get_node_type (root) == JSON_NODE_OBJECT)
        obj = json_node_dup_object (root);
    }
  g_object_unref (parser);
  return obj;
}

/* Performs a signed API call.  Returns the parsed JSON object (owned by the
 * caller) or NULL when the response body is empty.  On failure, @error is set
 * (also when the body carries a non-success business Code). */
static JsonObject *
chomikuj_call (ChomikujClient  *self,
               const gchar     *method,
               const gchar     *path,
               const gchar     *query,
               const gchar     *body,
               gboolean         send_api_key,
               gboolean         may_retry,
               GCancellable    *cancellable,
               GError         **error)
{
  gchar *token;
  gchar *url;
  GBytes *bytes;
  JsonObject *obj;
  guint status = 0;

  token = chomikuj_sign (path, query, body);
  url = g_strdup_printf ("%s%s%s%s",
                         self->base_url, path,
                         (query != NULL && *query != '\0') ? "?" : "",
                         query != NULL ? query : "");

  bytes = chomikuj_http (self, method, url, body, token, send_api_key,
                         may_retry, &status, cancellable, error);
  g_free (token);
  g_free (url);
  if (bytes == NULL)
    return NULL;

  obj = parse_json_object (bytes);
  g_bytes_unref (bytes);

  if (status >= 400)
    {
      set_http_error (status, obj, error);
      g_clear_pointer (&obj, json_object_unref);
      return NULL;
    }

  if (obj != NULL && json_object_has_member (obj, "Code"))
    {
      gint64 code = json_object_get_int_member (obj, "Code");
      if (code != 0 && code != 200 && code != 201)
        {
          const gchar *message = NULL;
          if (json_object_has_member (obj, "Message"))
            message = json_object_get_string_member (obj, "Message");
          set_business_error (code, message, error);
          json_object_unref (obj);
          return NULL;
        }
    }

  return obj;
}

static gchar *
json_object_to_string (JsonObject *obj)
{
  JsonNode *node;
  gchar *str;

  node = json_node_new (JSON_NODE_OBJECT);
  json_node_take_object (node, obj);
  str = json_to_string (node, FALSE);
  json_node_unref (node);
  return str;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

ChomikujClient *
chomikuj_client_new (const gchar   *account_name,
                     GCancellable  *cancellable,
                     GError       **error)
{
  ChomikujClient *self;
  gchar *device_id;

  self = g_new0 (ChomikujClient, 1);
  self->session = soup_session_new ();
  soup_session_set_timeout (self->session, 30);

  device_id = g_uuid_string_random ();
  self->user_agent = g_strdup_printf ("android/%s (%s; %s)",
                                      CHOMIKUJ_CLIENT_VER, device_id, "GVfs");
  g_free (device_id);

  /* CHOMIKUJ_BASE_URL lets the test suite point the client at a local mock
   * server in order to exercise the retry paths deterministically. */
  {
    const gchar *base_url = g_getenv ("CHOMIKUJ_BASE_URL");

    self->base_url = g_strdup (base_url != NULL && *base_url != '\0'
                               ? base_url : CHOMIKUJ_BASE_URL);
  }
  self->account_name = g_strdup (account_name);
  self->max_retries = 2;

  return self;
}

void
chomikuj_client_free (ChomikujClient *client)
{
  if (client == NULL)
    return;

  g_clear_object (&client->session);
  g_free (client->base_url);
  g_free (client->user_agent);
  g_free (client->account_name);
  g_free (client->account_id);
  g_free (client->api_key);
  g_free (client->avatar_url);
  g_free (client);
}

gboolean
chomikuj_client_login (ChomikujClient  *client,
                       const gchar     *password,
                       GCancellable    *cancellable,
                       GError         **error)
{
  JsonObject *req;
  gchar *body;
  JsonObject *resp;

  req = json_object_new ();
  json_object_set_string_member (req, "AccountName", client->account_name);
  json_object_set_string_member (req, "Password", password);
  body = json_object_to_string (req);

  resp = chomikuj_call (client, "POST",
                        CHOMIKUJ_API_PREFIX "/account/login",
                        NULL, body, FALSE, FALSE, cancellable, error);
  g_free (body);

  if (resp == NULL)
    return FALSE;

  if (json_object_has_member (resp, "ApiKey"))
    client->api_key = g_strdup (json_object_get_string_member (resp, "ApiKey"));
  if (json_object_has_member (resp, "AccountId"))
    {
      JsonNode *n = json_object_get_member (resp, "AccountId");
      if (n != NULL && json_node_get_value_type (n) == G_TYPE_INT64)
        client->account_id = g_strdup_printf ("%" G_GINT64_FORMAT,
                                              json_object_get_int_member (resp, "AccountId"));
      else
        client->account_id = g_strdup (json_object_get_string_member (resp, "AccountId"));
    }
  if (json_object_has_member (resp, "AccountName"))
    {
      g_free (client->account_name);
      client->account_name = g_strdup (json_object_get_string_member (resp, "AccountName"));
    }
  if (json_object_has_member (resp, "AvatarUrl"))
    client->avatar_url = g_strdup (json_object_get_string_member (resp, "AvatarUrl"));

  json_object_unref (resp);

  if (client->api_key == NULL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "Chomikuj login returned no session key");
      return FALSE;
    }

  return TRUE;
}

const gchar *
chomikuj_client_get_account_id (ChomikujClient *client)
{
  return client->account_id;
}

const gchar *
chomikuj_client_get_account_name (ChomikujClient *client)
{
  return client->account_name;
}

const gchar *
chomikuj_client_get_avatar_url (ChomikujClient *client)
{
  return client->avatar_url;
}

void
chomikuj_entry_free (ChomikujEntry *entry)
{
  if (entry == NULL)
    return;
  g_free (entry->name);
  g_free (entry->extension);
  g_free (entry->media_type);
  g_free (entry);
}

static void
parse_folder_entry (JsonObject *o, GList **out)
{
  ChomikujEntry *e = g_new0 (ChomikujEntry, 1);

  e->is_dir = TRUE;
  if (json_object_has_member (o, "Id"))
    e->id = json_object_get_int_member (o, "Id");
  if (json_object_has_member (o, "Name"))
    e->name = g_strdup (json_object_get_string_member (o, "Name"));
  if (json_object_has_member (o, "HasPassword"))
    e->has_password = json_object_get_boolean_member (o, "HasPassword");
  if (json_object_has_member (o, "IsHidden"))
    e->hidden = json_object_get_boolean_member (o, "IsHidden");
  if (e->name == NULL)
    e->name = g_strdup ("");

  *out = g_list_prepend (*out, e);
}

static void
parse_file_entry (JsonObject *o, GList **out)
{
  ChomikujEntry *e = g_new0 (ChomikujEntry, 1);
  const gchar *name = NULL;
  const gchar *type = NULL;

  e->is_dir = FALSE;
  if (json_object_has_member (o, "FileId"))
    e->id = json_object_get_int_member (o, "FileId");
  if (json_object_has_member (o, "FileName"))
    name = json_object_get_string_member (o, "FileName");
  if (json_object_has_member (o, "FileType"))
    type = json_object_get_string_member (o, "FileType");
  if (json_object_has_member (o, "MediaType"))
    e->media_type = g_strdup (json_object_get_string_member (o, "MediaType"));
  if (json_object_has_member (o, "IsHidden"))
    e->hidden = json_object_get_boolean_member (o, "IsHidden");
  if (json_object_has_member (o, "Size"))
    e->size = json_object_get_int_member (o, "Size") * 1024;

  if (type != NULL && *type != '\0')
    e->extension = g_strdup (type);
  e->name = chomikuj_join_name (name, type);
  if (e->name == NULL)
    e->name = g_strdup ("");

  *out = g_list_prepend (*out, e);
}

GList *
chomikuj_client_list_folder (ChomikujClient  *client,
                             const gchar     *parent_id,
                             GCancellable    *cancellable,
                             GError         **error)
{
  GList *entries = NULL;
  gint page;
  gchar *escaped_parent;

  escaped_parent = g_uri_escape_string (parent_id != NULL ? parent_id : "0",
                                        NULL, TRUE);

  for (page = 1; page <= CHOMIKUJ_MAX_PAGE; page++)
    {
      gchar *query;
      JsonObject *resp;
      JsonArray *folders, *files;
      guint i;

      query = g_strdup_printf ("Parent=%s&page=%d", escaped_parent, page);
      resp = chomikuj_call (client, "GET", CHOMIKUJ_API_PREFIX "/folders",
                            query, NULL, TRUE, FALSE, cancellable, error);
      g_free (query);

      if (resp == NULL)
        {
          g_list_free_full (entries, (GDestroyNotify) chomikuj_entry_free);
          g_free (escaped_parent);
          return NULL;
        }

      if (json_object_has_member (resp, "Folders"))
        {
          folders = json_object_get_array_member (resp, "Folders");
          for (i = 0; folders != NULL && i < json_array_get_length (folders); i++)
            parse_folder_entry (json_array_get_object_element (folders, i), &entries);
        }

      if (json_object_has_member (resp, "Files"))
        {
          files = json_object_get_array_member (resp, "Files");
          for (i = 0; files != NULL && i < json_array_get_length (files); i++)
            parse_file_entry (json_array_get_object_element (files, i), &entries);
        }

      {
        gboolean next = FALSE;
        if (json_object_has_member (resp, "IsNextPageAvailable"))
          next = json_object_get_boolean_member (resp, "IsNextPageAvailable");
        json_object_unref (resp);
        if (!next)
          break;
      }
    }

  g_free (escaped_parent);
  return g_list_reverse (entries);
}

gboolean
chomikuj_client_make_folder (ChomikujClient  *client,
                             const gchar     *parent_id,
                             const gchar     *name,
                             gint64          *out_id,
                             GCancellable    *cancellable,
                             GError         **error)
{
  JsonObject *req;
  JsonObject *resp;
  gchar *body;
  gchar *end;
  gint64 parsed_parent;

  req = json_object_new ();
  json_object_set_string_member (req, "FolderName", name);
  parsed_parent = g_ascii_strtoll (parent_id, &end, 10);
  if (end != NULL && *end == '\0')
    json_object_set_int_member (req, "ParentId", parsed_parent);
  else
    json_object_set_string_member (req, "ParentId", parent_id);
  body = json_object_to_string (req);

  resp = chomikuj_call (client, "POST", CHOMIKUJ_API_PREFIX "/folders/create",
                        NULL, body, TRUE, FALSE, cancellable, error);
  g_free (body);
  if (resp == NULL)
    return FALSE;

  if (out_id != NULL)
    {
      if (json_object_has_member (resp, "FolderId"))
        *out_id = json_object_get_int_member (resp, "FolderId");
      else
        *out_id = 0;
    }
  json_object_unref (resp);
  return TRUE;
}

gboolean
chomikuj_client_change_name (ChomikujClient  *client,
                             gboolean         is_dir,
                             gint64           id,
                             const gchar     *new_name,
                             GCancellable    *cancellable,
                             GError         **error)
{
  JsonObject *req;
  JsonObject *resp;
  gchar *body;
  const gchar *path;

  req = json_object_new ();
  if (is_dir)
    {
      json_object_set_int_member (req, "FolderId", id);
      json_object_set_string_member (req, "FolderName", new_name);
      path = CHOMIKUJ_API_PREFIX "/folders/changeName";
    }
  else
    {
      json_object_set_int_member (req, "FileId", id);
      json_object_set_string_member (req, "FileName", new_name);
      path = CHOMIKUJ_API_PREFIX "/files/changeName";
    }
  body = json_object_to_string (req);

  resp = chomikuj_call (client, "POST", path, NULL, body, TRUE, FALSE,
                        cancellable, error);
  g_free (body);
  if (resp == NULL)
    return FALSE;
  json_object_unref (resp);
  return TRUE;
}

static void
array_add_ids (JsonArray *array, const gint64 *ids, gsize n)
{
  gsize i;
  for (i = 0; i < n; i++)
    json_array_add_int_element (array, ids[i]);
}

gboolean
chomikuj_client_delete (ChomikujClient  *client,
                        const gint64    *file_ids,
                        gsize            n_files,
                        const gint64    *folder_ids,
                        gsize            n_folders,
                        GCancellable    *cancellable,
                        GError         **error)
{
  JsonObject *req;
  JsonObject *resp;
  gchar *body;

  req = json_object_new ();
  json_object_set_array_member (req, "Files", json_array_new ());
  json_object_set_array_member (req, "Folders", json_array_new ());
  array_add_ids (json_object_get_array_member (req, "Files"), file_ids, n_files);
  array_add_ids (json_object_get_array_member (req, "Folders"), folder_ids, n_folders);
  body = json_object_to_string (req);

  /* The endpoint returns an empty body; success is HTTP-only. */
  resp = chomikuj_call (client, "POST", CHOMIKUJ_API_PREFIX "/files/delete",
                        NULL, body, TRUE, FALSE, cancellable, error);
  g_free (body);
  if (resp != NULL)
    json_object_unref (resp);
  return error == NULL || *error == NULL;
}

gboolean
chomikuj_client_move (ChomikujClient  *client,
                      const gchar     *source_folder_id,
                      const gchar     *target_folder_id,
                      const gint64    *file_ids,
                      gsize            n_files,
                      const gint64    *folder_ids,
                      gsize            n_folders,
                      GCancellable    *cancellable,
                      GError         **error)
{
  JsonObject *req;
  JsonObject *resp;
  gchar *body;
  gchar *end;
  gint64 v;

  req = json_object_new ();
  v = g_ascii_strtoll (target_folder_id, &end, 10);
  if (end != NULL && *end == '\0')
    json_object_set_int_member (req, "TargetFolderId", v);
  else
    json_object_set_string_member (req, "TargetFolderId", target_folder_id);
  v = g_ascii_strtoll (source_folder_id, &end, 10);
  if (end != NULL && *end == '\0')
    json_object_set_int_member (req, "SourceFolderId", v);
  else
    json_object_set_string_member (req, "SourceFolderId", source_folder_id);
  json_object_set_array_member (req, "Files", json_array_new ());
  json_object_set_array_member (req, "Folders", json_array_new ());
  array_add_ids (json_object_get_array_member (req, "Files"), file_ids, n_files);
  array_add_ids (json_object_get_array_member (req, "Folders"), folder_ids, n_folders);
  body = json_object_to_string (req);

  resp = chomikuj_call (client, "POST", CHOMIKUJ_API_PREFIX "/files/move",
                        NULL, body, TRUE, FALSE, cancellable, error);
  g_free (body);
  if (resp != NULL)
    json_object_unref (resp);
  return error == NULL || *error == NULL;
}

gchar *
chomikuj_client_get_download_url (ChomikujClient  *client,
                                  gint64           file_id,
                                  GCancellable    *cancellable,
                                  GError         **error)
{
  gchar *query;
  JsonObject *resp;
  gchar *url = NULL;

  query = g_strdup_printf ("FileId=%" G_GINT64_FORMAT, file_id);
  resp = chomikuj_call (client, "GET", CHOMIKUJ_API_PREFIX "/files/download",
                        query, NULL, TRUE, FALSE, cancellable, error);
  g_free (query);
  if (resp == NULL)
    return NULL;

  if (json_object_has_member (resp, "FileUrl"))
    url = g_strdup (json_object_get_string_member (resp, "FileUrl"));
  json_object_unref (resp);

  if (url == NULL)
    g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                         "Chomikuj API returned no download URL");
  return url;
}

GInputStream *
chomikuj_client_open_read (ChomikujClient  *client,
                           gint64           file_id,
                           goffset          offset,
                           SoupMessage    **out_msg,
                           GCancellable    *cancellable,
                           GError         **error)
{
  gchar *url;
  SoupMessage *msg;
  GInputStream *stream;
  guint status;

  url = chomikuj_client_get_download_url (client, file_id, cancellable, error);
  if (url == NULL)
    return NULL;

  msg = soup_message_new ("GET", url);
  soup_message_headers_append (soup_message_get_request_headers (msg),
                               "User-Agent", client->user_agent);
  if (offset > 0)
    {
      gchar *range = g_strdup_printf ("bytes=%" G_GINT64_FORMAT "-", offset);
      soup_message_headers_append (soup_message_get_request_headers (msg),
                                   "Range", range);
      g_free (range);
    }

  stream = soup_session_send (client->session, msg, cancellable, error);
  if (stream == NULL)
    {
      g_object_unref (msg);
      g_free (url);
      return NULL;
    }

  status = soup_message_get_status (msg);
  if (status != 200 && status != 206)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Chomikuj download failed (HTTP %u)", status);
      g_object_unref (stream);
      g_object_unref (msg);
      g_free (url);
      return NULL;
    }

  g_free (url);
  *out_msg = msg;
  return stream;
}

/* Sleeps for a jittered, exponentially increasing delay while remaining
 * responsive to @cancellable.  @attempt is 1-based.  Returns FALSE if the
 * operation was cancelled while waiting. */
static gboolean
upload_retry_sleep (guint         attempt,
                    GCancellable *cancellable)
{
  guint64 delay, step, remaining;

  delay = (guint64) CHOMIKUJ_RETRY_BASE_US << (MIN (MAX (attempt, 1), 5) - 1);
  delay = MIN (delay, (guint64) CHOMIKUJ_RETRY_MAX_US);
  if (delay > 0)
    delay = (guint64) g_random_int_range (0, (gint) delay);

  remaining = delay;
  while (remaining > 0)
    {
      if (g_cancellable_is_cancelled (cancellable))
        return FALSE;
      step = MIN (remaining, (guint64) 100000);
      g_usleep ((gulong) step);
      remaining -= step;
    }

  return !g_cancellable_is_cancelled (cancellable);
}

static guint
send_chunk (ChomikujClient  *client,
            const gchar     *url,
            const gchar     *filename,
            const guint8    *data,
            gsize            len,
            goffset          start,
            goffset          end,
            GCancellable    *cancellable,
            GError         **error)
{
  gchar *boundary;
  gchar *escaped;
  GString *body;
  gchar *ctype, *range;
  GBytes *bytes, *resp;
  SoupMessage *msg;
  SoupMessageHeaders *headers;
  guint status = 0;

  boundary = g_strdup_printf ("***%" G_GINT64_FORMAT "***", g_get_real_time ());
  escaped = escape_filename (filename);
  body = g_string_new (NULL);
  g_string_append_printf (body, "--%s\r\n", boundary);
  g_string_append_printf (body,
                          "Content-Disposition: form-data; name=\"files[]\";"
                          "filename=\"%s\"\r\n\r\n", escaped);
  g_string_append_len (body, (const gchar *) data, len);
  g_string_append_printf (body, "\r\n--%s--\r\n", boundary);

  ctype = g_strdup_printf ("multipart/form-data;boundary=%s", boundary);
  range = g_strdup_printf ("%" G_GINT64_FORMAT "-%" G_GINT64_FORMAT, start, end);

  msg = soup_message_new ("POST", url);
  headers = soup_message_get_request_headers (msg);
  soup_message_headers_append (headers, "User-Agent", client->user_agent);
  soup_message_headers_append (headers, "Connection", "Keep-Alive");
  soup_message_headers_append (headers, "ENCTYPE", "multipart/form-data");
  soup_message_headers_append (headers, "File-Range", range);

  bytes = g_bytes_new (body->str, body->len);
  soup_message_set_request_body_from_bytes (msg, ctype, bytes);
  g_bytes_unref (bytes);

  resp = soup_session_send_and_read (client->session, msg, cancellable, error);
  if (resp != NULL)
    {
      status = soup_message_get_status (msg);
      g_bytes_unref (resp);
    }

  g_object_unref (msg);
  g_string_free (body, TRUE);
  g_free (boundary);
  g_free (escaped);
  g_free (ctype);
  g_free (range);

  return status;
}

gboolean
chomikuj_client_upload_file (ChomikujClient       *client,
                             const gchar          *local_path,
                             const gchar          *folder_id,
                             const gchar          *remote_name,
                             ChomikujProgressFunc  progress,
                             gpointer              user_data,
                             GCancellable         *cancellable,
                             GError              **error)
{
  GStatBuf st;
  JsonObject *req, *resp;
  gchar *body, *crc, *end;
  gchar *url = NULL;
  gint64 size;
  gint64 chunk = 0;
  gboolean completed = FALSE;
  GFile *file = NULL;
  GFileInputStream *in = NULL;
  guint retries = 0, resets = 0, terminal = 0;
  gboolean ok = FALSE;

  if (g_stat (local_path, &st) != 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                   "Cannot stat %s", local_path);
      return FALSE;
    }
  size = (gint64) st.st_size;

  crc = chomikuj_crc32_hex (local_path, error);
  if (crc == NULL)
    return FALSE;

  req = json_object_new ();
  json_object_set_string_member (req, "Name", remote_name);
  json_object_set_int_member (req, "Size", size);
  if (folder_id != NULL)
    {
      gint64 fid = g_ascii_strtoll (folder_id, &end, 10);
      if (end != NULL && *end == '\0')
        json_object_set_int_member (req, "FolderId", fid);
      else
        json_object_set_string_member (req, "FolderId", folder_id);
    }
  json_object_set_string_member (req, "Hash", crc);
  g_free (crc);
  body = json_object_to_string (req);

  resp = chomikuj_call (client, "POST",
                        CHOMIKUJ_API_PREFIX "/files/upload/partialUpload",
                        NULL, body, TRUE, TRUE, cancellable, error);
  g_free (body);
  if (resp == NULL)
    return FALSE;

  if (json_object_has_member (resp, "UploadCompleted"))
    completed = json_object_get_boolean_member (resp, "UploadCompleted");
  if (json_object_has_member (resp, "Chunk"))
    chunk = json_object_get_int_member (resp, "Chunk");
  if (json_object_has_member (resp, "Url") &&
      !json_object_get_null_member (resp, "Url"))
    url = g_strdup (json_object_get_string_member (resp, "Url"));
  json_object_unref (resp);

  if (completed)
    {
      g_free (url);
      if (progress != NULL)
        progress (size, size, user_data);
      return TRUE;
    }

  if (url == NULL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "Chomikuj upload returned no upload URL");
      return FALSE;
    }

  file = g_file_new_for_path (local_path);
  in = g_file_read (file, cancellable, error);
  if (in == NULL)
    goto out;

  while (TRUE)
    {
      gboolean complete;
      goffset start, end_off;
      guint8 *buf = NULL;
      gsize chunk_len = 0;
      guint code;

      complete = chunk >= size;
      start = (goffset) chunk;

      if (!complete)
        {
          gsize toread = (gsize) MIN ((gint64) CHOMIKUJ_UPLOAD_CHUNK, size - chunk);
          gsize got = 0;

          buf = g_malloc (toread);
          if (!g_seekable_seek (G_SEEKABLE (in), start, G_SEEK_SET,
                                cancellable, error))
            {
              g_free (buf);
              goto out;
            }
          while (got < toread)
            {
              gssize n = g_input_stream_read (G_INPUT_STREAM (in), buf + got,
                                              toread - got, cancellable, error);
              if (n <= 0)
                {
                  if (n == 0)
                    g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                                         "Unexpected end of file during upload");
                  g_free (buf);
                  goto out;
                }
              got += (gsize) n;
            }
          chunk_len = toread;
        }

      end_off = complete ? start : start + (goffset) chunk_len;
      code = send_chunk (client, url, remote_name, buf, chunk_len,
                         start, end_off, cancellable, error);
      g_free (buf);

      if (code == 200)
        {
          if (progress != NULL)
            progress (size, size, user_data);
          ok = TRUE;
          break;
        }
      else if (code == 206)
        {
          retries = 0;
          if (complete)
            {
              if (++terminal >= 2)
                {
                  ok = TRUE;
                  break;
                }
              continue;
            }
          chunk = (gint64) end_off;
          if (progress != NULL)
            progress ((goffset) chunk, (goffset) size, user_data);
          continue;
        }
      else if (code == 409)
        {
          if (++resets > CHOMIKUJ_MAX_UPLOAD_RESETS)
            {
              g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                                   "Upload reset too many times");
              goto out;
            }
          retries = 0;
          chunk = 0;
          terminal = 0;
          if (!upload_retry_sleep (resets, cancellable))
            {
              g_cancellable_set_error_if_cancelled (cancellable, error);
              goto out;
            }
          continue;
        }
      else if (code == 0 || code == 408 || code == 410 || code == 429 ||
               (code >= 500 && code < 600))
        {
          /* A dropped connection (code == 0) or a transient server status:
           * retry the very same chunk after a jittered backoff. */
          if (g_cancellable_is_cancelled (cancellable))
            {
              if (error != NULL && *error == NULL)
                g_cancellable_set_error_if_cancelled (cancellable, error);
              goto out;
            }
          if (++retries > CHOMIKUJ_MAX_CHUNK_RETRIES)
            {
              if (code != 0)
                g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                             "Upload failed (HTTP %u)", code);
              /* code == 0: keep the network error set by send_chunk() */
              goto out;
            }
          if (code == 0)
            g_clear_error (error);
          if (!upload_retry_sleep (retries, cancellable))
            {
              g_cancellable_set_error_if_cancelled (cancellable, error);
              goto out;
            }
          continue;
        }
      else if (code >= 400)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "Upload failed (HTTP %u)", code);
          goto out;
        }
      else
        {
          ok = TRUE;
          break;
        }
    }

 out:
  g_clear_object (&in);
  g_clear_object (&file);
  g_free (url);
  return ok;
}
