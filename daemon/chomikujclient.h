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

#ifndef __CHOMIKUJ_CLIENT_H__
#define __CHOMIKUJ_CLIENT_H__

#include <glib.h>
#include <gio/gio.h>
#include <libsoup/soup.h>

G_BEGIN_DECLS

typedef struct _ChomikujClient ChomikujClient;

/* One entry of a folder listing.  Identifiers are the numeric server ids;
 * folder id "0" is the account root. */
typedef struct
{
  gint64 id;
  gchar *name;              /* full name, extension included */
  gint64 size;              /* bytes (0 for folders) */
  gchar *extension;         /* file extension without the dot, or NULL */
  gchar *media_type;        /* string enum, e.g. "Music", or NULL */
  guint is_dir : 1;
  guint hidden : 1;
  guint has_password : 1;
} ChomikujEntry;

typedef void (*ChomikujProgressFunc) (goffset current,
                                      goffset total,
                                      gpointer user_data);

ChomikujClient *chomikuj_client_new  (const gchar   *account_name,
                                      GCancellable  *cancellable,
                                      GError       **error);
void            chomikuj_client_free (ChomikujClient *client);

gboolean chomikuj_client_login (ChomikujClient *client,
                                const gchar    *password,
                                GCancellable   *cancellable,
                                GError        **error);

const gchar *chomikuj_client_get_account_id   (ChomikujClient *client);
const gchar *chomikuj_client_get_account_name (ChomikujClient *client);
const gchar *chomikuj_client_get_avatar_url   (ChomikujClient *client);

GList *chomikuj_client_list_folder (ChomikujClient *client,
                                    const gchar    *parent_id,
                                    GCancellable   *cancellable,
                                    GError        **error);

gboolean chomikuj_client_make_folder (ChomikujClient *client,
                                      const gchar    *parent_id,
                                      const gchar    *name,
                                      gint64         *out_id,
                                      GCancellable   *cancellable,
                                      GError        **error);

gboolean chomikuj_client_change_name (ChomikujClient *client,
                                      gboolean        is_dir,
                                      gint64          id,
                                      const gchar    *new_name,
                                      GCancellable   *cancellable,
                                      GError        **error);

gboolean chomikuj_client_delete (ChomikujClient *client,
                                 const gint64   *file_ids,
                                 gsize           n_files,
                                 const gint64   *folder_ids,
                                 gsize           n_folders,
                                 GCancellable   *cancellable,
                                 GError        **error);

gboolean chomikuj_client_move (ChomikujClient *client,
                               const gchar    *source_folder_id,
                               const gchar    *target_folder_id,
                               const gint64   *file_ids,
                               gsize           n_files,
                               const gint64   *folder_ids,
                               gsize           n_folders,
                               GCancellable   *cancellable,
                               GError        **error);

/* Opens a stream for reading @file_id, starting at @offset.  On success the
 * caller owns the returned stream and must unref @out_msg (which is kept so
 * the backend can query the response status / headers). */
gchar *chomikuj_client_get_download_url (ChomikujClient *client,
                                         gint64          file_id,
                                         GCancellable   *cancellable,
                                         GError        **error);

GInputStream *chomikuj_client_open_read (ChomikujClient  *client,
                                         gint64           file_id,
                                         goffset          offset,
                                         SoupMessage    **out_msg,
                                         GCancellable    *cancellable,
                                         GError         **error);

gboolean chomikuj_client_upload_file (ChomikujClient       *client,
                                      const gchar          *local_path,
                                      const gchar          *folder_id,
                                      const gchar          *remote_name,
                                      ChomikujProgressFunc  progress,
                                      gpointer              user_data,
                                      GCancellable         *cancellable,
                                      GError              **error);

void chomikuj_entry_free (ChomikujEntry *entry);

/* Exposed for unit testing. */

/* The reverse-engineered request-signing secret. */
const gchar *chomikuj_secret (void);
/* Decodes BuildConfig.SECRET_KEY exactly as the client does. */
gchar       *chomikuj_decode_secret (const gchar *key_csv);
/* Token = md5( (path + "?" + query + body + SECRET).substring(1) ). */
gchar       *chomikuj_sign (const gchar *path,
                            const gchar *query,
                            const gchar *body);
/* Splits a full name at the last dot; @extension may be NULL. */
void         chomikuj_split_name (const gchar  *full_name,
                                  gchar       **base,
                                  gchar       **extension);
/* Joins a base name and extension using the same rule as the server. */
gchar       *chomikuj_join_name (const gchar *base,
                                 const gchar *extension);
/* CRC32 of a file as a lowercase, unpadded hex string. */
gchar       *chomikuj_crc32_hex (const gchar  *path,
                                 GError      **error);

G_END_DECLS

#endif /* __CHOMIKUJ_CLIENT_H__ */
