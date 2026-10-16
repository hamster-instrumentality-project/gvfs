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
 * A GVfs backend for the Chomikuj.pl file sharing service, built on the
 * "Mobile API v3" (see chomikujclient.c).  Mount with:
 *
 *     gio mount chomikuj://account/
 *
 * Capabilities and limitations of the underlying API (see MOBILE_PROTOCOL.md):
 *   - no file/folder timestamps are exposed, so mtime is always unset;
 *   - upload never overwrites: replace() deletes the existing file first;
 *   - there is no server-side copy, but copy is emulated via download+upload;
 *   - listing sizes are floored kilobytes.
 */

#include <config.h>

#include <string.h>
#include <glib/gstdio.h>
#include <glib/gi18n.h>
#include <gio/gio.h>

#include "gvfsbackendchomikuj.h"
#include "chomikujclient.h"
#include "gvfskeyring.h"

#include "gvfsjobmount.h"
#include "gvfsjobunmount.h"
#include "gvfsjobenumerate.h"
#include "gvfsjobqueryinfo.h"
#include "gvfsjobqueryinforead.h"
#include "gvfsjobqueryinfowrite.h"
#include "gvfsjobqueryfsinfo.h"
#include "gvfsjobopenforread.h"
#include "gvfsjobread.h"
#include "gvfsjobseekread.h"
#include "gvfsjobopenforwrite.h"
#include "gvfsjobwrite.h"
#include "gvfsjobseekwrite.h"
#include "gvfsjobtruncate.h"
#include "gvfsjobclosewrite.h"
#include "gvfsjobsetdisplayname.h"
#include "gvfsjobdelete.h"
#include "gvfsjobmakedirectory.h"
#include "gvfsjobmove.h"

#define ROOT_ID "0"
#define DIR_CACHE_TTL (5 * G_USEC_PER_SEC)

typedef struct
{
  GList *entries;      /* ChomikujEntry*, owned */
  gint64 fetched_at;
} DirCache;

typedef struct
{
  ChomikujClient *client;
  gint64 file_id;
  gchar *path;
  GInputStream *stream;
  SoupMessage *msg;
  goffset offset;
} ChomikujReadHandle;

typedef struct
{
  gchar *local_path;
  gchar *folder_id;
  gchar *name;
  GFileOutputStream *out;
  gboolean replace;
} ChomikujWriteHandle;

struct _GVfsBackendChomikuj
{
  GVfsBackend parent_instance;

  ChomikujClient *client;
  gchar *display_name;
  GHashTable *dir_cache;      /* folder_id -> DirCache* */
  GRecMutex mutex;
};

struct _GVfsBackendChomikujClass
{
  GVfsBackendClass parent_class;
};

G_DEFINE_TYPE (GVfsBackendChomikuj, g_vfs_backend_chomikuj, G_VFS_TYPE_BACKEND)

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static gchar **
path_segments (const gchar *path)
{
  gchar **raw;
  GPtrArray *arr;
  guint i;

  raw = g_strsplit (path != NULL ? path : "/", "/", -1);
  arr = g_ptr_array_new_with_free_func (g_free);
  for (i = 0; raw[i] != NULL; i++)
    {
      if (raw[i][0] != '\0')
        g_ptr_array_add (arr, g_strdup (raw[i]));
    }
  g_strfreev (raw);
  g_ptr_array_add (arr, NULL);
  return (gchar **) g_ptr_array_free (arr, FALSE);
}

static ChomikujEntry *
entry_copy (const ChomikujEntry *e)
{
  ChomikujEntry *c = g_new0 (ChomikujEntry, 1);
  c->id = e->id;
  c->name = g_strdup (e->name);
  c->size = e->size;
  c->extension = g_strdup (e->extension);
  c->media_type = g_strdup (e->media_type);
  c->is_dir = e->is_dir;
  c->hidden = e->hidden;
  c->has_password = e->has_password;
  return c;
}

static void
dir_cache_free (DirCache *cache)
{
  g_list_free_full (cache->entries, (GDestroyNotify) chomikuj_entry_free);
  g_free (cache);
}

static void
invalidate_dir (GVfsBackendChomikuj *self,
                const gchar          *folder_id)
{
  g_rec_mutex_lock (&self->mutex);
  g_hash_table_remove (self->dir_cache, folder_id);
  g_rec_mutex_unlock (&self->mutex);
}

static void
invalidate_all (GVfsBackendChomikuj *self)
{
  g_rec_mutex_lock (&self->mutex);
  g_hash_table_remove_all (self->dir_cache);
  g_rec_mutex_unlock (&self->mutex);
}

/* Returns a freshly allocated list of copies of the entries in @folder_id. */
static GList *
get_dir_entries (GVfsBackendChomikuj *self,
                 const gchar          *folder_id,
                 GCancellable         *cancellable,
                 GError              **error)
{
  DirCache *cache;
  gint64 now = g_get_monotonic_time ();
  GList *entries, *l, *copy = NULL;

  g_rec_mutex_lock (&self->mutex);
  cache = g_hash_table_lookup (self->dir_cache, folder_id);
  if (cache != NULL && now - cache->fetched_at < DIR_CACHE_TTL)
    {
      for (l = cache->entries; l != NULL; l = l->next)
        copy = g_list_prepend (copy, entry_copy (l->data));
      g_rec_mutex_unlock (&self->mutex);
      return g_list_reverse (copy);
    }
  g_rec_mutex_unlock (&self->mutex);

  entries = chomikuj_client_list_folder (self->client, folder_id, cancellable, error);
  if (entries == NULL && error != NULL && *error != NULL)
    return NULL;

  g_rec_mutex_lock (&self->mutex);
  cache = g_new0 (DirCache, 1);
  cache->entries = entries;
  cache->fetched_at = now;
  g_hash_table_insert (self->dir_cache, g_strdup (folder_id), cache);
  for (l = entries; l != NULL; l = l->next)
    copy = g_list_prepend (copy, entry_copy (l->data));
  g_rec_mutex_unlock (&self->mutex);

  return g_list_reverse (copy);
}

static ChomikujEntry *
find_entry (GVfsBackendChomikuj *self,
            const gchar          *folder_id,
            const gchar          *name,
            GCancellable         *cancellable,
            GError              **error)
{
  GList *entries, *l;
  ChomikujEntry *found = NULL;

  entries = get_dir_entries (self, folder_id, cancellable, error);
  if (entries == NULL && error != NULL && *error != NULL)
    return NULL;

  for (l = entries; l != NULL; l = l->next)
    {
      ChomikujEntry *e = l->data;
      if (g_strcmp0 (e->name, name) == 0)
        {
          found = entry_copy (e);
          break;
        }
    }

  g_list_free_full (entries, (GDestroyNotify) chomikuj_entry_free);
  return found;
}

/* Resolves a path to a folder id.  "/" maps to the root id. */
static gboolean
resolve_folder (GVfsBackendChomikuj  *self,
                const gchar          *path,
                gchar               **out_id,
                GCancellable         *cancellable,
                GError              **error)
{
  gchar **segs = path_segments (path);
  gchar *current = g_strdup (ROOT_ID);
  guint i;
  gboolean ok = TRUE;

  for (i = 0; ok && segs[i] != NULL; i++)
    {
      ChomikujEntry *e = find_entry (self, current, segs[i], cancellable, error);
      if (e == NULL)
        {
          if (error != NULL && *error == NULL)
            g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                         "Folder “%s” not found", path);
          ok = FALSE;
          break;
        }
      if (!e->is_dir)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_DIRECTORY,
                       "“%s” is not a folder", segs[i]);
          chomikuj_entry_free (e);
          ok = FALSE;
          break;
        }
      g_free (current);
      current = g_strdup_printf ("%" G_GINT64_FORMAT, e->id);
      chomikuj_entry_free (e);
    }

  g_strfreev (segs);

  if (!ok)
    {
      g_free (current);
      return FALSE;
    }

  *out_id = current;
  return TRUE;
}

/* Resolves the parent folder id and basename for a path to be created/removed. */
static gboolean
resolve_parent (GVfsBackendChomikuj  *self,
                const gchar          *path,
                gchar               **out_parent_id,
                gchar               **out_basename,
                GCancellable         *cancellable,
                GError              **error)
{
  gchar **segs;
  guint n, i;
  GString *parent_path;
  gboolean ok;

  *out_parent_id = NULL;
  *out_basename = NULL;

  segs = path_segments (path);
  n = g_strv_length (segs);

  if (n == 0)
    {
      g_strfreev (segs);
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                           "A name is required");
      return FALSE;
    }

  *out_basename = g_strdup (segs[n - 1]);

  parent_path = g_string_new ("/");
  for (i = 0; i + 1 < n; i++)
    {
      g_string_append (parent_path, segs[i]);
      g_string_append_c (parent_path, '/');
    }

  ok = resolve_folder (self, parent_path->str, out_parent_id, cancellable, error);
  g_string_free (parent_path, TRUE);
  g_strfreev (segs);

  return ok;
}

/* Resolves a full path to an entry (copy). */
static ChomikujEntry *
resolve_entry (GVfsBackendChomikuj  *self,
               const gchar          *path,
               GCancellable         *cancellable,
               GError              **error)
{
  gchar **segs = path_segments (path);
  guint n = g_strv_length (segs);
  gchar *current = g_strdup (ROOT_ID);
  ChomikujEntry *result = NULL;
  guint i;

  if (n == 0)
    {
      result = g_new0 (ChomikujEntry, 1);
      result->id = 0;
      result->is_dir = TRUE;
      result->name = g_strdup ("/");
      g_strfreev (segs);
      return result;
    }

  for (i = 0; i < n; i++)
    {
      ChomikujEntry *e = find_entry (self, current, segs[i], cancellable, error);
      if (e == NULL)
        {
          if (error != NULL && *error == NULL)
            g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                         "“%s” not found", path);
          break;
        }

      if (i + 1 == n)
        {
          result = e;
          break;
        }

      if (!e->is_dir)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_DIRECTORY,
                       "“%s” is not a folder", segs[i]);
          chomikuj_entry_free (e);
          break;
        }
      g_free (current);
      current = g_strdup_printf ("%" G_GINT64_FORMAT, e->id);
      chomikuj_entry_free (e);
    }

  g_free (current);
  g_strfreev (segs);
  return result;
}

static GFileInfo *
entry_to_file_info (ChomikujEntry          *e,
                    GFileAttributeMatcher  *matcher)
{
  GFileInfo *info;
  gchar *id;

  info = g_file_info_new ();
  g_file_info_set_name (info, e->name);
  g_file_info_set_display_name (info, e->name);
  g_file_info_set_file_type (info, e->is_dir ? G_FILE_TYPE_DIRECTORY
                                             : G_FILE_TYPE_REGULAR);
  g_file_info_set_size (info, e->is_dir ? 0 : e->size);
  /* The API's IsHidden on files is a visibility/privacy flag, not the Unix
   * dot-file sense, so only folders are exposed as hidden. */
  if (e->is_dir)
    g_file_info_set_attribute_boolean (info, G_FILE_ATTRIBUTE_STANDARD_IS_HIDDEN, e->hidden);
  g_file_info_set_attribute_boolean (info, G_FILE_ATTRIBUTE_STANDARD_IS_VIRTUAL, FALSE);

  id = g_strdup_printf ("%" G_GINT64_FORMAT, e->id);
  g_file_info_set_attribute_string (info, G_FILE_ATTRIBUTE_ID_FILE, id);
  g_free (id);

  if (e->is_dir)
    {
      GIcon *icon = g_themed_icon_new ("folder");
      g_file_info_set_content_type (info, "inode/directory");
      g_file_info_set_icon (info, icon);
      g_object_unref (icon);
    }
  else
    {
      gchar *ctype = g_content_type_guess (e->name, NULL, 0, NULL);
      GIcon *icon = g_content_type_get_icon (ctype);
      g_file_info_set_content_type (info, ctype);
      g_file_info_set_icon (info, icon);
      g_object_unref (icon);
      g_free (ctype);
    }

  return info;
}

/* ------------------------------------------------------------------ */
/*  Mount / unmount                                                    */
/* ------------------------------------------------------------------ */

static gchar *
get_password (GVfsBackendChomikuj *self,
              GMountSource         *source,
              const gchar          *account,
              GPasswordSave        *out_save,
              GError              **error)
{
  gchar *password = NULL;
  gchar *keyring_password = NULL;

  *out_save = G_PASSWORD_SAVE_NEVER;

  if (g_vfs_keyring_is_available () &&
      g_vfs_keyring_lookup_password (account, "chomikuj.pl", NULL, "chomikuj",
                                     NULL, NULL, 0, NULL, NULL, &keyring_password) &&
      keyring_password != NULL && *keyring_password != '\0')
    return keyring_password;

  g_free (keyring_password);

  if (source != NULL && !g_mount_source_is_dummy (source))
    {
      gboolean aborted = FALSE;
      gboolean res;
      gchar *prompt;
      GAskPasswordFlags flags = G_ASK_PASSWORD_NEED_PASSWORD;

      if (g_vfs_keyring_is_available ())
        flags |= G_ASK_PASSWORD_SAVING_SUPPORTED;

      prompt = g_strdup_printf (_("Authentication Required\n"
                                  "Enter password for “%s”:"), account);
      res = g_mount_source_ask_password (source, prompt, account, NULL, flags,
                                         &aborted, &password, NULL, NULL, NULL,
                                         out_save);
      g_free (prompt);

      if (!res || aborted || password == NULL)
        {
          g_free (password);
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
                               "Authentication cancelled");
          return NULL;
        }
      return password;
    }

  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_PERMISSION_DENIED,
                       "No password available for Chomikuj account");
  return NULL;
}

static void
g_vfs_backend_chomikuj_mount (GVfsBackend  *backend,
                              GVfsJobMount *job,
                              GMountSpec   *mount_spec,
                              GMountSource *mount_source,
                              gboolean      is_automount)
{
  GVfsBackendChomikuj *self = G_VFS_BACKEND_CHOMIKUJ (backend);
  GError *error = NULL;
  const gchar *host, *user, *account;
  gchar *password;
  GPasswordSave save;
  gchar *display;

  host = g_mount_spec_get (mount_spec, "host");
  user = g_mount_spec_get (mount_spec, "user");
  account = (user != NULL && *user != '\0') ? user : host;

  if (account == NULL || *account == '\0')
    {
      g_vfs_job_failed_literal (G_VFS_JOB (job), G_IO_ERROR,
                                G_IO_ERROR_INVALID_ARGUMENT,
                                _("No account specified; use chomikuj://account/"));
      return;
    }

  password = get_password (self, mount_source, account, &save, &error);
  if (password == NULL)
    {
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  self->client = chomikuj_client_new (account, G_VFS_JOB (job)->cancellable, &error);
  if (self->client == NULL)
    {
      g_free (password);
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  if (!chomikuj_client_login (self->client, password,
                              G_VFS_JOB (job)->cancellable, &error))
    {
      g_free (password);
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  if (save != G_PASSWORD_SAVE_NEVER && g_vfs_keyring_is_available ())
    g_vfs_keyring_save_password (account, "chomikuj.pl", NULL, "chomikuj",
                                 NULL, NULL, 0, password, save);
  g_free (password);

  g_free (self->display_name);
  display = g_strdup (chomikuj_client_get_account_name (self->client));
  if (display == NULL || *display == '\0')
    {
      g_free (display);
      display = g_strdup (account);
    }
  self->display_name = display;

  g_vfs_backend_set_display_name (backend, self->display_name);
  g_vfs_backend_set_icon_name (backend, "folder-remote");
  g_vfs_backend_set_symbolic_icon_name (backend, "folder-remote-symbolic");
  g_vfs_backend_set_mount_spec (backend, mount_spec);
  g_vfs_backend_set_user_visible (backend, TRUE);

  g_vfs_job_succeeded (G_VFS_JOB (job));
}

static void
g_vfs_backend_chomikuj_unmount (GVfsBackend        *backend,
                                GVfsJobUnmount     *job,
                                GMountUnmountFlags  flags,
                                GMountSource       *mount_source)
{
  GVfsBackendChomikuj *self = G_VFS_BACKEND_CHOMIKUJ (backend);

  g_clear_pointer (&self->client, chomikuj_client_free);
  invalidate_all (self);
  g_vfs_job_succeeded (G_VFS_JOB (job));
}

/* ------------------------------------------------------------------ */
/*  Enumerate / query info                                             */
/* ------------------------------------------------------------------ */

static void
g_vfs_backend_chomikuj_enumerate (GVfsBackend           *backend,
                                  GVfsJobEnumerate      *job,
                                  const gchar           *filename,
                                  GFileAttributeMatcher *matcher,
                                  GFileQueryInfoFlags    flags)
{
  GVfsBackendChomikuj *self = G_VFS_BACKEND_CHOMIKUJ (backend);
  GError *error = NULL;
  gchar *folder_id = NULL;
  GList *entries, *l;

  if (!resolve_folder (self, filename, &folder_id, G_VFS_JOB (job)->cancellable, &error))
    {
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  entries = get_dir_entries (self, folder_id, G_VFS_JOB (job)->cancellable, &error);
  g_free (folder_id);

  if (entries == NULL && error != NULL)
    {
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  g_vfs_job_succeeded (G_VFS_JOB (job));

  for (l = entries; l != NULL; l = l->next)
    {
      GFileInfo *info = entry_to_file_info (l->data, matcher);
      g_vfs_job_enumerate_add_info (job, info);
      g_object_unref (info);
    }
  g_list_free_full (entries, (GDestroyNotify) chomikuj_entry_free);

  g_vfs_job_enumerate_done (job);
}

static void
g_vfs_backend_chomikuj_query_info (GVfsBackend           *backend,
                                   GVfsJobQueryInfo      *job,
                                   const gchar           *filename,
                                   GFileQueryInfoFlags    flags,
                                   GFileInfo             *info,
                                   GFileAttributeMatcher *matcher)
{
  GVfsBackendChomikuj *self = G_VFS_BACKEND_CHOMIKUJ (backend);
  GError *error = NULL;
  ChomikujEntry *e;
  GFileInfo *extra;

  e = resolve_entry (self, filename, G_VFS_JOB (job)->cancellable, &error);
  if (e == NULL)
    {
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  extra = entry_to_file_info (e, matcher);
  g_file_info_copy_into (extra, info);
  g_object_unref (extra);
  chomikuj_entry_free (e);

  g_vfs_job_succeeded (G_VFS_JOB (job));
}

static void
g_vfs_backend_chomikuj_query_fs_info (GVfsBackend           *backend,
                                      GVfsJobQueryFsInfo    *job,
                                      const gchar           *filename,
                                      GFileInfo             *info,
                                      GFileAttributeMatcher *matcher)
{
  GVfsBackendChomikuj *self = G_VFS_BACKEND_CHOMIKUJ (backend);

  g_file_info_set_attribute_string (info, G_FILE_ATTRIBUTE_FILESYSTEM_TYPE, "chomikuj");
  g_file_info_set_attribute_boolean (info, G_FILE_ATTRIBUTE_FILESYSTEM_REMOTE, TRUE);

  if (g_file_attribute_matcher_matches (matcher, G_FILE_ATTRIBUTE_FILESYSTEM_SIZE) ||
      g_file_attribute_matcher_matches (matcher, G_FILE_ATTRIBUTE_FILESYSTEM_FREE))
    {
      guint64 total = 0, used = 0, free_space = 0;
      GError *error = NULL;

      if (chomikuj_client_query_transfer (self->client, &total, &used, &free_space,
                                          G_VFS_JOB (job)->cancellable, &error))
        {
          g_file_info_set_attribute_uint64 (info, G_FILE_ATTRIBUTE_FILESYSTEM_SIZE, total);
          g_file_info_set_attribute_uint64 (info, G_FILE_ATTRIBUTE_FILESYSTEM_USED, used);
          g_file_info_set_attribute_uint64 (info, G_FILE_ATTRIBUTE_FILESYSTEM_FREE, free_space);
        }
      g_clear_error (&error);
    }

  g_vfs_job_succeeded (G_VFS_JOB (job));
}

/* ------------------------------------------------------------------ */
/*  Reading                                                            */
/* ------------------------------------------------------------------ */

static void
g_vfs_backend_chomikuj_open_for_read (GVfsBackend         *backend,
                                      GVfsJobOpenForRead  *job,
                                      const gchar         *filename)
{
  GVfsBackendChomikuj *self = G_VFS_BACKEND_CHOMIKUJ (backend);
  GError *error = NULL;
  ChomikujEntry *e;
  ChomikujReadHandle *handle;

  e = resolve_entry (self, filename, G_VFS_JOB (job)->cancellable, &error);
  if (e == NULL)
    {
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }
  if (e->is_dir)
    {
      chomikuj_entry_free (e);
      g_vfs_job_failed_literal (G_VFS_JOB (job), G_IO_ERROR,
                                G_IO_ERROR_IS_DIRECTORY,
                                _("Cannot open a folder for reading"));
      return;
    }

  handle = g_new0 (ChomikujReadHandle, 1);
  handle->client = self->client;
  handle->file_id = e->id;
  handle->path = g_strdup (filename);
  handle->stream = chomikuj_client_open_read (self->client, e->id, 0,
                                              &handle->msg,
                                              G_VFS_JOB (job)->cancellable,
                                              &error);
  chomikuj_entry_free (e);

  if (handle->stream == NULL)
    {
      g_free (handle->path);
      g_free (handle);
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  g_vfs_job_open_for_read_set_handle (job, handle);
  g_vfs_job_open_for_read_set_can_seek (job, TRUE);
  g_vfs_job_succeeded (G_VFS_JOB (job));
}

static void
g_vfs_backend_chomikuj_read (GVfsBackend      *backend,
                             GVfsJobRead      *job,
                             GVfsBackendHandle handle,
                             gchar            *buffer,
                             gsize             bytes_requested)
{
  ChomikujReadHandle *h = handle;
  GError *error = NULL;
  gssize n;

  n = g_input_stream_read (h->stream, buffer, bytes_requested,
                           G_VFS_JOB (job)->cancellable, &error);
  if (n < 0)
    {
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  h->offset += n;
  g_vfs_job_read_set_size (job, (gsize) n);
  g_vfs_job_succeeded (G_VFS_JOB (job));
}

static void
g_vfs_backend_chomikuj_seek_on_read (GVfsBackend      *backend,
                                     GVfsJobSeekRead  *job,
                                     GVfsBackendHandle handle,
                                     goffset           offset,
                                     GSeekType         type)
{
  ChomikujReadHandle *h = handle;
  GError *error = NULL;
  goffset target;

  switch (type)
    {
    case G_SEEK_SET: target = offset; break;
    case G_SEEK_CUR: target = h->offset + offset; break;
    case G_SEEK_END: target = offset; break; /* size unknown; treat as absolute */
    default:
      g_vfs_job_failed_literal (G_VFS_JOB (job), G_IO_ERROR,
                                G_IO_ERROR_INVALID_ARGUMENT, _("Invalid seek"));
      return;
    }

  if (target < 0)
    {
      g_vfs_job_failed_literal (G_VFS_JOB (job), G_IO_ERROR,
                                G_IO_ERROR_INVALID_ARGUMENT, _("Invalid seek"));
      return;
    }

  if (target == h->offset)
    {
      g_vfs_job_succeeded (G_VFS_JOB (job));
      return;
    }

  g_clear_object (&h->stream);
  g_clear_object (&h->msg);

  h->stream = chomikuj_client_open_read (h->client, h->file_id, target,
                                         &h->msg, G_VFS_JOB (job)->cancellable,
                                         &error);
  if (h->stream == NULL)
    {
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  h->offset = target;
  g_vfs_job_succeeded (G_VFS_JOB (job));
}

static void
g_vfs_backend_chomikuj_close_read (GVfsBackend      *backend,
                                   GVfsJobCloseRead *job,
                                   GVfsBackendHandle handle)
{
  ChomikujReadHandle *h = handle;

  g_clear_object (&h->stream);
  g_clear_object (&h->msg);
  g_free (h->path);
  g_free (h);

  g_vfs_job_succeeded (G_VFS_JOB (job));
}

static void
g_vfs_backend_chomikuj_query_info_on_read (GVfsBackend           *backend,
                                           GVfsJobQueryInfoRead  *job,
                                           GVfsBackendHandle      handle,
                                           GFileInfo             *info,
                                           GFileAttributeMatcher *matcher)
{
  ChomikujReadHandle *h = handle;
  GVfsBackendChomikuj *self = G_VFS_BACKEND_CHOMIKUJ (backend);
  GError *error = NULL;
  ChomikujEntry *e;
  GFileInfo *extra;

  e = resolve_entry (self, h->path, G_VFS_JOB (job)->cancellable, &error);
  if (e == NULL)
    {
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  extra = entry_to_file_info (e, matcher);
  g_file_info_copy_into (extra, info);
  g_object_unref (extra);
  chomikuj_entry_free (e);

  g_vfs_job_succeeded (G_VFS_JOB (job));
}

/* ------------------------------------------------------------------ */
/*  Namespace mutation                                                 */
/* ------------------------------------------------------------------ */

static void
g_vfs_backend_chomikuj_make_directory (GVfsBackend         *backend,
                                       GVfsJobMakeDirectory *job,
                                       const gchar         *filename)
{
  GVfsBackendChomikuj *self = G_VFS_BACKEND_CHOMIKUJ (backend);
  GError *error = NULL;
  gchar *parent_id = NULL, *basename = NULL;

  if (!resolve_parent (self, filename, &parent_id, &basename,
                       G_VFS_JOB (job)->cancellable, &error))
    goto fail;

  {
    ChomikujEntry *existing = find_entry (self, parent_id, basename,
                                          G_VFS_JOB (job)->cancellable, &error);
    if (existing != NULL)
      {
        chomikuj_entry_free (existing);
        g_set_error (&error, G_IO_ERROR, G_IO_ERROR_EXISTS,
                     "“%s” already exists", basename);
        goto fail;
      }
  }
  if (error != NULL)
    goto fail;

  if (!chomikuj_client_make_folder (self->client, parent_id, basename, NULL,
                                    G_VFS_JOB (job)->cancellable, &error))
    goto fail;

  invalidate_dir (self, parent_id);
  g_free (parent_id);
  g_free (basename);
  g_vfs_job_succeeded (G_VFS_JOB (job));
  return;

 fail:
  g_free (parent_id);
  g_free (basename);
  g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
  g_error_free (error);
}

static void
g_vfs_backend_chomikuj_set_display_name (GVfsBackend          *backend,
                                         GVfsJobSetDisplayName *job,
                                         const gchar          *filename,
                                         const gchar          *display_name)
{
  GVfsBackendChomikuj *self = G_VFS_BACKEND_CHOMIKUJ (backend);
  GError *error = NULL;
  ChomikujEntry *e = NULL;
  gchar *parent_id = NULL, *basename = NULL;
  gboolean ok;

  if (!resolve_parent (self, filename, &parent_id, &basename,
                       G_VFS_JOB (job)->cancellable, &error))
    goto fail;

  e = find_entry (self, parent_id, basename, G_VFS_JOB (job)->cancellable, &error);
  if (e == NULL)
    {
      if (error == NULL)
        g_set_error (&error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                     "“%s” not found", filename);
      goto fail;
    }

  ok = chomikuj_client_change_name (self->client, e->is_dir, e->id, display_name,
                                    G_VFS_JOB (job)->cancellable, &error);
  if (!ok)
    goto fail;

  {
    gchar *dirname = g_path_get_dirname (filename);
    gchar *new_path = g_build_filename (dirname, display_name, NULL);
    g_vfs_job_set_display_name_set_new_path (job, new_path);
    g_free (dirname);
    g_free (new_path);
  }
  invalidate_dir (self, parent_id);
  chomikuj_entry_free (e);
  g_free (parent_id);
  g_free (basename);
  g_vfs_job_succeeded (G_VFS_JOB (job));
  return;

 fail:
  g_clear_pointer (&e, chomikuj_entry_free);
  g_free (parent_id);
  g_free (basename);
  g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
  g_error_free (error);
}

static void
g_vfs_backend_chomikuj_delete (GVfsBackend    *backend,
                               GVfsJobDelete  *job,
                               const gchar    *filename)
{
  GVfsBackendChomikuj *self = G_VFS_BACKEND_CHOMIKUJ (backend);
  GError *error = NULL;
  ChomikujEntry *e;
  gchar *parent_id = NULL, *basename = NULL;

  if (!resolve_parent (self, filename, &parent_id, &basename,
                       G_VFS_JOB (job)->cancellable, &error))
    goto fail;

  e = find_entry (self, parent_id, basename, G_VFS_JOB (job)->cancellable, &error);
  if (e == NULL)
    {
      if (error == NULL)
        g_set_error (&error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                     "“%s” not found", filename);
      goto fail;
    }

  if (e->is_dir)
    {
      if (!chomikuj_client_delete (self->client, NULL, 0, &e->id, 1,
                                   G_VFS_JOB (job)->cancellable, &error))
        {
          chomikuj_entry_free (e);
          goto fail;
        }
      {
        gchar *child = g_strdup_printf ("%" G_GINT64_FORMAT, e->id);
        invalidate_dir (self, child);
        g_free (child);
      }
    }
  else
    {
      if (!chomikuj_client_delete (self->client, &e->id, 1, NULL, 0,
                                   G_VFS_JOB (job)->cancellable, &error))
        {
          chomikuj_entry_free (e);
          goto fail;
        }
    }

  chomikuj_entry_free (e);
  invalidate_dir (self, parent_id);
  g_free (parent_id);
  g_free (basename);
  g_vfs_job_succeeded (G_VFS_JOB (job));
  return;

 fail:
  g_free (parent_id);
  g_free (basename);
  g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
  g_error_free (error);
}

static void
g_vfs_backend_chomikuj_move (GVfsBackend          *backend,
                             GVfsJobMove          *job,
                             const gchar          *source,
                             const gchar          *destination,
                             GFileCopyFlags        flags,
                             GFileProgressCallback progress_callback,
                             gpointer              progress_callback_data)
{
  GVfsBackendChomikuj *self = G_VFS_BACKEND_CHOMIKUJ (backend);
  GError *error = NULL;
  ChomikujEntry *e = NULL;
  ChomikujEntry *target = NULL;
  ChomikujEntry *dst_entry = NULL;
  gchar *src_parent = NULL, *src_base = NULL;
  gchar *dst_parent = NULL, *dst_base = NULL;
  gchar *new_name = NULL;

  if (!resolve_parent (self, source, &src_parent, &src_base,
                       G_VFS_JOB (job)->cancellable, &error))
    goto fail;

  e = find_entry (self, src_parent, src_base, G_VFS_JOB (job)->cancellable, &error);
  if (e == NULL)
    {
      if (error == NULL)
        g_set_error (&error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                     "“%s” not found", source);
      goto fail;
    }

  /* The destination may be an existing folder (move into it) or a full
   * destination path (the new name). */
  if (!resolve_parent (self, destination, &dst_parent, &dst_base,
                       G_VFS_JOB (job)->cancellable, &error))
    goto fail;

  dst_entry = find_entry (self, dst_parent, dst_base,
                          G_VFS_JOB (job)->cancellable, &error);
  if (dst_entry != NULL && dst_entry->is_dir)
    {
      gchar *old_parent = dst_parent;
      dst_parent = g_strdup_printf ("%" G_GINT64_FORMAT, dst_entry->id);
      g_free (old_parent);
      new_name = g_strdup (src_base);
    }
  else
    {
      new_name = g_strdup (dst_base);
    }

  target = find_entry (self, dst_parent, new_name,
                       G_VFS_JOB (job)->cancellable, &error);
  if (target != NULL && target->id != e->id)
    {
      g_set_error (&error, G_IO_ERROR, G_IO_ERROR_EXISTS,
                   "“%s” already exists", new_name);
      goto fail;
    }

  {
    const gint64 *files = e->is_dir ? NULL : &e->id;
    const gint64 *folders = e->is_dir ? &e->id : NULL;
    gsize n_files = e->is_dir ? 0 : 1;
    gsize n_folders = e->is_dir ? 1 : 0;

    /* files/move can only relocate between folders; a name change within the
     * same folder must go through changeName. */
    if (g_strcmp0 (dst_parent, src_parent) != 0)
      {
        if (!chomikuj_client_move (self->client, src_parent, dst_parent,
                                   files, n_files, folders, n_folders,
                                   G_VFS_JOB (job)->cancellable, &error))
          goto fail;
      }

    if (g_strcmp0 (new_name, src_base) != 0)
      {
        if (!chomikuj_client_change_name (self->client, e->is_dir, e->id,
                                          new_name,
                                          G_VFS_JOB (job)->cancellable, &error))
          goto fail;
      }
  }

  invalidate_dir (self, src_parent);
  invalidate_dir (self, dst_parent);
  chomikuj_entry_free (e);
  g_clear_pointer (&target, chomikuj_entry_free);
  g_clear_pointer (&dst_entry, chomikuj_entry_free);
  g_free (new_name);
  g_free (src_parent);
  g_free (src_base);
  g_free (dst_parent);
  g_free (dst_base);
  g_vfs_job_succeeded (G_VFS_JOB (job));
  return;

 fail:
  g_clear_pointer (&e, chomikuj_entry_free);
  g_clear_pointer (&target, chomikuj_entry_free);
  g_clear_pointer (&dst_entry, chomikuj_entry_free);
  g_free (new_name);
  g_free (src_parent);
  g_free (src_base);
  g_free (dst_parent);
  g_free (dst_base);
  g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
  g_error_free (error);
}

/* ------------------------------------------------------------------ */
/*  Writing                                                            */
/* ------------------------------------------------------------------ */

static ChomikujWriteHandle *
write_handle_new (const gchar *folder_id,
                  const gchar *name,
                  gboolean     replace,
                  GCancellable *cancellable,
                  GError      **error)
{
  ChomikujWriteHandle *handle;
  GFile *file;
  gchar *tmp_path = NULL;
  gint fd;

  fd = g_file_open_tmp ("gvfs-chomikuj-XXXXXX", &tmp_path, error);
  if (fd < 0)
    return NULL;
  g_close (fd, NULL);

  file = g_file_new_for_path (tmp_path);
  handle = g_new0 (ChomikujWriteHandle, 1);
  handle->local_path = tmp_path;
  handle->folder_id = g_strdup (folder_id);
  handle->name = g_strdup (name);
  handle->replace = replace;
  handle->out = g_file_replace (file, NULL, FALSE, G_FILE_CREATE_NONE,
                                cancellable, error);
  g_object_unref (file);

  if (handle->out == NULL)
    {
      g_unlink (tmp_path);
      g_free (handle->local_path);
      g_free (handle->folder_id);
      g_free (handle->name);
      g_free (handle);
      return NULL;
    }

  return handle;
}

static void
write_handle_free (ChomikujWriteHandle *handle)
{
  g_clear_object (&handle->out);
  if (handle->local_path != NULL)
    g_unlink (handle->local_path);
  g_free (handle->local_path);
  g_free (handle->folder_id);
  g_free (handle->name);
  g_free (handle);
}

static void
open_for_write_common (GVfsBackend         *backend,
                       GVfsJobOpenForWrite *job,
                       const gchar         *filename,
                       gboolean             replace)
{
  GVfsBackendChomikuj *self = G_VFS_BACKEND_CHOMIKUJ (backend);
  GError *error = NULL;
  gchar *parent_id = NULL, *basename = NULL;
  ChomikujWriteHandle *handle;

  if (!resolve_parent (self, filename, &parent_id, &basename,
                       G_VFS_JOB (job)->cancellable, &error))
    goto fail;

  if (!replace)
    {
      ChomikujEntry *existing = find_entry (self, parent_id, basename,
                                            G_VFS_JOB (job)->cancellable, &error);
      if (existing != NULL)
        {
          chomikuj_entry_free (existing);
          g_set_error (&error, G_IO_ERROR, G_IO_ERROR_EXISTS,
                       "“%s” already exists", basename);
          goto fail;
        }
      if (error != NULL)
        goto fail;
    }

  handle = write_handle_new (parent_id, basename, replace,
                             G_VFS_JOB (job)->cancellable, &error);
  if (handle == NULL)
    goto fail;

  g_vfs_job_open_for_write_set_handle (job, handle);
  g_vfs_job_open_for_write_set_can_seek (job, TRUE);
  g_vfs_job_open_for_write_set_can_truncate (job, TRUE);
  g_free (parent_id);
  g_free (basename);
  g_vfs_job_succeeded (G_VFS_JOB (job));
  return;

 fail:
  g_free (parent_id);
  g_free (basename);
  g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
  g_error_free (error);
}

static void
g_vfs_backend_chomikuj_create (GVfsBackend         *backend,
                               GVfsJobOpenForWrite *job,
                               const gchar         *filename,
                               GFileCreateFlags     flags)
{
  open_for_write_common (backend, job, filename, FALSE);
}

static void
g_vfs_backend_chomikuj_replace (GVfsBackend         *backend,
                                GVfsJobOpenForWrite *job,
                                const gchar         *filename,
                                const gchar         *etag,
                                gboolean             make_backup,
                                GFileCreateFlags     flags)
{
  open_for_write_common (backend, job, filename, TRUE);
}

static GOutputStream *
write_handle_output (ChomikujWriteHandle *handle)
{
  return G_OUTPUT_STREAM (handle->out);
}

static void
g_vfs_backend_chomikuj_write (GVfsBackend      *backend,
                              GVfsJobWrite     *job,
                              GVfsBackendHandle handle,
                              gchar            *buffer,
                              gsize             buffer_size)
{
  ChomikujWriteHandle *h = handle;
  GError *error = NULL;
  gssize n;

  n = g_output_stream_write (write_handle_output (h), buffer, buffer_size,
                             G_VFS_JOB (job)->cancellable, &error);
  if (n < 0)
    {
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  g_vfs_job_write_set_written_size (job, (gsize) n);
  g_vfs_job_succeeded (G_VFS_JOB (job));
}

static void
g_vfs_backend_chomikuj_seek_on_write (GVfsBackend      *backend,
                                      GVfsJobSeekWrite *job,
                                      GVfsBackendHandle handle,
                                      goffset           offset,
                                      GSeekType         type)
{
  ChomikujWriteHandle *h = handle;
  GError *error = NULL;
  GSeekable *seekable = G_SEEKABLE (write_handle_output (h));

  if (!g_seekable_seek (seekable, offset, type,
                        G_VFS_JOB (job)->cancellable, &error))
    {
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  g_vfs_job_succeeded (G_VFS_JOB (job));
}

static void
g_vfs_backend_chomikuj_truncate (GVfsBackend      *backend,
                                 GVfsJobTruncate  *job,
                                 GVfsBackendHandle handle,
                                 goffset           size)
{
  ChomikujWriteHandle *h = handle;
  GError *error = NULL;
  GSeekable *seekable = G_SEEKABLE (write_handle_output (h));

  if (!g_seekable_truncate (seekable, size, G_VFS_JOB (job)->cancellable, &error))
    {
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  g_vfs_job_succeeded (G_VFS_JOB (job));
}

static void
g_vfs_backend_chomikuj_close_write (GVfsBackend      *backend,
                                    GVfsJobCloseWrite *job,
                                    GVfsBackendHandle handle)
{
  GVfsBackendChomikuj *self = G_VFS_BACKEND_CHOMIKUJ (backend);
  ChomikujWriteHandle *h = handle;
  GError *error = NULL;
  GOutputStream *out;

  out = write_handle_output (h);
  if (!g_output_stream_close (out, G_VFS_JOB (job)->cancellable, &error))
    {
      write_handle_free (h);
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  if (h->replace)
    {
      ChomikujEntry *existing = find_entry (self, h->folder_id, h->name,
                                            G_VFS_JOB (job)->cancellable, &error);
      if (existing != NULL)
        {
          gboolean deleted;
          if (existing->is_dir)
            deleted = chomikuj_client_delete (self->client, NULL, 0,
                                              &existing->id, 1,
                                              G_VFS_JOB (job)->cancellable, &error);
          else
            deleted = chomikuj_client_delete (self->client, &existing->id, 1,
                                              NULL, 0,
                                              G_VFS_JOB (job)->cancellable, &error);
          chomikuj_entry_free (existing);
          if (!deleted)
            {
              write_handle_free (h);
              g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
              g_error_free (error);
              return;
            }
          invalidate_dir (self, h->folder_id);
        }
      else if (error != NULL)
        {
          write_handle_free (h);
          g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
          g_error_free (error);
          return;
        }
    }

  if (!chomikuj_client_upload_file (self->client, h->local_path, h->folder_id,
                                    h->name, NULL, NULL,
                                    G_VFS_JOB (job)->cancellable, &error))
    {
      write_handle_free (h);
      g_vfs_job_failed_from_error (G_VFS_JOB (job), error);
      g_error_free (error);
      return;
    }

  invalidate_dir (self, h->folder_id);
  write_handle_free (h);
  g_vfs_job_succeeded (G_VFS_JOB (job));
}

static void
g_vfs_backend_chomikuj_query_info_on_write (GVfsBackend           *backend,
                                            GVfsJobQueryInfoWrite *job,
                                            GVfsBackendHandle      handle,
                                            GFileInfo             *info,
                                            GFileAttributeMatcher *matcher)
{
  ChomikujWriteHandle *h = handle;

  g_file_info_set_name (info, h->name);
  g_file_info_set_display_name (info, h->name);
  g_file_info_set_file_type (info, G_FILE_TYPE_REGULAR);
  g_file_info_set_size (info, g_seekable_tell (G_SEEKABLE (write_handle_output (h))));

  g_vfs_job_succeeded (G_VFS_JOB (job));
}

/* ------------------------------------------------------------------ */
/*  GObject plumbing                                                   */
/* ------------------------------------------------------------------ */

static void
g_vfs_backend_chomikuj_finalize (GObject *object)
{
  GVfsBackendChomikuj *self = G_VFS_BACKEND_CHOMIKUJ (object);

  g_clear_pointer (&self->client, chomikuj_client_free);
  g_free (self->display_name);
  g_clear_pointer (&self->dir_cache, g_hash_table_unref);
  g_rec_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (g_vfs_backend_chomikuj_parent_class)->finalize (object);
}

static void
g_vfs_backend_chomikuj_class_init (GVfsBackendChomikujClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GVfsBackendClass *backend_class = G_VFS_BACKEND_CLASS (klass);

  gobject_class->finalize = g_vfs_backend_chomikuj_finalize;

  backend_class->mount = g_vfs_backend_chomikuj_mount;
  backend_class->unmount = g_vfs_backend_chomikuj_unmount;
  backend_class->enumerate = g_vfs_backend_chomikuj_enumerate;
  backend_class->query_info = g_vfs_backend_chomikuj_query_info;
  backend_class->query_info_on_read = g_vfs_backend_chomikuj_query_info_on_read;
  backend_class->query_info_on_write = g_vfs_backend_chomikuj_query_info_on_write;
  backend_class->query_fs_info = g_vfs_backend_chomikuj_query_fs_info;
  backend_class->open_for_read = g_vfs_backend_chomikuj_open_for_read;
  backend_class->read = g_vfs_backend_chomikuj_read;
  backend_class->seek_on_read = g_vfs_backend_chomikuj_seek_on_read;
  backend_class->close_read = g_vfs_backend_chomikuj_close_read;
  backend_class->create = g_vfs_backend_chomikuj_create;
  backend_class->replace = g_vfs_backend_chomikuj_replace;
  backend_class->write = g_vfs_backend_chomikuj_write;
  backend_class->seek_on_write = g_vfs_backend_chomikuj_seek_on_write;
  backend_class->truncate = g_vfs_backend_chomikuj_truncate;
  backend_class->close_write = g_vfs_backend_chomikuj_close_write;
  backend_class->make_directory = g_vfs_backend_chomikuj_make_directory;
  backend_class->set_display_name = g_vfs_backend_chomikuj_set_display_name;
  backend_class->delete = g_vfs_backend_chomikuj_delete;
  backend_class->move = g_vfs_backend_chomikuj_move;
}

static void
g_vfs_backend_chomikuj_init (GVfsBackendChomikuj *self)
{
  self->dir_cache = g_hash_table_new_full (g_str_hash, g_str_equal,
                                           g_free, (GDestroyNotify) dir_cache_free);
  g_rec_mutex_init (&self->mutex);
}
