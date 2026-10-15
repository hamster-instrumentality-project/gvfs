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
 * Live, self-cleaning verification of the Chomikuj Mobile API client.
 *
 * Disabled unless CHOMIKUJ_ACCOUNT and CHOMIKUJ_PASSWORD are set in the
 * environment.  It only ever touches resources it creates itself: it makes a
 * unique temporary folder, uploads a small file into it, downloads and
 * verifies it, renames it, then deletes the folder (which cascades).  Existing
 * user data is never modified or removed.
 *
 * Run with:
 *   CHOMIKUJ_ACCOUNT=... CHOMIKUJ_PASSWORD=... _build/test/unit/chomikuj-live
 */

#include <config.h>

#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "chomikujclient.h"

static gboolean
read_all (GInputStream *stream,
          GByteArray   *out)
{
  guint8 buf[65536];
  gssize n;
  GError *error = NULL;

  while ((n = g_input_stream_read (stream, buf, sizeof buf, NULL, &error)) > 0)
    g_byte_array_append (out, buf, (guint) n);

  if (n < 0)
    {
      g_printerr ("download read failed: %s\n", error->message);
      g_error_free (error);
      return FALSE;
    }
  return TRUE;
}

int
main (int   argc,
      char *argv[])
{
  const gchar *account, *password;
  ChomikujClient *client;
  GError *error = NULL;
  gchar *folder_name = NULL;
  gchar *folder_id_s = NULL;
  gint64 folder_id = 0;
  gchar *local_path = NULL;
  const gchar *content = "gvfs chomikuj live probe\n";
  GList *entries, *l;
  gint64 file_id = -1;
  gboolean ok = FALSE;
  gint exit_code = 1;

  account = g_getenv ("CHOMIKUJ_ACCOUNT");
  password = g_getenv ("CHOMIKUJ_PASSWORD");
  if (account == NULL || *account == '\0' ||
      password == NULL || *password == '\0')
    {
      g_print ("chomikuj-live: CHOMIKUJ_ACCOUNT/CHOMIKUJ_PASSWORD not set; skipping\n");
      return 0;
    }

  client = chomikuj_client_new (account, NULL, &error);
  g_assert_no_error (error);

  if (!chomikuj_client_login (client, password, NULL, &error))
    {
      g_printerr ("login failed: %s\n", error->message);
      goto out;
    }
  g_print ("logged in as %s (id %s)\n",
           chomikuj_client_get_account_name (client),
           chomikuj_client_get_account_id (client));

  folder_name = g_strdup_printf ("gvfs-live-%u", g_random_int ());
  if (!chomikuj_client_make_folder (client, "0", folder_name, &folder_id, NULL, &error))
    {
      g_printerr ("mkdir failed: %s\n", error->message);
      goto out;
    }
  folder_id_s = g_strdup_printf ("%" G_GINT64_FORMAT, folder_id);
  g_print ("created folder %s (id %s)\n", folder_name, folder_id_s);

  /* Upload. */
  {
    gint fd = g_file_open_tmp ("gvfs-chomikuj-live-XXXXXX", &local_path, &error);
    g_assert_no_error (error);
    g_assert_cmpint (write (fd, content, strlen (content)), ==, (gssize) strlen (content));
    g_close (fd, NULL);
  }
  {
    gchar *remote = g_strdup_printf ("probe-%u.txt", g_random_int ());
    if (!chomikuj_client_upload_file (client, local_path, folder_id_s, remote,
                                      NULL, NULL, NULL, &error))
      {
        g_printerr ("upload failed: %s\n", error->message);
        g_free (remote);
        goto cleanup;
      }
    g_print ("uploaded %s\n", remote);
    g_free (remote);
  }

  /* Verify it lists, then download and compare. */
  entries = chomikuj_client_list_folder (client, folder_id_s, NULL, &error);
  if (entries == NULL && error != NULL)
    {
      g_printerr ("list failed: %s\n", error->message);
      goto cleanup;
    }
  for (l = entries; l != NULL; l = l->next)
    {
      ChomikujEntry *e = l->data;
      if (!e->is_dir)
        file_id = e->id;
    }
  g_list_free_full (entries, (GDestroyNotify) chomikuj_entry_free);

  if (file_id < 0)
    {
      g_printerr ("uploaded file not found in listing\n");
      goto cleanup;
    }

  {
    SoupMessage *msg = NULL;
    GInputStream *stream;
    GByteArray *data = g_byte_array_new ();

    stream = chomikuj_client_open_read (client, file_id, 0, &msg, NULL, &error);
    if (stream == NULL)
      {
        g_printerr ("download failed: %s\n", error->message);
        g_byte_array_unref (data);
        goto cleanup;
      }
    if (!read_all (stream, data))
      {
        g_object_unref (stream);
        g_clear_object (&msg);
        g_byte_array_unref (data);
        goto cleanup;
      }
    g_object_unref (stream);
    g_clear_object (&msg);

    if (data->len == strlen (content) &&
        memcmp (data->data, content, data->len) == 0)
      g_print ("download verified (%u bytes)\n", data->len);
    else
      {
        g_printerr ("download content mismatch (%u bytes)\n", data->len);
        g_byte_array_unref (data);
        goto cleanup;
      }
    g_byte_array_unref (data);
  }

  /* Rename, then delete the whole probe folder (recursive, self-created only). */
  if (!chomikuj_client_change_name (client, TRUE, folder_id, "gvfs-live-renamed",
                                    NULL, &error))
    {
      g_printerr ("rename failed: %s\n", error->message);
      goto cleanup;
    }
  g_print ("renamed folder\n");

  if (!chomikuj_client_delete (client, NULL, 0, &folder_id, 1, NULL, &error))
    {
      g_printerr ("delete failed: %s\n", error->message);
      goto cleanup;
    }
  g_print ("deleted probe folder; live check complete\n");
  ok = TRUE;

 cleanup:
  if (!ok && folder_id != 0)
    {
      GError *cleanup_error = NULL;
      /* Best-effort cleanup of the folder we created. */
      chomikuj_client_delete (client, NULL, 0, &folder_id, 1, NULL, &cleanup_error);
      g_clear_error (&cleanup_error);
    }
  if (local_path != NULL)
    g_unlink (local_path);

 out:
  g_free (local_path);
  g_free (folder_id_s);
  g_free (folder_name);
  chomikuj_client_free (client);
  g_clear_error (&error);

  exit_code = ok ? 0 : 1;
  return exit_code;
}
