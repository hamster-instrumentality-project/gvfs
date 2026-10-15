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

#include <config.h>

#include <unistd.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "chomikujclient.h"

static void
test_secret (void)
{
  g_assert_cmpstr (chomikuj_secret (), ==, "wzrwYua$.DSe8suk!`'2");
}

static void
test_sign (void)
{
  gchar *token;

  token = chomikuj_sign ("/api/v3/account/login", "",
                         "{\"AccountName\":\"user\",\"Password\":\"pass\"}");
  g_assert_cmpstr (token, ==, "939c68c9a0d660e2ae606c9d0da1157d");
  g_free (token);
}

static void
test_name_split (void)
{
  gchar *base = NULL, *ext = NULL, *joined;

  chomikuj_split_name ("a.b.c.bin", &base, &ext);
  g_assert_cmpstr (base, ==, "a.b.c");
  g_assert_cmpstr (ext, ==, "bin");
  joined = chomikuj_join_name (base, ext);
  g_assert_cmpstr (joined, ==, "a.b.c.bin");
  g_free (base);
  g_free (ext);
  g_free (joined);

  chomikuj_split_name ("noextension", &base, &ext);
  g_assert_cmpstr (base, ==, "noextension");
  g_assert_null (ext);
  g_free (base);

  /* A name already carrying the extension must not gain it twice. */
  chomikuj_split_name ("movie.mkv", &base, &ext);
  joined = chomikuj_join_name (base, "mkv");
  g_assert_cmpstr (joined, ==, "movie.mkv");
  g_free (base);
  g_free (ext);
  g_free (joined);
}

static void
test_crc32 (void)
{
  gchar *path = NULL;
  gint fd;
  gchar *crc;
  GError *error = NULL;

  fd = g_file_open_tmp ("gvfs-chomikuj-test-XXXXXX", &path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (write (fd, "123456789", 9), ==, 9);
  g_close (fd, NULL);

  crc = chomikuj_crc32_hex (path, &error);
  g_assert_no_error (error);
  g_assert_cmpstr (crc, ==, "cbf43926");

  g_free (crc);
  g_unlink (path);
  g_free (path);
}

int
main (int   argc,
      char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/chomikuj/secret", test_secret);
  g_test_add_func ("/chomikuj/sign", test_sign);
  g_test_add_func ("/chomikuj/name-split", test_name_split);
  g_test_add_func ("/chomikuj/crc32", test_crc32);

  return g_test_run ();
}
