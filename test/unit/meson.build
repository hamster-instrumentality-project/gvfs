tests = [
  'outputstream'
]

deps = [
  gio_dep,
  glib_dep,
]

foreach test: tests
  executable(
    test,
    test + '.c',
    include_directories: top_inc,
    dependencies: deps,
  )
endforeach

if enable_chomikuj
  chomikuj_test = executable(
    'chomikuj',
    [
      'chomikuj.c',
      '../../daemon/chomikujclient.c',
    ],
    include_directories: [top_inc, include_directories('../../daemon')],
    dependencies: [gio_dep, glib_dep, libsoup_dep, json_glib_dep],
  )

  test('chomikuj', chomikuj_test)

  # Live, self-cleaning verification against the real backend.  Built but not
  # registered with meson test: it only runs when CHOMIKUJ_ACCOUNT and
  # CHOMIKUJ_PASSWORD are set, and it must be invoked explicitly.
  executable(
    'chomikuj-live',
    [
      'chomikuj-live.c',
      '../../daemon/chomikujclient.c',
    ],
    include_directories: [top_inc, include_directories('../../daemon')],
    dependencies: [gio_dep, glib_dep, libsoup_dep, json_glib_dep],
  )
endif
