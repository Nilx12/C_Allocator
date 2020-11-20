cmake_minimum_required(VERSION 3.17)
project(project1 C)

# Przyjmij standard C11
set(CMAKE_C_STANDARD 11)

# Ustaw opcje kompilatora (z raportu Dante)
add_compile_options(
        "-ggdb3"
        "-std=c11"
        "-xc"
        "-pedantic"
        "-Werror"
        "-Wall"
        "-Wextra"
        "-fmax-errors=5"
        "-Werror=vla"
        "-Wno-error=unused-parameter"
        "-Wno-error=parentheses"
        "-Wno-parentheses"
        "-D_GNU_SOURCE"
        "-D__TEST_BOOTSTRAP"
        "-DINSIDE_DANTE"
)

# Ustaw opcje konsolidatora (z raportu Dante)
add_link_options(
        "-ggdb3"
        "-fuse-ld=gold"
        "-Wl,-Map=main.map"
        "-Wl,-cref"
)

# Utwórz target 'project1' i dodaj do niego pliki źródlowe:
add_executable(project1
        main.c # Nazwa głównego pliku, z funkcją main
        heap.c heap.h)

# Dołącz biblioteki libm oraz libpthread
target_link_libraries(project1 m pthread)