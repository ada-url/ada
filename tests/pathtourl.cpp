
#include <cstdlib>
#include <iostream>

#include "ada.h"


/**
 * Node.js has a function called url.pathToFileURL(path).
 * https://nodejs.org/api/url.html#urlpathtofileurlpath
 *
 * It is explained as follows...
 *
 * This function ensures that path is resolved absolutely,
 * and that the URL control characters are correctly encoded when converting into a File URL.
 *
 * new URL('/foo#1', 'file:');           // Incorrect: file:///foo#1
 * pathToFileURL('/foo#1');              // Correct:   file:///foo%231 (POSIX)
 *
 * new URL('/some/path%.c', 'file:');    // Incorrect: file:///some/path%.c
 * pathToFileURL('/some/path%.c');       // Correct:   file:///some/path%25.c (POSIX)
 *
 * For reference, the path percent-encode set is:
 *
 * U+0020 SPACE, U+0022 ("), U+0023 (#), U+003C (<), and U+003E (>), U+003F (?), U+0060 (`), U+007B ({), and U+007D (}).
 * C0 controls:  range U+0000 NULL to U+001F INFORMATION SEPARATOR ONE, inclusive.
 * and all code points greater than U+007E (~).
 *
 * Thus '%' is allowed as a path character in a URL.
 * Under many operating systems, including common Linux distributions and macos,
 * both file names path%.c and path%25.c are allowed as one can easily check.
 *
 * Type the following commands in a shell:
 *
 * touch path%.c
 * touch path%25.c
 * ls path*
 *
 * Thus it is unclear why Node wants the path /some/path%.c to become the path /some/path%25.c.
 *
 * Which path names are legal typically does not just depend on the operating system, it also depends
 * critical on the file system.
 */
bool check_path_setters() {
    ada::result url = ada::parse("file://");
    url->set_pathname("/foo#1");
    std::cout << url->get_href() << std::endl;
    if(url->get_href() != "file:///foo%231") { return false; }
    // expected: file:///foo%231
    url->set_pathname("/some/path%.c");
    // node claims that it should be: file:///some/path%25.c
    std::cout << url->get_href() << std::endl;
    if(url->get_href() != "/some/path%.c") { return false; }

    return true;
}

int main() {
    return check_path_setters() ? EXIT_SUCCESS : EXIT_FAILURE;
}