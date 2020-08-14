#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>

#include "llvm/Demangle/Demangle.h"

#if defined(_MSC_VER)
//  Microsoft
#define EXPORT extern "C" __declspec(dllexport)
#define IMPORT __declspec(dllimport)
#elif defined(__GNUC__)
//  GCC
#define EXPORT extern "C" __attribute__((visibility("default")))
#define IMPORT
#else
//  do nothing and hope for the best?
#define EXPORT
#define IMPORT
#pragma warning Unknown dynamic link import/export semantics.
#endif

const char kDemumbleVersion[] = "1.2.17";

EXPORT bool demangle_raw(const char* s, char* out, size_t* n_used = 0) {
    if (char* itanium = llvm::itaniumDemangle(s, NULL, NULL, NULL)) {
        snprintf(out, 1024, "%s", itanium);
        free(itanium);
        return true;
    }
    else if (char* ms = llvm::microsoftDemangle(s, n_used, NULL, NULL, NULL)) {
        snprintf(out, 1024, "%s", ms);
        free(ms);
        return true;
    } else {
        snprintf(out, 1024, "%s", s);
    }
}

EXPORT bool is_mangle_char_itanium(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '$';
}

EXPORT bool is_mangle_char_win(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || strchr("?_@$", c);
}

EXPORT bool is_plausible_itanium_prefix(char* s) {
    // Itanium symbols start with 1-4 underscores followed by Z.
    // strnstr() is BSD, so use a small local buffer and strstr().
    const int N = 5;  // == strlen("____Z")
    char prefix[N + 1];
    strncpy(prefix, s, N); prefix[N] = '\0';
    return strstr(prefix, "_Z");
}

static char outbuf[8192] = { 0 };
static char buf[8192] = { 0 };
EXPORT bool demangle(const char* s, char* out) {
    bool need_separator = false;
    strcpy_s(buf, s);
    char* cur = buf;
    char* end = cur + strlen(cur);

    while (cur != end) {
        size_t special = strcspn(cur, "_?");
        printf("%.*s", static_cast<int>(special), cur);
        need_separator = false;
        cur += special;
        if (cur == end)
            break;

        size_t n_sym = 0;
        if (*cur == '?') {
            while (cur + n_sym != end && is_mangle_char_win(cur[n_sym]))
                ++n_sym;
        }
        else if (is_plausible_itanium_prefix(cur)) {
            while (cur + n_sym != end && is_mangle_char_itanium(cur[n_sym]))
                ++n_sym;
        }
        else {
            printf("_");
            ++cur;
            continue;
        }

        char tmp = cur[n_sym];
        cur[n_sym] = '\0';
        size_t n_used = n_sym;
        demangle_raw(cur, out, &n_used);
        need_separator = true;
        cur[n_sym] = tmp;

        cur += n_used;
    }

    return false;
}

EXPORT void get_version(char *out) {
    snprintf(out, 1024, "%s", kDemumbleVersion);
}

int main(int argc, char *argv[]) {
    char tmp[1024] = { 0 };
    demangle("?Fx_i@@YAHP6AHH@Z@Z", tmp);
    printf("Demangled: %s", tmp);
    return 1;
}
