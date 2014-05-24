// iocode : coding/decoding windows IO codes

#include "stdafx.h"

#define FUNCTION_FROM_CTL_CODE(ctrlCode) (((DWORD)(ctrlCode & 0x3FFC)) >> 2)
#define ACCESS_FROM_CTL_CODE(ctrlCode) (((DWORD)(ctrlCode & 0xC000)) >> 14)

typedef struct _TABLE
{
    const TCHAR **strings;
    ULONG lastelement;
} TABLE, PTABLE;

// !!! -- ATTENTION -- !!!
// This table's INDEXES need to match winioctl.h's #defines!!
// !!! -- ATTENTION -- !!!
const TCHAR* device_type_string[] = {
    L"DEVICE_UNKNOWN", // fail value
    L"FILE_DEVICE_BEEP",
    L"FILE_DEVICE_CD_ROM",
    L"FILE_DEVICE_CD_ROM_FILE_SYSTEM",
    L"FILE_DEVICE_CONTROLLER",
    L"FILE_DEVICE_DATALINK",
    L"FILE_DEVICE_DFS",
    L"FILE_DEVICE_DISK",
    L"FILE_DEVICE_DISK_FILE_SYSTEM",
    L"FILE_DEVICE_FILE_SYSTEM",
    L"FILE_DEVICE_INPORT_PORT",
    L"FILE_DEVICE_KEYBOARD",
    L"FILE_DEVICE_MAILSLOT",
    L"FILE_DEVICE_MIDI_IN",
    L"FILE_DEVICE_MIDI_OUT",
    L"FILE_DEVICE_MOUSE",
    L"FILE_DEVICE_MULTI_UNC_PROVIDER",
    L"FILE_DEVICE_NAMED_PIPE",
    L"FILE_DEVICE_NETWORK",
    L"FILE_DEVICE_NETWORK_BROWSER",
    L"FILE_DEVICE_NETWORK_FILE_SYSTEM",
    L"FILE_DEVICE_NULL",
    L"FILE_DEVICE_PARALLEL_PORT",
    L"FILE_DEVICE_PHYSICAL_NETCARD",
    L"FILE_DEVICE_PRINTER",
    L"FILE_DEVICE_SCANNER",
    L"FILE_DEVICE_SERIAL_MOUSE_PORT",
    L"FILE_DEVICE_SERIAL_PORT",
    L"FILE_DEVICE_SCREEN",
    L"FILE_DEVICE_SOUND",
    L"FILE_DEVICE_STREAMS",
    L"FILE_DEVICE_TAPE",
    L"FILE_DEVICE_TAPE_FILE_SYSTEM",
    L"FILE_DEVICE_TRANSPORT",
    L"FILE_DEVICE_UNKNOWN",
    L"FILE_DEVICE_VIDEO",
    L"FILE_DEVICE_VIRTUAL_DISK",
    L"FILE_DEVICE_WAVE_IN",
    L"FILE_DEVICE_WAVE_OUT",
    L"FILE_DEVICE_8042_PORT",
    L"FILE_DEVICE_NETWORK_REDIRECTOR",
    L"FILE_DEVICE_BATTERY",
    L"FILE_DEVICE_BUS_EXTENDER",
    L"FILE_DEVICE_MODEM",
    L"FILE_DEVICE_VDM",
    L"FILE_DEVICE_MASS_STORAGE",
    L"FILE_DEVICE_SMB",
    L"FILE_DEVICE_KS",
    L"FILE_DEVICE_CHANGER",
    L"FILE_DEVICE_SMARTCARD",
    L"FILE_DEVICE_ACPI",
    L"FILE_DEVICE_DVD",
    L"FILE_DEVICE_FULLSCREEN_VIDEO",
    L"FILE_DEVICE_DFS_FILE_SYSTEM",
    L"FILE_DEVICE_DFS_VOLUME",
    L"FILE_DEVICE_SERENUM",
    L"FILE_DEVICE_TERMSRV",
    L"FILE_DEVICE_KSEC",
    L"FILE_DEVICE_FIPS",
    L"FILE_DEVICE_INFINIBAND",
    L"DEVICE_UNKNOWN",
    L"DEVICE_UNKNOWN",
    L"FILE_DEVICE_VMBUS",
    L"FILE_DEVICE_CRYPT_PROVIDER",
    L"FILE_DEVICE_WPD",
    L"FILE_DEVICE_BLUETOOTH",
    L"FILE_DEVICE_MT_COMPOSITE",
    L"FILE_DEVICE_MT_TRANSPORT",
    L"FILE_DEVICE_BIOMETRIC",
    L"FILE_DEVICE_PMI", // last valid index 0x45
    NULL
};
const ULONG maxdevtype = 0x45;
TABLE device_type_table = {device_type_string, maxdevtype};


// !!! -- ATTENTION -- !!!
// This table's INDEXES need to match winioctl.h's #defines!!
// !!! -- ATTENTION -- !!!
const TCHAR* method_string[] = {
    L"METHOD_BUFFERED",
    L"METHOD_IN_DIRECT",
    L"METHOD_OUT_DIRECT",
    L"METHOD_NEITHER",
    NULL
};
const ULONG maxmethod = 0x3;
TABLE method_table = {method_string, maxmethod};

// !!! -- ATTENTION -- !!!
// This table's INDEXES need to match winioctl.h's #defines!!
// !!! -- ATTENTION -- !!!
const TCHAR* access_string[] = {
    L"FILE_ANY_ACCESS",
    //L"FILE_SPECIAL_ACCESS", // SKIPPING AS IT IS EQUAL TO FILE_ANY_ACCESS (0)
    L"FILE_READ_ACCESS",
    L"FILE_WRITE_ACCESS",
    NULL
};
const ULONG maxaccess = 0x2;
TABLE access_table = {access_string, maxaccess};

UINT GetIndex(TCHAR* str, TABLE *table)
{
    TCHAR *stop;
    ULONG index, i=0;
    const TCHAR **strings= table->strings;
    ULONG max = table->lastelement;

    index = _tcstoul(str, &stop, 0);
    // This is not a number, search the table for the string
    if(*stop) {
        while(i<=max) {
            if(!_tcscmp(str, strings[i])) {
                index=i;
                break;
            }
            i++;
        }
    }
    return index;
}

int _tmain(int argc, _TCHAR* argv[])
{
    DWORD iocode, devicetype, function, method, access;
    TCHAR *stop;

    // Check # of args
    switch(argc) {
    case 2:
        iocode = _tcstoul(argv[1], &stop, 0);
        devicetype = DEVICE_TYPE_FROM_CTL_CODE(iocode);
        function = FUNCTION_FROM_CTL_CODE(iocode);
        method = METHOD_FROM_CTL_CODE(iocode);
        access = ACCESS_FROM_CTL_CODE(iocode);
        _tprintf(L"DECODING IOCODE %#.8x:\ndevice type = %#x %s (%s)\nfunction = %#x (%s)\nmethod = %s\naccess = %s\n",
            iocode,
            devicetype,
            devicetype>maxdevtype ? L"UNKNOWN" : device_type_string[devicetype],
            devicetype&0x8000 ? L"VENDOR" : L"MS",
            function,
            function&0x800 ? L"VENDOR" : L"MS",
            method>maxmethod ? L"INVALID" : method_string[method],
            access>maxaccess ? L"INVALID" : access_string[access]);
        break;
    case 5:
        devicetype = GetIndex(argv[1], &device_type_table);
        function = _tcstoul(argv[2], &stop, 0);
        if(function>0xfff) {
            _tprintf(L"Invalid function #, max is 0xfff\n");
            return 0;
        }
        method = GetIndex(argv[3], &method_table);
        access = GetIndex(argv[4], &access_table);
        _tprintf(L"ENCODED IOCODE %#.8x", CTL_CODE(devicetype, function, method, access));
        break;
    default:
        _tprintf(L"USAGE: %s [IOCODE]\nor\n%s [DEVICE_TYPE] [FUNCTION] [METHOD] [ACCESS]", argv[0], argv[0]);
        break;
    }
    return 0;
}
