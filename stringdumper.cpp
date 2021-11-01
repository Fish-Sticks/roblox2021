std::unordered_map<std::string, std::vector<int>> resolve_encrypted_strings(uintptr_t idabase) {
    std::unordered_map<std::string, std::vector<int>> enc_strings;

    PIMAGE_NT_HEADERS fish = ImageNtHeader(GetModuleHandle(NULL));
    MEMORY_BASIC_INFORMATION MBI{ 0 };
    uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandle(NULL)) + fish->OptionalHeader.BaseOfCode;
    DWORD old;

    byte lastebp = 0;
    uintptr_t lastaddress = 0;

    VirtualProtect((LPVOID)base, fish->OptionalHeader.SizeOfCode, PAGE_EXECUTE_READWRITE, &old);
    for (int i = base; i < base + fish->OptionalHeader.SizeOfCode - 16; ++i) { // size of sig is 16
        if (
            *reinterpret_cast<byte*>(i) == 0xC7 && 
            *reinterpret_cast<byte*>(i + 1) == 0x45
        ) {
            lastebp = *reinterpret_cast<byte*>(i + 2);
            lastaddress = *reinterpret_cast<uintptr_t*>(i + 3);
        }
        if (
            *reinterpret_cast<byte*>(i) == 0x8B &&
            *reinterpret_cast<byte*>(i + 1) == 0x45 &&
            *reinterpret_cast<byte*>(i + 2) == lastebp &&
            *reinterpret_cast<byte*>(i + 3) == 0x2D
        ) {
            uintptr_t subaddy = *reinterpret_cast<uintptr_t*>(i + 4);
            enc_strings[reinterpret_cast<const char*>(lastaddress - subaddy)].push_back(i - reinterpret_cast<uintptr_t>(GetModuleHandle(NULL)) + idabase);
        }
    }
    VirtualProtect((LPVOID)base, fish->OptionalHeader.SizeOfCode, old, &old);

    return enc_strings;
}

void dump_enc_strings() {
    std::unordered_map<std::string, std::vector<int>> enc_strings = resolve_encrypted_strings(0x7C0000);

    for (std::pair<std::string, std::vector<int>> member : enc_strings) {
        printf_s("\"%s\" - {", member.first.c_str());
        for (int i = 0; i < member.second.size(); ++i) {
            if (i == member.second.size() - 1) {
                printf_s("0x%08X}\n", member.second[i]);
            }
            else {
                printf_s("0x%08X, ", member.second[i]);
            }
        }
    }

    std::cout << "done!\n";
}
