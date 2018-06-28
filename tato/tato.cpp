//library stuff
void print(const char* fmt, ...);
void error_func(const char* fmt, ...);
void error_loc(const char* loc, const char* fmt, ...);
#define error(...) { __debugbreak(); error_func(__VA_ARGS__); }
extern "C" { int strcmp(const char* str1, const char* str2); size_t strlen(const char* str); };
typedef long long s64; typedef unsigned long long u64;
typedef unsigned char u8; typedef char s8; typedef unsigned short u16; typedef int s32; typedef unsigned int u32;
typedef float f32;
extern "C" { __declspec(dllimport) __declspec(allocator) __declspec(restrict) void* calloc(u64 count, u64 size); __declspec(dllimport) void free(void* ptr); }
extern "C" { void* __cdecl memset(void*  _Dst, int    _Val, size_t _Size); void* __cdecl memcpy(void* _Dst, void const* _Src, size_t _Size); }
u64 str_hash(const char* str, size_t len) {
    u64 x = 0xcbf29ce484222325ull;
    for (u32 i = 0; i < len; ++i) {
        x ^= str[i]; x *= 0x100000001b3ull; x ^= x >> 32;
    }
    return x;
}
u64 hash(const char* str) { return str_hash(str, strlen(str)); }
u64 hash(u64 v) { return v; }
template <typename K, typename V> struct Map {
    K* keys; V* vals;
    u32 len, cap;
    void clear() { delete[] keys; delete[] vals; *this = {}; }
    V* get(K key) {
        if (len == 0) return nullptr;
        u64 i = hash(key);
        while (true) {
            i &= cap - 1;
            if (keys[i] == key)
                return &vals[i];
            else if (!keys[i])
                return nullptr;
            ++i;
        }
        return nullptr;
    }
    void grow() {
        u32 newcap = cap * 2 < 16 ? 16 : cap * 2;
        Map new_map = { (K*)calloc(1, sizeof(K)*newcap), (V*)calloc(1, sizeof(V)*newcap), 0, newcap };
        for (u32 i = 0; i < cap; ++i)
            if (keys[i])
                new_map.put(keys[i], vals[i]);
        free(keys); free(vals);
        *this = new_map;
    }
    void put(K key, V val) {
        if (2 * len >= cap)
            grow();
        u64 i = hash(key);
        while (true) {
            i &= cap - 1;
            if (keys[i] == key) {
                vals[i] = val; return;
            }
            else if (!keys[i]) {
                ++len; keys[i] = key; vals[i] = val; return;
            }
            ++i;
        }
    }
};
template <typename T> struct Vector {
    T* items; u32 len, cap;
    T* begin() { return items; }
    T& back() { return items[len - 1]; }
    T* end() { return items + len; }
    void clear() { delete[] items; *this = {}; }
    void grow() {
        resize(cap * 2 < 16 ? 16 : cap * 2);
    }
    void resize(u32 size) {
        cap = size;
        T* newitems = new T[size]{};
        if (items) {
            if (size < len) len = size;
            for (u32 i = 0; i < len; ++i)
                newitems[i] = items[i];
            delete[] items;
        }
        items = newitems;
    }
    void push(T item) {
        if (len >= cap) grow();
        items[len++] = item;
    }
    T pop() { if (len > 0) { --len; } return items[len]; }
};
template <typename T> struct Pool {
    T* items; u32 len;
    T* push(T item) {
        if (len == 0 || len >= 32) {
            items = new T[32]{}; len = 0;
        }
        items[len++] = item; return &items[len - 1];
    }
};
void print_buf(Vector<char>& buf, const char* fmt, ...);

//string interning
Map<u64, char*> strs{};
const char* internstr(const char* beg, const char* end) {
    u32 len = (u32)(end - beg);
    u64 hash = str_hash(beg, len);
    if (char** existingstr = strs.get(hash))
        return *existingstr;
    char* str = new char[len + 1];
    for (char* t = str; beg != end; ++beg, ++t) *t = *beg;
    str[len] = 0;
    strs.put(hash, str);
    return str;
}
const char* internstr(const char* str) { return internstr(str, str + strlen(str)); }

enum class TokenType { GTEQ, LSH, RSH, EQ, ENDL, ADD, SUB, LT, NOT, AND, OR, INT_VAL, REG, ID, EOF, MEM, LSB, RSB, IF, LPR, RPR, EQEQ, DOLLAR, COLON, ZERO, VAL };
const char* token_strs[] = { ">=", "<<", ">>", "=", "newline", "+", "-", "<", "!", "&", "|", "integer value", "register", "label", "eof", "mem", "[", "]", "if", "(", ")", "==", "$", ":", "zero", "val" };
struct Token { TokenType type; const char *str, *loc; u32 val; };
Token token{};
const char *stream = nullptr, *streambeg = nullptr;
#define TOK(v, t) if (c == v) { token.type = TokenType::t; ++stream; return; }
#define TOK2(v, t) if (c == v[0] && stream[1] == v[1]) { token.type = TokenType::t; stream+=2; return; }
#define KEYW(s,t) static const char* t = nullptr; if (t == nullptr) { t = internstr(s); } if (t == token.str) { token.type = TokenType::t; return; }
void nexttoken() {
    token = {};
    token.loc = stream;
    char c = *stream;
    while (c == ' ' || c == '\t' || c == '\r') { ++stream; c = *stream; }
    if (c == '#') {
        ++stream; c = *stream;
        while (c != '\n' && c != 0) { ++stream; c = *stream; }
    }
    TOK2(">=", GTEQ) TOK2("<<", LSH) TOK2(">>", RSH) TOK2("==", EQEQ) TOK2("if", IF) TOK2("==", EQEQ)
    TOK('=', EQ) TOK('\n', ENDL) TOK('+', ADD) TOK('-', SUB) TOK('<', LT) 
    TOK('!', NOT) TOK('&', AND) TOK('|', OR) TOK('$', DOLLAR) TOK(':', COLON)
    TOK(0, EOF) TOK('[', LSB) TOK(']', RSB) TOK('(', LPR) TOK(')', RPR)
    if (c == 'r' && stream[1] >= '0' && stream[1] <= '9') {
        token.type = TokenType::REG;
        token.val = stream[1] - '0';
        if (token.val < 0 || token.val > 7) error("Invalid register %d", token.val);
        stream += 2;
        return;
    }
    if (c == 's' && stream[1] == 'p') { token.type = TokenType::REG; token.val = 6; stream += 2; return; }
    if (c == 'p' && stream[1] == 'c') { token.type = TokenType::REG; token.val = 7; stream += 2; return; }
    if (c >= '0' && c <= '9' && stream[1] == 'x') {
        int num = 0; stream += 2; c = *stream;
        while ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
            num *= 16;
            if (c >= '0' && c <= '9')
                num += c - '0';
            else if (c >= 'A' && c <= 'F')
                num += c - 'A' + 10;
            else if (c >= 'a' && c <= 'f')
                num += c - 'a' + 10;
            ++stream; c = *stream;
        }
        token.type = TokenType::INT_VAL; token.val = num; return;
    }
    if (c >= '0' && c <= '9') {
        int num = 0;
        while (c >= '0' && c <= '9') {
            num *= 10; num += c - '0'; ++stream; c = *stream;
        }
        if (c == 'x') ++stream;
        token.type = TokenType::INT_VAL; token.val = num; return;
    }
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
        const char* start = stream;
        while ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') { ++stream; c = *stream; }
        token.str = internstr(start, stream);
        KEYW("mem", MEM) KEYW("val", VAL) KEYW("zero", ZERO)
        token.type = TokenType::ID; return;
    }
    error("Unexpected token '%c' (%d)", c, c);
}

enum class OpCode : u8 {
    LIT, ADD, LOAD, STORE, LT, GTEQ, TEST, SUB, AND, OR, LSH, RSH, NOT
};
const char* opcode_strs[] = { "", "+", "", "", "<", ">=", "", "-", "&", "|", "<<", ">>", "!" };
#pragma pack(push, 1)
struct Inst {
    Inst() : value(0) {}
    Inst(u16 val) : value(val) {}
    Inst(OpCode op, bool litC, u8 rA, bool zB, u8 rB, u8 rC) : opcode(op), litC(litC), rA(rA), zB(zB), rB(rB), rC(rC) {}
    Inst(u8 rA, bool top, u8 lit) : opcode(OpCode::LIT), litC(top), rA(rA), lit(lit) {}
    union {
        struct {
            OpCode opcode : 4; bool litC : 1; u8 rA : 3;
            union
            {
                struct { bool zB : 1; u8 rB : 3; u8 rC : 4; };
                u8 lit : 8;
            };
        };
        u16 value;
    };
};
#pragma pack(pop)
static_assert(sizeof(u16) == sizeof(Inst), "?");
Vector<Inst> gen_asm{};
Map<const char*, u32> labels{};
struct LabelFixup {
    const char *label, *loc;
    u32 idx;
};
Vector<LabelFixup> label_fixups{};
static bool match(TokenType type) { if (type == token.type) { nexttoken(); return true; } return false; }
static void expect(TokenType type) { if (type != token.type) { error("Expected %s not %s", token_strs[(int)type], token_strs[(int)token.type]); } nexttoken(); }
static void expect_endl() { if (token.type != TokenType::ENDL && token.type != TokenType::EOF) { error("Expected end of line"); if (token.type == TokenType::ENDL) nexttoken(); } }
static void parse_rC(Inst& inst) {
    if (token.type == TokenType::REG) {
        inst.litC = false; inst.rC = token.val; nexttoken();
    }
    else if (token.type == TokenType::INT_VAL) {
        if (token.val > 0xF) error("Literal value 0x%x too large (max 0xF)", token.val);
        inst.litC = true; inst.rC = token.val; nexttoken();
    }
    else
        error("Expected rC value or register not %s", token_strs[(int)token.type]);
}
static void parse_pair(Inst& inst, TokenType l_bracket, TokenType op_type, TokenType r_bracket) {
    expect(l_bracket);
    if (token.type == TokenType::INT_VAL) {
        if (token.val > 0xF) error("Literal value 0x%x too large (max 0xF)", token.val);
        inst.zB = true; inst.rB = 0;
        inst.litC = true; inst.rC = token.val;
        nexttoken();
        if (match(op_type)) {
            if (inst.rC != 0) error("rB must be 0");
            parse_rC(inst);
        }
    }
    else if (token.type == TokenType::REG) {
        inst.zB = false; inst.rB = token.val; nexttoken();
        expect(op_type);
        parse_rC(inst);
    }
    expect(r_bracket);
}
static void parse(const char* str) {
    streambeg = str; stream = str; gen_asm.clear(); labels.clear(); label_fixups.clear(); 
    nexttoken();
    while (token.type != TokenType::EOF) {
        while (token.type == TokenType::ENDL) nexttoken();
        if (token.type == TokenType::EOF) break;
        if (token.type == TokenType::ID) {
            labels.put(token.str, gen_asm.len); nexttoken();
            expect(TokenType::COLON); 
            expect_endl();
        }
        else if (match(TokenType::ZERO)) {
            if (token.type != TokenType::INT_VAL) error("Expected int value");
            Inst inst{};
            inst.value = 0;
            for (u32 i = 0; i < token.val; ++i)
                gen_asm.push(inst);
            nexttoken(); expect_endl();
        }
        else if (match(TokenType::VAL)) {
            if (token.type != TokenType::INT_VAL) error("Expected int value");
            Inst inst{};
            inst.value = token.val;
            gen_asm.push(inst);
            nexttoken(); expect_endl();
        }
        else if (token.type == TokenType::REG) {
            Inst inst{};
            inst.rA = token.val; nexttoken();
            expect(TokenType::EQ);
            if (token.type == TokenType::REG) {
                inst.rB = token.val; inst.zB = false; nexttoken();
            }
            else if (token.type == TokenType::INT_VAL) {
                if (token.val > 0) {//literal
                    if (token.val > 0xFFFF) error("Literal value 0x%x too large (max 0xFFFF)", token.val);
                    inst.opcode = OpCode::LIT;
                    inst.litC = false;/*top=false*/ inst.lit = token.val & 0xFF;
                    gen_asm.push(inst);
                    if (token.val > 0xFF) {
                        inst.litC = true;/*top=true*/ inst.lit = token.val >> 8;
                        gen_asm.push(inst);
                    }
                    nexttoken();
                    expect_endl();
                    continue;
                }
                if (token.val != 0) error("rB can only be 0 when used as a literal value");
                inst.rB = 0; inst.zB = true; nexttoken();
            }
            else if (match(TokenType::DOLLAR)) {
                inst.opcode = OpCode::LIT;
                inst.litC = false; inst.lit = 0;
                label_fixups.push({ token.str, token.loc, gen_asm.len });
                gen_asm.push(inst);
                inst.litC = true; inst.lit = 0;
                nexttoken();
                expect_endl();
                continue;
            }
            else if (match(TokenType::NOT)) {
                inst.rB = 0; inst.zB = true;
                parse_rC(inst);
                expect_endl();
                gen_asm.push(inst);
                continue;
            }
            else if (match(TokenType::SUB)) {
                inst.opcode = OpCode::SUB; inst.rB = 0; inst.zB = true;
                parse_rC(inst);
                expect_endl();
                gen_asm.push(inst);
                continue;
            }
            else if (match(TokenType::MEM)) {
                inst.opcode = OpCode::LOAD;
                parse_pair(inst, TokenType::LSB, TokenType::ADD, TokenType::RSB);
                expect_endl();
                gen_asm.push(inst);
                continue;
            }
            else
                error("Unexpected token %s", token_strs[(int)token.type]);

            if (token.type == TokenType::ENDL || token.type == TokenType::EOF) {
                if (inst.zB) {
                    inst.opcode = OpCode::LIT; inst.lit = inst.rB; nexttoken();
                    gen_asm.push(inst);
                    continue;
                }
                inst.opcode = OpCode::ADD;
                inst.rC = inst.rB;
                inst.rB = 0; inst.zB = true;
                nexttoken();
                gen_asm.push(inst);
                continue;
            }

            switch (token.type) {
            case TokenType::ADD: inst.opcode = OpCode::ADD; break;
            case TokenType::LT: inst.opcode = OpCode::LT; break;
            case TokenType::GTEQ: inst.opcode = OpCode::GTEQ; break;
            case TokenType::SUB: inst.opcode = OpCode::SUB; break;
            case TokenType::AND: inst.opcode = OpCode::AND; break;
            case TokenType::OR: inst.opcode = OpCode::OR; break;
            case TokenType::LSH: inst.opcode = OpCode::LSH; break;
            case TokenType::RSH: inst.opcode = OpCode::RSH; break;
            default: error("Unexpected op %s", token_strs[(int)token.type]);
            }
            nexttoken();

            parse_rC(inst);
            expect_endl();
            gen_asm.push(inst);
        }
        else if (match(TokenType::MEM)) {
            Inst inst{};
            inst.opcode = OpCode::STORE;
            parse_pair(inst, TokenType::LSB, TokenType::ADD, TokenType::RSB);
            expect(TokenType::EQ);
            if (token.type != TokenType::REG) error("Expected register");
            inst.rA = token.val;
            nexttoken();
            expect_endl();
            gen_asm.push(inst);
        }
        else if (match(TokenType::IF)) {
            Inst inst{};
            inst.opcode = OpCode::TEST;
            inst.rA = 7;
            parse_pair(inst, TokenType::LPR, TokenType::EQEQ, TokenType::RPR);
            expect_endl();
            gen_asm.push(inst);
        }
        else
            error("Unexpected token %s", token_strs[(int)token.type]);
    }

    Vector<Inst> final_asm{};
    u32 fixup_idx = 0;
    for (u32 i = 0; i < gen_asm.len; ++i) {
        Inst inst = gen_asm.items[i];
        if (fixup_idx < label_fixups.len && label_fixups.items[fixup_idx].idx == i) {
            LabelFixup& fixup = label_fixups.items[fixup_idx];
            u32* val = labels.get(fixup.label);
            if (!val) error_loc(fixup.loc, "Undefined label %s", fixup.label);
            if (inst.opcode != OpCode::LIT) error("Expected literal instruction");
            if (*val > 0xFF) {
                inst.litC = true; inst.lit = *val >> 8;
                final_asm.push(inst);
                for (u32 j = fixup_idx + 1; j < label_fixups.len; ++j)
                    label_fixups.items[j].idx++;
                for (u32 j = 0; j < labels.cap; ++j)
                    if (labels.keys[j] && labels.vals[j] > fixup_idx)
                        labels.vals[j]++;
            }
            inst.litC = false; inst.lit = *val;
            ++fixup_idx;
        }
        final_asm.push(inst);
    }
    gen_asm.clear();
    gen_asm = final_asm;
    
    if (gen_asm.len * sizeof(Inst) >= 0x8000) error("Program too large! Total size %d kb (max %d KB)", (gen_asm.len * sizeof(Inst)) / 1024, 0x8000 / 1024);
}

//disassembly
static const char* disasm_reg(u8 reg) {
    switch (reg) {
    case 0: return "r0"; case 1: return "r1"; case 2: return "r2"; case 3: return "r3"; 
    case 4: return "r4"; case 5: return "r5"; case 6: return "sp"; case 7: return "pc";
    default: error("Invalid register %d", reg); return nullptr;
    }
}
static const char* disasm_rB(Inst& inst) {
    return inst.zB ? "0" : disasm_reg(inst.rB);
}
static const char* disasm_rC(Inst& inst) {
    if (inst.litC) {
        static Vector<char> buf{};
        buf.clear();
        print_buf(buf, "%d", inst.rC);
        return buf.items;
    }
    else return disasm_reg(inst.rC);
}
static const char* disasm(const char* str, u32 size) {
    static Vector<char> disasm_buf{};
    disasm_buf.clear();
    Inst* insts = (Inst*)str;
    if (size % sizeof(Inst) != 0) error("File size %d not a multiple of 16", size);
    u32 count = size / sizeof(Inst);
    for (u32 i = 0; i < count; ++i) {
        Inst& inst = insts[i];
        switch (inst.opcode) {
        case OpCode::LIT: {
            u16 lit = inst.litC ? inst.lit << 8 : inst.lit;
            print_buf(disasm_buf, "%x: %s = %d (0x%x)\n", i, disasm_reg(inst.rA), lit, lit);
        } break;
        case OpCode::LOAD:
            print_buf(disasm_buf, "%x: %s = mem[%s + %s]\n", i, disasm_reg(inst.rA), disasm_rB(inst), disasm_rC(inst));
            break;
        case OpCode::STORE:
            print_buf(disasm_buf, "%x: mem[%s + %s] = %s\n", i, disasm_rB(inst), disasm_rC(inst), disasm_reg(inst.rA));
            break;
        case OpCode::TEST:
            print_buf(disasm_buf, "%x: if (%s == %s)\n", i, disasm_rB(inst), disasm_rC(inst));
            break;
        case OpCode::ADD: case OpCode::LT: case OpCode::GTEQ: case OpCode::SUB: 
        case OpCode::AND: case OpCode::OR: case OpCode::LSH: case OpCode::RSH:
            print_buf(disasm_buf, "%x: %s = %s %s %s\n", i, disasm_reg(inst.rA), disasm_rB(inst), opcode_strs[(int)inst.opcode], disasm_rC(inst));
            break;
        case OpCode::NOT:
            print_buf(disasm_buf, "%x: %s = !%s", disasm_reg(inst.rA), disasm_rC(inst));
            break;
        }
    }
    return disasm_buf.items;
}

static void run_vm(u16(&regs)[8], u32 max_cycles) {
    u16 mem[0xFFFF];
    memset(mem, 0, sizeof(mem));
    memcpy(mem, gen_asm.items, sizeof(Inst)*gen_asm.len);
    memset(regs, 0, sizeof(u16) * 8);
    u32 cycles = 0;
    while (regs[7] < 0xFFFF && (max_cycles == 0 || cycles < max_cycles)) {
        Inst inst = Inst(mem[regs[7]]);
        u16& rA = regs[inst.rA];
        u16 rB = inst.zB ? 0 : regs[inst.rB];
        u16 rC = inst.litC ? inst.rC : regs[inst.rC];
        switch (inst.opcode) {
            case OpCode::LIT: rA = (rA & (inst.litC ? 0xFF : 0xFF00)) | (inst.litC ? inst.lit << 8 : inst.lit); break;
            case OpCode::ADD: rA = rB + rC; break; 
            case OpCode::LOAD: rA = mem[rB + rC]; break;
            case OpCode::STORE: mem[rB + rC] = rA; break;
            case OpCode::LT: rA = rB < rC; break;
            case OpCode::GTEQ: rA = rB >= rC; break;
            case OpCode::TEST: rA = rA + (rB == rC ? 1 : 2); break;
            case OpCode::SUB: rA = rB - rC; break;
            case OpCode::AND: rA = rB & rC; break;
            case OpCode::OR: rA = rB | rC; break;
            case OpCode::LSH: rA = rB << rC; break;
            case OpCode::RSH: rA = rB >> rC; break;
            case OpCode::NOT: rA = !rC; break;
            default: error("Undefined opcode %x", inst.opcode); break;
        }
        if (inst.rA != 7) ++regs[7];
        ++cycles;
    }
}

template<int size> static void test_asm(const char* str, const Inst(&expected)[size], int expected_offset = 0) {
    parse(str);
    if (size + expected_offset != gen_asm.len)
        error("Expected asm of length %d not %d", size, gen_asm.len);
    for (int i = 0; i < size; ++i)
        if (expected[i].value != gen_asm.items[i + expected_offset].value) {
            const Inst* e = expected + i;
            const Inst* v = gen_asm.items + i + expected_offset;
            error("Expected 0x%x got 0x%x", e->value, v->value);
        }
}
static void test_disasm(const char* str, const char* expected) {
    parse(str);
    const char* got = disasm((const char*)gen_asm.items, gen_asm.len * sizeof(Inst));
    if (strcmp(got, expected) != 0) error("Expected '%s' got '%s'\n", expected, got);
}
static void test_vm(const char* str, u32 max_cycles, const u16(&expected_regs)[8]) {
    parse(str);
    u16 regs[8];
    memset(regs, 0, sizeof(regs));
    run_vm(regs, max_cycles);
    for (u32 i = 0; i < 8; ++i) {
        if (regs[i] != expected_regs[i]) {
            error("r%d expected %d got %d", i, expected_regs[i], regs[i]);
        }
    }
}

static void test() {
    test_asm("r2=0x0\n", { Inst(2, false, 0) });
    test_asm("r0=0xFFFF\n", { Inst(0, false, 0xFF), Inst(0, true, 0xFF) });
    test_asm("#test comment\n\n   r0 = 3\nr1 = r0 + 7\n", { Inst(0, false, 3), Inst(OpCode::ADD, true, 1, false, 0, 7) });
    test_asm("r0 = r1\nr1 = r2\n r3=r4\n \tr5=   r6\nr6=r7\npc=sp\nsp=pc\n", { Inst(OpCode::ADD, false, 0, true, 0, 1), Inst(OpCode::ADD, false, 1, true, 0, 2), Inst(OpCode::ADD, false, 3, true, 0, 4), Inst(OpCode::ADD, false, 5, true, 0, 6), Inst(OpCode::ADD, false, 6, true, 0, 7), Inst(OpCode::ADD, false, 7, true, 0, 6), Inst(OpCode::ADD, false, 6, true, 0, 7) });
    test_asm("r1=0x6972\n", { Inst(1, false, 0x72), Inst(1, true, 0x69) });
    test_asm("r0=r1+r2\nr3=r4+r5\nr6=sp+pc\nr7=r7+r7\n", { Inst(OpCode::ADD, false, 0, false, 1, 2), Inst(OpCode::ADD, false, 3, false, 4, 5), Inst(OpCode::ADD, false, 6, false, 6, 7), Inst(OpCode::ADD, false, 7, false, 7, 7) });
    test_asm("r0=0+r3\nr1=0-r2\nr2=r3-3\nr4=r5-0xF", { Inst(OpCode::ADD, false, 0, true, 0, 3), Inst(OpCode::SUB, false, 1, true, 0, 2), Inst(OpCode::SUB, true, 2, false, 3, 3), Inst(OpCode::SUB, true, 4, false, 5, 0xF) });
    test_asm("r5=0-5\nr0=r1<r2\nr3=r4>=3\nr4=r1&r2\nr5=r6|r7", { Inst(OpCode::SUB, true, 5, true, 0, 5), Inst(OpCode::LT, false, 0, false, 1, 2), Inst(OpCode::GTEQ, true, 3, false, 4, 3), Inst(OpCode::AND, false, 4, false, 1, 2), Inst(OpCode::OR, false, 5, false, 6, 7) });
    test_asm("pc=-15\nr1=-r2\n", { Inst(OpCode::SUB, true, 7, true, 0, 0xF), Inst(OpCode::SUB, false, 1, true, 0, 2) });
    test_asm("r0=r1<<r2\nr2=r3>>r4\nr5=0<<1\nr6=0>>3", { Inst(OpCode::LSH, false, 0, false, 1, 2), Inst(OpCode::RSH, false, 2, false, 3, 4), Inst(OpCode::LSH, true, 5, true, 0, 1), Inst(OpCode::RSH, true, 6, true, 0, 3) });
    test_asm("mem[0] = r0\nmem[0+0]=r0\nmem[sp+14] = r1\nmem[0xF] = r3\nmem[r2+r3]=r4\n", { Inst(OpCode::STORE, true, 0, true, 0, 0), Inst(OpCode::STORE, true, 0, true, 0, 0), Inst(OpCode::STORE, true, 1, false, 6, 14), Inst(OpCode::STORE, true, 3, true, 0, 0xF), Inst(OpCode::STORE, false, 4, false, 2, 3) });
    test_asm("r0 = mem[0]\nr1=mem[sp+14]\nr3=mem[0xF]\nr4=mem[r2+r3]\n", { Inst(OpCode::LOAD, true, 0, true, 0, 0), Inst(OpCode::LOAD, true, 1, false, 6, 14), Inst(OpCode::LOAD, true, 3, true, 0, 0xF), Inst(OpCode::LOAD, false, 4, false, 2, 3) });
    test_asm("if (0 == 0)\nif (r1 == 3)\nif (r6 == r5)", { Inst(OpCode::TEST, true, 7, true, 0, 0), Inst(OpCode::TEST, true, 7, false, 1, 3), Inst(OpCode::TEST, false, 7, false, 6, 5) });
    test_asm("r0=37\nr0=$bar\nbar:\nr0=3", { Inst(0, false, 37), Inst(0, false, 2), Inst(0, false, 3) });
    test_asm("foo:\nr0=38\npc=$foo", { Inst(0, false, 38), Inst(7, false, 0) });
    test_asm("pc = $end\na:\nval 10\nb:\nval 5\nend:\nr0 = $a\nr1 = $b\n", { Inst(7, false, 3), Inst(10), Inst(5), Inst(0, false, 1), Inst(1, false, 2) });
    test_asm("zero 3\n", { Inst(0), Inst(0), Inst(0) });
    test_asm("zero 512\ntest:\nr5 = 5\npc = $test\n", { Inst(5, false, 5), Inst(7, true, 2), Inst(7, false, 1) }, 512);
    test_disasm("r0=0xFFFF\nr5=0x6972", "0: r0 = 255 (0xff)\n1: r0 = 65280 (0xff00)\n2: r5 = 114 (0x72)\n3: r5 = 26880 (0x6900)\n");
    test_disasm("r2=0x0", "0: r2 = 0 (0x0)\n");
    test_disasm("r0 = r1\nr1 = r2\n r3 = r4\n \tr5 = r6\nr6 = r7\npc = sp\nsp = pc", "0: r0 = 0 + r1\n1: r1 = 0 + r2\n2: r3 = 0 + r4\n3: r5 = 0 + sp\n4: sp = 0 + pc\n5: pc = 0 + sp\n6: sp = 0 + pc\n");
    test_disasm("r0=r1+r2\nr3=r4+r5\nr6=sp+pc\nr7=r7+r7\n", "0: r0 = r1 + r2\n1: r3 = r4 + r5\n2: sp = sp + pc\n3: pc = pc + pc\n");
    test_disasm("r0=0+r3\nr1=0-r2\nr2=r3-3\nr4=r5-0xF", "0: r0 = 0 + r3\n1: r1 = 0 - r2\n2: r2 = r3 - 3\n3: r4 = r5 - 15\n");
    test_disasm("r5=0-5\nr0=r1<r2\nr3=r4>=3\nr4=r1&r2\nr5=r6|r7", "0: r5 = 0 - 5\n1: r0 = r1 < r2\n2: r3 = r4 >= 3\n3: r4 = r1 & r2\n4: r5 = sp | pc\n");
    test_disasm("pc=-15\nr1=-r2\n", "0: pc = 0 - 15\n1: r1 = 0 - r2\n");
    test_disasm("r0=r1<<r2\nr2=r3>>r4\nr5=0<<1\nr6=0>>3", "0: r0 = r1 << r2\n1: r2 = r3 >> r4\n2: r5 = 0 << 1\n3: sp = 0 >> 3\n");
    test_disasm("mem[0] = r0\nmem[0+0]=r0\nmem[sp+14] = r1\nmem[0xF] = r3\nmem[r2+r3]=r4\n", "0: mem[0 + 0] = r0\n1: mem[0 + 0] = r0\n2: mem[sp + 14] = r1\n3: mem[0 + 15] = r3\n4: mem[r2 + r3] = r4\n");
    test_disasm("r0 = mem[0]\nr1=mem[sp+14]\nr3=mem[0xF]\nr4=mem[r2+r3]\n", "0: r0 = mem[0 + 0]\n1: r1 = mem[sp + 14]\n2: r3 = mem[0 + 15]\n3: r4 = mem[r2 + r3]\n");
    test_disasm("if (0 == 0)\nif (r1 == 3)\nif (r6 == r5)", "0: if (0 == 0)\n1: if (r1 == 3)\n2: if (sp == r5)\n");
    test_disasm("r0=37\nr0=$bar\nbar:\nr0=3", "0: r0 = 37 (0x25)\n1: r0 = 2 (0x2)\n2: r0 = 3 (0x3)\n");
    test_disasm("foo:\nr0=38\npc=$foo", "0: r0 = 38 (0x26)\n1: pc = 0 (0x0)\n");
    test_disasm("pc = $end\na:\nval 10\nb:\nval 5\nend:\nr0 = $a\nr1 = $b\n", "0: pc = 3 (0x3)\n1: r0 = r0 << r0\n2: r0 = r0 >= r0\n3: r0 = 1 (0x1)\n4: r1 = 2 (0x2)\n");
    test_vm("r0=0xFFFF\npc=r0", 0, { 0xFFFF, 0, 0, 0, 0, 0, 0, 0xFFFF });
    test_vm("r0=0|1\nr1=2\nr2=r1+5\nr3=0-15\nr4=5\nr5=r1+r4\nr6=r1<<2\n", 7, { 1, 2, 7, (u16)-15, 5, 7, 8, 7 });
    test_vm("loop:\nr0=r0+1\nr1=r0<15\nif (r1==1)\npc=$loop\nr2=0xFFFF\npc=r2\n", 0, { 15, 0, 0xFFFF, 0, 0, 0, 0, 0xFFFF });
    test_vm("mem[1] = 10\nmem[2] = 20\nmem[3] = 30\nr0=3\nmem[r0+1] = 40\nr0 = mem[1]\nr1 = mem[2]\nr2 = mem[3]\nr3 = mem[4]\n", 9, { 10, 20, 30, 40, 0, 0, 0, 9 });
}

#define _CRT_SECURE_NO_WARNINGS
#include <cstdio>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <cassert>
#include <cstring>

extern "C" { __declspec(dllimport) void __stdcall OutputDebugStringA(const char* str); }
void print(const char* fmt, va_list args) {
    static char errbuf[1024];
    vsnprintf(errbuf, 1024, fmt, args);
    OutputDebugStringA(errbuf);
    printf("%s", errbuf);
}
void print(const char* fmt, ...) {
    va_list args; va_start(args, fmt); print(fmt, args); va_end(args);
}
void print_buf(Vector<char>& buf, const char* fmt, ...) {
    va_list args; va_start(args, fmt);
    int num = vsnprintf(nullptr, 0, fmt, args);
    buf.resize(buf.len + num + 1);
    vsnprintf(buf.items + buf.len, num + 1, fmt, args);
    buf.len += num;
    buf.items[buf.len] = 0;
}
void error_func(const char* loc, const char* fmt, va_list args) {
    print("Error: ");
    print(fmt, args);
    int line = 0, lineoff = 0;
    if (loc) {
        const char* linestart = streambeg, *lineend = streambeg;
        for (const char* s = streambeg; s != loc; ++s, ++lineoff) {
            if (*s == '\n') { ++line; lineoff = 0; linestart = s + 1; }
        }
        for (lineend = linestart; *lineend != '\0' && *lineend != '\n'; ++lineend);
        print(" at %d:%d\n%.*s\n", line + 1, lineoff, lineend - linestart, linestart);
        for (int i = 0; i < lineoff - 1; ++i) print(" ");
        print("^\n");
    }
    exit(1);
}
void error_func(const char* fmt, ...) {
    va_list args; va_start(args, fmt); error_func(token.loc, fmt, args); va_end(args);
}
void error_loc(const char* loc, const char* fmt, ...) {
    va_list args; va_start(args, fmt); error_func(loc, fmt, args); va_end(args);
}

int main(int argc, char** argv) {
    test();
    if (argc <= 1) {
        print("Usage:\n\t./tato source.asm -o target.bin\n\t./tato "); return 1;
    }

    const char* output_file = nullptr;
    Vector<char> input_asm{};
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 < argc) {
                output_file = argv[i + 1];
                ++i;
            }
        }
        else if (strcmp(argv[i], "-d") == 0) {
            if (i + 1 < argc) {
                const char* fname = argv[i];
                FILE* file = fopen(fname, "rb");
                if (!file) {
                    print("Failed to open %s: %s\n", fname, strerror(errno)); return 1;
                }
                fseek(file, 0, SEEK_END);
                u32 sz = (u32)ftell(file);
                fseek(file, 0, SEEK_SET);
                input_asm.resize(input_asm.len + sz + 1);
                if (fread(input_asm.items + input_asm.len, 1, sz, file) != sz) {
                    print("Failed to read %s: %s", fname, strerror(errno)); return 1;
                }
                input_asm.len = input_asm.cap - 1;
                input_asm.items[input_asm.len] = 0;
                fclose(file);
                print("%s\n", disasm(input_asm.items, input_asm.len));
            }
        }
        else {
            const char* fname = argv[i];
            print("Reading %s\n", fname);
            FILE* file = fopen(fname, "rb");
            if (!file) {
                print("Failed to open %s: %s\n", fname, strerror(errno)); return 1;
            }
            fseek(file, 0, SEEK_END);
            u32 sz = (u32)ftell(file);
            fseek(file, 0, SEEK_SET);
            input_asm.resize(input_asm.len + sz + 1);
            if (fread(input_asm.items + input_asm.len, 1, sz, file) != sz) {
                print("Failed to read %s: %s", fname, strerror(errno)); return 1;
            }
            input_asm.len = input_asm.cap - 1;
            input_asm.items[input_asm.len] = 0;
            fclose(file);
        }
    }
    print("Compiling\n");
    parse(input_asm.items);
    if (!output_file) {
        print("No output file specified with -o\n"); return 1;
    }
    {
        print("Writing %s\n", output_file);
        FILE* file = fopen(output_file, "wb");
        if (!file) {
            print("Failed to open %s: %s\n", output_file, strerror(errno)); return 1;
        }
        if (fwrite(gen_asm.items, 1, sizeof(u16)*gen_asm.len, file) != sizeof(u16)*gen_asm.len) {
            print("Failed to write %s: %s\n", output_file, strerror(errno)); return 1;
        }
        fclose(file);
    }
    return 0;
}

