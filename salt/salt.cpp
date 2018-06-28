//library stuff
void print(const char* fmt, ...);
struct Expr; struct Stmt;
void error(Expr* expr, const char* fmt, ...);
void error(Stmt* stmt, const char* fmt, ...);
void error(const char* fmt, ...);
extern "C" { int strcmp(const char* str1, const char* str2); }
typedef long long s64; typedef unsigned long long u64;
typedef unsigned char u8; typedef char s8; typedef int s32; typedef unsigned int u32;
typedef float f32;
extern "C" { __declspec(dllimport) __declspec(allocator) __declspec(restrict) void* calloc(u64 count, u64 size); __declspec(dllimport) void free(void* ptr); }
extern "C" { size_t strlen(const char* str); }
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
		cap = cap * 2 < 16 ? 16 : cap * 2;
		T* newitems = new T[cap]{};
		if (items)
			for (u32 i = 0; i < len; ++i)
				newitems[i] = items[i];
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

//string interning
Map<u64,char*> strs{};
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

//tokeniser
enum class TokenType { LPR, RPR, EQ, GT, LT, GTEQ, LTEQ, GTEQ, NEQ, ADD, SUB, MUL, DIV, MOD, DOT, LSB, INT_VAL, ID, EOF, COMMA, LBR, RBR, SC, IF, ELIF, ELSE, WHILE, FUNC, RETURN, FOR, COLON, VAR, TRUE, FALSE, RSB, INT, BOOL, STRUCT, CHAR, STR, AND, NULLPTR };
const char* token_strs[] = { "(", ")", "=", ">", "<", "==", "<=", ">=", "!=", "+", "-", "*", "/", "%", ".", "[", "int_val", "id", "<eof>", ",", "{", "}", ";", "if", "elif", "else", "while", "func", "return", "for", ":", "var", "true", "false", "]", "int", "bool", "struct", "char", "\"", "&", "nullptr" };
struct Token { TokenType type; int val; const char* str; const char* loc; } token;
const char *streambeg, *stream;
#define TOK(cv,t) case cv: { ++stream; token.type = TokenType::t; return; }
#define TOK2(cv,t) if (c == cv[0] && stream[1] == cv[1]) { stream += 2; token.type = TokenType::t; return; }
#define KEYW(s,t) static const char* t = internstr(s); if (t == token.str) { token.type = TokenType::t; return; }
void nexttoken() {
	token = {};
	char c = *stream;
	token.loc = stream;
	while (c == ' ' || c == '\t' || c == '\n') { ++stream; c = *stream; }
	if (c >= '0' && c <= '9') {
		int num = 0;
		while (c >= '0' && c <= '9') {
			num *= 10; num += c - '0'; ++stream; c = *stream;
		}
		token.type = TokenType::INT_VAL; token.val = num; return;
	}
	if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		const char* start = stream; ++stream; c = *stream;
		while ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') { ++stream; c = *stream; }
		token.str = internstr(start, stream); 
		KEYW("if", IF) KEYW("elif", ELIF) KEYW("else", ELSE) KEYW("while", WHILE) KEYW("func", FUNC) KEYW("return", RETURN) KEYW("for", FOR)
        KEYW("int", INT) KEYW("char", CHAR) KEYW("bool", BOOL) KEYW("struct", STRUCT) KEYW("var", VAR) KEYW("true", TRUE) KEYW("false", FALSE)
        KEYW("nullptr", NULLPTR)
		token.type = TokenType::ID; return;
	}
    if (c == '"') {
        const char* start = stream; ++stream; c = *stream;
        while (c >= ' ' && c <= '~' && c != '"' && c != '\0') { ++stream; c = *stream; }
        token.str = internstr(start + 1, stream);
        token.type = TokenType::STR; 
        if (c != '"') error("Expected \"");
        ++stream;
        return;
    }
	TOK2("==", EQEQ) TOK2("<=", LTEQ) TOK2(">=", GTEQ) TOK2("!=", NEQ)
    switch (c) {
	TOK('>', GT) TOK('<', LT) TOK(':', COLON)
	TOK('+', ADD) TOK('-', SUB) TOK('*', MUL) TOK('/', DIV) TOK('%', MOD) TOK('(', LPR) TOK(')', RPR) TOK('[', LSB) TOK(']', RSB)
	TOK('\0', EOF) TOK('=', EQ) TOK(',', COMMA) TOK('{', LBR) TOK('}', RBR) TOK(';', SC) TOK('&', AND) TOK('.', DOT)
    }
	error("Unknown symbol %c", c);
}
void expect(TokenType type) {
	if (token.type != type) error("Unexpected %s expected %s", token_strs[(int)token.type], token_strs[(int)type]);
	nexttoken();
}
bool match(TokenType type) {
	if (token.type == type) { nexttoken(); return true; }
	return false;
}

//parser
enum class TypeKind { NONE, VOID, FUNC, INT, CHAR, BOOL, STRUCT, INT_ARR, CHAR_ARR, BOOL_ARR, STRUCT_ARR, INT_PTR, CHAR_PTR, BOOL_PTR, STRUCT_PTR, NULL_PTR };
const char* type_strs[] = { "none","void", "func", "int", "char", "bool", "struct", "int[]", "char[]", "bool[]", "struct[]", "int*", "char*", "bool*", "struct*", "nullptr" };
struct Type {
    TypeKind kind; int size; Type* base; const char* struct_name;
    bool operator ==(const TypeKind& o) const { return kind == o; }
    bool operator !=(const TypeKind& o) const { return kind != o; }
    bool operator ==(const Type& o) const { return kind == o.kind && size == o.size && base == o.base && struct_name == o.struct_name; }
    bool operator !=(const Type& o) const { return !(*this == o); }
    operator bool() const { return kind != TypeKind::NONE; }
    bool is_array() const { return kind >= TypeKind::INT_ARR && kind <= TypeKind::STRUCT_ARR; }
    bool is_pointer() const { return kind >= TypeKind::INT_PTR && kind <= TypeKind::NULL_PTR; }
    bool is_maths_type() const { return kind >= TypeKind::INT && kind <= TypeKind::BOOL; }
    const char* to_str() const {
        static char buf[128];
        if (kind == TypeKind::STRUCT)
            return struct_name;
        else if (kind == TypeKind::STRUCT_PTR || kind == TypeKind::STRUCT_ARR) {
            u32 i = 0;
            while (i < 125 && struct_name[i] != '\0') {
                buf[i] = struct_name[i]; ++i;
            }
            if (kind == TypeKind::STRUCT_PTR) { buf[i++] = '*'; }
            else { buf[i++] = '['; buf[i++] = ']'; }
            buf[i] = 0;
            return buf;
        }
        else
            return type_strs[(int)kind]; 
    }
    Type() {}
    Type(TypeKind kind, int size = 1, Type* base = nullptr, const char* struct_name = nullptr) : kind(kind), size(size), base(base), struct_name(struct_name) {}
};
Pool<Type> types{};
u64 hash(Type& type) {
    return (u64)type.kind | (u64)type.size << 8 | (u64)type.struct_name << 16 | (u64)type.base << 32;
}
Map<Type, Type*> type_map{};
Type* make_type(Type type) {
    Type** t = type_map.get(type);
    if (t) return *t;
    Type* nt = types.push(type);
    type_map.put(type, nt);
    return nt;
}
Type* to_array(Type* type, int size) {
    switch (type->kind) {
    case TypeKind::INT: return make_type(Type(TypeKind::INT_ARR, size, type));
    case TypeKind::CHAR: return make_type(Type(TypeKind::CHAR_ARR, size, type));
    case TypeKind::BOOL: return make_type(Type(TypeKind::BOOL_ARR, size, type));
    case TypeKind::STRUCT: return make_type(Type(TypeKind::STRUCT_ARR, size, type, type->struct_name));
    default: error("Cannot create array of type %s", type->to_str()); return nullptr;
    }
}
Type* to_pointer_base_type(Type* type) {
    if (type->base) 
        return type->base;
    error("Cannot get base type for %s", type->to_str());
    return nullptr;
}
Type* to_pointer(Type* type) {
    switch (type->kind) {
        case TypeKind::INT: return make_type(Type(TypeKind::INT_PTR, 1, type));
        case TypeKind::CHAR: return make_type(Type(TypeKind::CHAR_PTR, 1, type));
        case TypeKind::BOOL: return make_type(Type(TypeKind::BOOL_PTR, 1, type));
        case TypeKind::STRUCT: return make_type(Type(TypeKind::STRUCT_PTR, 1, type, type->struct_name));
        default: error("Cannot create pointer of type %s", type->to_str()); return nullptr;
    }
}
struct Value {
	TypeKind type;
    union {
        int int_val; char char_val; bool bool_val;
    };
    static Value VOID() { Value t{}; t.type = TypeKind::VOID; return t; }
    static Value INT(int val) { Value t{}; t.type = TypeKind::INT; t.int_val = val; return t; }
	static Value FUNC() { Value t{}; t.type = TypeKind::FUNC; return t; }
    static Value CHAR(char val) { Value t{}; t.type = TypeKind::CHAR; t.char_val = val; return t; }
    static Value BOOL(bool val) { Value t{}; t.type = TypeKind::BOOL; t.bool_val = val; return t; }
    static Value NULLPTR() { Value t{}; t.type = TypeKind::NULL_PTR; return t; }
};
enum class ExprType { VAR, VAL, BINARY, CALL, ARRAY, CAST, PTR_DEREF, PTR_ADDR_OF };
struct Expr {
	ExprType type;
	const char* loc;
	union {
		const char* varname;
        Value val;
		struct { TokenType op; Expr *l, *r; } binary;
		struct { const char* funcname; Vector<Expr*> args; } call;
        struct { Vector<Expr*> vals; } arr;
        struct { Type* type; Expr* expr; } cast;
        Expr* ptr_expr;
	};
	Expr() {}
    Expr(const char* loc, Value val) : type(ExprType::VAL), loc(loc), val(val) {}
	Expr(const char* loc, TokenType op, Expr* l, Expr* r) : type(ExprType::BINARY), loc(loc), binary({ op, l, r }) {}
	Expr(const char* loc, const char* varname) : type(ExprType::VAR), loc(loc), varname(varname) {}
	Expr(const char* loc, const char* funcname, Vector<Expr*>& args) : type(ExprType::CALL), loc(loc), call({ funcname, args }) {}
    Expr(const char* loc, Vector<Expr*>& vals) : type(ExprType::ARRAY), loc(loc), arr({vals}) {}
    Expr(const char* loc, Type* type, Expr* expr) : type(ExprType::CAST), loc(loc), cast({ type, expr }) {}
    Expr(const char* loc, ExprType type, Expr* ptr_expr) : type(type), loc(loc), ptr_expr(ptr_expr) {}
};
Pool<Expr> exprs{};
struct Scope;
Expr* parse_expr(Scope* scope);
Type* parse_type(Scope* scope);
Expr* parse_binary(Scope* scope) {
    const char* loc = token.loc;
	if (match(TokenType::LPR)) {//parens
		Expr* expr = parse_expr(scope);
		expect(TokenType::RPR);
		return expr;
	}
	else if (token.type == TokenType::INT_VAL) {
		Token t = token; nexttoken();
		return exprs.push(Expr(loc, Value::INT(t.val)));
	}
    else if (token.type == TokenType::TRUE || token.type == TokenType::FALSE) {
        Token t = token; nexttoken();
        return exprs.push(Expr(loc, Value::BOOL(t.type == TokenType::TRUE)));
    }
	else if (token.type == TokenType::ID) {
		Token t = token; nexttoken();
		if (match(TokenType::LPR)) {//func call
			Vector<Expr*> args{};
			if (token.type != TokenType::RPR) {
				args.push(parse_expr(scope));
				while (match(TokenType::COMMA))
					args.push(parse_expr(scope));
			}
			expect(TokenType::RPR);
			return exprs.push(Expr(loc, t.str, args));
		}
		else//var
			return exprs.push(Expr(loc, t.str));
	}
    else if (token.type >= TokenType::INT && token.type <= TokenType::CHAR) {//cast
        Type* type = parse_type(scope);
        return exprs.push(Expr(loc, type, parse_expr(scope)));
    }
    else if (match(TokenType::LBR)) {//array
        Vector<Expr*> vals{};
        vals.push(parse_expr(scope));
        while (match(TokenType::COMMA))
            vals.push(parse_expr(scope));
        expect(TokenType::RBR);
        return exprs.push(Expr(loc, vals));
    }
    else if (token.type == TokenType::STR) {//string
        Vector<Expr*> vals{};
        const char* c = token.str;
        while (*c != '\0') {
            vals.push(exprs.push(Expr(loc, Value::CHAR(*c)))); ++c;
        }
        nexttoken();
        return exprs.push(Expr(loc, vals));
    }
    else if (match(TokenType::NULLPTR)) {//nullptr
        return exprs.push(Expr(loc, Value::NULLPTR()));
    }
	error("Unexpected %s", token_strs[(int)token.type]); return nullptr;
}
Expr* parse_unary(Scope* scope, TokenType p = TokenType::EQ) {
	if (p == TokenType::INT_VAL)
		return parse_binary(scope);
	TokenType np = (TokenType)((int)p + 1);
    const char* loc = token.loc;
    if (p == TokenType::DOT) {
        if (match(TokenType::AND))
            return exprs.push(Expr(loc, ExprType::PTR_ADDR_OF, parse_unary(scope, np)));
        else if (match(TokenType::MUL))
            return exprs.push(Expr(loc, ExprType::PTR_DEREF, parse_binary(scope)));
    }
	Expr* expr = parse_unary(scope, np);
    while (match(p)) {
        expr = exprs.push(Expr(loc, p, expr, parse_unary(scope, np)));
        if (p == TokenType::LSB) expect(TokenType::RSB);
        loc = token.loc;
    }
	return expr;
}
Expr* parse_expr(Scope* scope) {
	return parse_unary(scope);
}
enum class StmtType { EXPR, BLOCK, IF, WHILE, RETURN, VAR };
struct CondBlock { Expr* cond; Stmt* block; };
struct Stmt {
	StmtType type;
	const char* loc;
	union {
		Expr* expr;
        struct { Vector<Stmt*> stmts; Scope* scope; } block;
		struct { Vector<CondBlock> conds; Stmt* elseblock; } ifexpr;
		CondBlock whileexpr;
        struct { const char* varname; Type type; Expr* init; } var;
	};
	Stmt() {}
	Stmt(const char* loc, Vector<Stmt*>& stmts, Scope* scope) : type(StmtType::BLOCK), loc(loc), block({ stmts, scope }) {}
	Stmt(const char* loc, Vector<CondBlock>& conds, Stmt* elseblock) : type(StmtType::IF), loc(loc), ifexpr({ conds, elseblock }) {}
	Stmt(const char* loc, Expr* cond, Stmt* block) : type(StmtType::WHILE), loc(loc), whileexpr({ cond, block }) {}
	Stmt(const char* loc, bool is_return, Expr* expr) : type(is_return ? StmtType::RETURN : StmtType::EXPR), loc(loc), expr(expr) {}
    Stmt(const char* loc, const char* varname, Type type, Expr* init) : type(StmtType::VAR), loc(loc), var({ varname, type, init }) {}
};
Pool<Stmt> stmts;
struct ParamDef {
    const char* name; Type* type;
};
struct ScopeVar {
    const char* name; const char* loc; Type* type;
    union {
        struct { int local_var_idx; Expr* init; } var;
        struct { Type* ret_type; Vector<ParamDef> params; Vector<Stmt*> block; Scope* scope; } func;
    };
    ScopeVar() {}
    ScopeVar(const char* name, const char* loc, Type* ret_type, Vector<ParamDef> params, Scope* scope) : name(name), loc(loc), type(make_type(Type(TypeKind::FUNC))), func({ ret_type, params, {}, scope }) {}
    ScopeVar(const char* name, const char* loc, Type* type, Expr* init) : name(name), loc(loc), type(type), var({ 0, init }) {}
    ScopeVar(const char* name, const char* loc, Type* type, Vector<ParamDef> elems) : name(name), loc(loc), type(type), func({ type, elems, {}, nullptr }) {}
};
struct Scope {
    Vector<ScopeVar> vars; int local_var_count;
    Scope* parent;
    ScopeVar* get(const char* name) {
        for (ScopeVar& var : vars)
            if (var.name == name)
                return &var;
        if (parent) return parent->get(name);
        return nullptr;
    }
    ScopeVar* put(ScopeVar var) {
        if (get(var.name)) error(var.loc, "%s already exists", var.name);
        if (var.type->kind != TypeKind::FUNC && var.type->kind != TypeKind::STRUCT) {
            var.var.local_var_idx = local_var_count;
            local_var_count += var.type->size;
        }
        vars.push(var);
        return &vars.back();
    }
};
Pool<Scope> scopes{};
void parse_var(const char* loc, Scope* scope);
Stmt* parse_stmt(Scope* scope) {
    const char* loc = token.loc;
	if (match(TokenType::LBR)) {//scope block
		Vector<Stmt*> block{};
        Scope* block_scope = scopes.push({});
        block_scope->parent = scope;
        block_scope->local_var_count = scope->local_var_count;
        while (token.type != TokenType::RBR && token.type != TokenType::EOF) {
            Stmt* stmt = parse_stmt(scope);
            if (stmt) block.push(stmt);
        }
		expect(TokenType::RBR);
		return stmts.push(Stmt(loc, block, block_scope));
	}
	else if (match(TokenType::IF)) {
		expect(TokenType::LPR);
		Expr* ifexpr = parse_expr(scope);
		expect(TokenType::RPR);
		Stmt* thenstmt = parse_stmt(scope);
        if (!thenstmt) error("then statement block cannot be a variable definition");
		Vector<CondBlock> conds{};
		conds.push({ ifexpr, thenstmt });
		while (match(TokenType::ELIF)) {
			expect(TokenType::LPR);
			ifexpr = parse_expr(scope);
			expect(TokenType::RPR);
			thenstmt = parse_stmt(scope);
            if (!thenstmt) error("then statement block cannot be a variable definition");
			conds.push({ ifexpr, thenstmt });
		}
		Stmt* elsestmt = match(TokenType::ELSE) ? parse_stmt(scope) : nullptr;
		return stmts.push(Stmt(loc, conds, elsestmt));
	}
	else if (match(TokenType::WHILE)) {
		expect(TokenType::LPR);
		Expr* cond = parse_expr(scope);
		expect(TokenType::RPR);
		Stmt* block = parse_stmt(scope);
        if (!block) error("while statement block cannot be a variable definition");
		return stmts.push(Stmt(loc, cond, block));
	}
	else if (match(TokenType::RETURN)) {
		Expr* expr = parse_expr(scope); expect(TokenType::SC);
		return stmts.push(Stmt(loc, true, expr));
	}
	else if (match(TokenType::FOR)) {
		expect(TokenType::LPR);
		Vector<Stmt*> block{};
		if (token.type != TokenType::SC) {
			Expr* init = parse_expr(scope); block.push(stmts.push(Stmt(loc, false, init)));
			if (init->type != ExprType::BINARY && init->binary.op != TokenType::EQ) error(init, "Must initialise a variable");
		}
		expect(TokenType::SC);
		Expr* whilecond = parse_expr(scope); expect(TokenType::SC);
		Vector<Stmt*> forblock{};
		Expr* increment = parse_expr(scope);
		if (increment->type != ExprType::BINARY && increment->binary.op != TokenType::EQ) error(increment, "Must modify a variable");
		expect(TokenType::RPR);
        Stmt* body = parse_stmt(scope); if (body) { forblock.push(body); } forblock.push(stmts.push(Stmt(loc, false, increment)));
		block.push(stmts.push(Stmt(loc, whilecond, stmts.push(Stmt(loc, forblock, scope)))));
		return stmts.push(Stmt(loc, block, scope));
	}
    else if (match(TokenType::VAR)) {
        parse_var(loc, scope);
        return nullptr;
    }
	else {
		Expr* expr = parse_expr(scope); expect(TokenType::SC);
		return stmts.push(Stmt(loc, false, expr));
	}
}
Type* parse_type(Scope* scope) {
    Type* type = nullptr;
    switch (token.type) {
    case TokenType::INT: type = make_type(Type(TypeKind::INT)); break;
    case TokenType::CHAR: type = make_type(Type(TypeKind::CHAR)); break;
    case TokenType::BOOL: type = make_type(Type(TypeKind::BOOL)); break;
    case TokenType::ID: {
        ScopeVar* struc = scope->get(token.str);
        if (!struc) error("Undefined struct %s", token.str);
        if (struc->type->kind != TypeKind::STRUCT) error("%s is an %s not a struct", token.str, struc->type->to_str());
        type = struc->type;
    }
        break;
    default: error("Expected type"); return nullptr;
    }
    nexttoken();
    if (match(TokenType::LSB)) {
        int size = -1;
        if (token.type == TokenType::INT) {
            size = token.val; nexttoken();
        }
        expect(TokenType::RSB);
        return to_array(type, size);
    }
    if (match(TokenType::MUL)) {
        return to_pointer(type);
    }
    return type;
}
Type* validate_expr(Expr* expr, Scope* scope) {
    switch (expr->type) {
    case ExprType::BINARY: {
        Type* left = validate_expr(expr->binary.l, scope);
        if (expr->binary.op == TokenType::DOT) {//struct member deref
            if (left->kind != TypeKind::STRUCT_PTR && left->kind != TypeKind::STRUCT) error(expr, "Expected struct or struct pointer");
            if (expr->binary.r->type != ExprType::VAR) error(expr, "Expected struct field");
            ScopeVar* struc = scope->get(left->struct_name);
            for (ParamDef& parm : struc->func.params) {
                if (parm.name == expr->binary.r->varname)
                    return parm.type;
            }
            error(expr, "Failed to find field %s on %s", expr->binary.r->varname, left->struct_name);
        }
        Type* right = validate_expr(expr->binary.r, scope);
        if (expr->binary.op == TokenType::LSB) {//array index
            if (!left->is_array() && !left->is_pointer()) error(expr, "Expected array or pointer type");
            if (right->kind != TypeKind::INT) error(expr, "Expected int to index array");
            return to_pointer_base_type(left);
        }
        else if (expr->binary.op == TokenType::EQ) {//assign
            if (expr->binary.l->type != ExprType::PTR_DEREF && expr->binary.l->type != ExprType::VAR && expr->binary.l->type != ExprType::BINARY && expr->binary.op != TokenType::LSB) error(expr, "Expected variable, pointer dereference or array index");
            if (left != right) error(expr, "Cannot assign %s to %s", left->to_str(), right->to_str());
            return left;
        }
        else {
            if (!left->is_maths_type()) error(expr, "Cannot apply operator %s to %s", token_strs[(int)expr->binary.op], type_strs[(int)left->kind]);
            if (!right->is_maths_type()) error(expr, "Cannot apply operator %s to %s", token_strs[(int)expr->binary.op], type_strs[(int)right->kind]);
            if (expr->binary.op >= TokenType::GT && expr->binary.op <= TokenType::LT)
                return make_type(Type(TypeKind::BOOL));
            else if (expr->binary.op >= TokenType::ADD && expr->binary.op <= TokenType::MOD)
                return left;
        }
        error(expr->loc, "Invalid operation %s", token_strs[(int)expr->binary.op]);
    }
    case ExprType::CALL: {
        ScopeVar* func = scope->get(expr->call.funcname);
        if (!func) error("Undefined function %s", expr->call.funcname);
        if (func->type->kind != TypeKind::FUNC && func->type->kind != TypeKind::STRUCT) error("%s is not a function or struct", expr->call.funcname);

        if (func->func.params.len != expr->call.args.len) error("%s expected %d args got %d", expr->call.funcname, func->func.params.len, expr->call.args.len);
        for (u32 i = 0; i < func->func.params.len; ++i) {
            Type* ret_type = validate_expr(expr->call.args.items[i], scope);
            if (ret_type != func->func.params.items[i].type) error("Expected %s got %s", func->func.params.items[i].type->to_str(), ret_type->to_str());
        }    
        return func->func.ret_type;
    }
    case ExprType::VAL:
        return make_type(Type(expr->val.type, 1));
    case ExprType::VAR: {
        ScopeVar* var = scope->get(expr->varname);
        if (!var) error("Undefined variable %s", expr->varname);
        if (var->type->kind == TypeKind::FUNC || var->type->kind == TypeKind::VOID) error("Cannot use %s as a variable", var->type->to_str());
        return var->type;
    }
    case ExprType::ARRAY: {
        Type* type = validate_expr(expr->arr.vals.items[0], scope);
        int size = type->size;
        for (u32 i = 1; i < expr->arr.vals.len; ++i) {
            Type* next_type = validate_expr(expr->arr.vals.items[i], scope);
            if (type != next_type) error("Expected %s got %s", type->to_str(), next_type->to_str());
            size += next_type->size;
        }
        return to_array(type, size);
    }
    case ExprType::CAST: {
        Type* type = validate_expr(expr->cast.expr, scope);
        if (type->is_maths_type() && expr->cast.type->is_maths_type()) {
            return expr->cast.type;
        }
        error(expr, "Cannot cast %s to %s", type->to_str(), expr->cast.type->to_str());
    }
    case ExprType::PTR_ADDR_OF:
        return to_pointer(validate_expr(expr->ptr_expr, scope));
    case ExprType::PTR_DEREF:
        return to_pointer_base_type(validate_expr(expr->ptr_expr, scope));
    default: error("Unhandled expr type");
        break;
    }
    return make_type(Type(TypeKind::VOID));
}
void expect_expr_type(Expr* expr, Type* ret_type, Scope* scope) {
    Type* type = validate_expr(expr, scope);
    if (type != ret_type) error("Expected %s got %s", ret_type->to_str(), type->to_str());
}
bool validate_stmt(Stmt* stmt, Type* ret_type, Scope* scope) {
    bool did_return;
    switch (stmt->type) {
    case StmtType::BLOCK: {
        did_return = false;
        for (Stmt* s : stmt->block.stmts)
            did_return = validate_stmt(s, ret_type, stmt->block.scope);
        return did_return;
    }
    case StmtType::EXPR:
        validate_expr(stmt->expr, scope);
        return false;
    case StmtType::IF:
        did_return = true;
        for (CondBlock cond : stmt->ifexpr.conds) {
            expect_expr_type(cond.cond, make_type(Type(TypeKind::BOOL)), scope);
            did_return = did_return && validate_stmt(cond.block, ret_type, scope);
        }
        if (stmt->ifexpr.elseblock)
            did_return = did_return && validate_stmt(stmt->ifexpr.elseblock, ret_type, scope);
        return did_return;
    case StmtType::RETURN:
        expect_expr_type(stmt->expr, ret_type, scope);
        return true;
    case StmtType::WHILE:
        did_return = false;
        expect_expr_type(stmt->whileexpr.cond, make_type(Type(TypeKind::BOOL)), scope);
        return validate_stmt(stmt->whileexpr.block, ret_type, scope);
    default:
        error("Unhandled stmt");
        return false;
    }
}
void parse_var(const char* loc, Scope* scope) {
    if (token.type != TokenType::ID) error("Expected variable name");
    const char* name = token.str; nexttoken();
    expect(TokenType::COLON);
    Type* type = parse_type(scope);
    expect(TokenType::EQ);
    Expr* expr = parse_expr(scope);
    expect(TokenType::SC);
    Type* ret_type = validate_expr(expr, scope);
    if (type->is_array() && type->size == -1 && ret_type->is_array()) {
        type = ret_type;
    }
    if (type->is_pointer() && ret_type->kind == TypeKind::NULL_PTR)
        ret_type = type;
    if (type != ret_type) error("Expected %s got %s", type->to_str(), ret_type->to_str());
    scope->put(ScopeVar(name, loc, type, expr));
}
Scope* parse(const char* str) {
	stream = streambeg = str; nexttoken();
    Scope* scope = scopes.push({});
    while (token.type != TokenType::EOF) {
        const char* loc = token.loc;
        if (match(TokenType::VAR)) {
            parse_var(loc, scope);
        }
        else if (match(TokenType::FUNC)) {
            if (token.type != TokenType::ID) error("Expected function name");
            const char* name = token.str; nexttoken();
            if (scope->get(name)) error(loc, "%s already exists", name);
            Vector<ParamDef> parms{};
            expect(TokenType::LPR);
            Scope* func_scope = scopes.push({});
            func_scope->parent = scope;
            if (token.type == TokenType::ID) {
                const char* param_loc = token.loc; const char* param_name = token.str; nexttoken();
                expect(TokenType::COLON);
                Type* param_type = parse_type(scope);
                func_scope->put(ScopeVar(param_name, param_loc, param_type, nullptr));
                parms.push({ param_name, param_type });
                while (match(TokenType::COMMA)) {
                    param_loc = token.loc;
                    if (token.type != TokenType::ID) error("Expected arg name");
                    param_name = token.str; nexttoken();
                    expect(TokenType::COLON);
                    param_type = parse_type(scope);
                    func_scope->put(ScopeVar(param_name, param_loc, param_type, nullptr));
                    parms.push({ param_name, param_type });
                }
            }
            expect(TokenType::RPR);
            Type* ret_type = match(TokenType::COLON) ? parse_type(scope) : make_type(Type(TypeKind::VOID));
            expect(TokenType::LBR);
            ScopeVar* func = scope->put(ScopeVar(name, loc, ret_type, parms, func_scope));
            bool did_return = false;
            while (token.type != TokenType::RBR && token.type != TokenType::EOF) {
                Stmt* stmt = parse_stmt(scope);
                if (!stmt) continue;
                did_return = validate_stmt(stmt, ret_type, func_scope);
                func->func.block.push(stmt);
            }
            if (ret_type->kind != TypeKind::VOID && !did_return) error(loc, "Not all paths return a value");
            expect(TokenType::RBR);
        }
        else if (match(TokenType::STRUCT)) {
            if (token.type != TokenType::ID) error("Expected struct name");
            const char* name = token.str; nexttoken();
            if (scope->get(name)) error("%s already exists", name);
            Vector<ParamDef> elems{};
            expect(TokenType::LPR);
            u32 size = 0;
            if (token.type != TokenType::ID) error("Expected structure member");
            do {
                const char* parm_name = token.str; nexttoken();
                expect(TokenType::COLON);
                Type* parm_type = parse_type(scope);
                size += parm_type->size;
                elems.push({ parm_name, parm_type });
            } while (match(TokenType::COMMA));
            expect(TokenType::RPR);
            expect(TokenType::SC);
            Type* type = make_type(Type(TypeKind::STRUCT, size, nullptr, name));
            scope->put(ScopeVar(name, loc, type, elems));
        }
        else
            error("Unexpected token");
    }
    return scope;
}
// c code generator!
#define _CRT_SECURE_NO_WARNINGS
#include <cstdio>
#include <stdlib.h>
#include <string.h>
void gen_expr(FILE* file, Expr* expr, Scope* scope) {
    switch (expr->type) {
    case ExprType::VAL:
        switch (expr->val.type) {
        case TypeKind::INT:
            fprintf(file, "%d", expr->val.int_val);
            break;
        case TypeKind::BOOL:
            fprintf(file, "%s", expr->val.bool_val ? "true" : "false");
            break;
        case TypeKind::CHAR:
            fprintf(file, "'%c'", expr->val.char_val);
            break;
        default:
            error("Unhandled type"); break;
        }
        break;
    case ExprType::VAR:
        fprintf(file, "%s", expr->varname);
        break;
    case ExprType::BINARY:
        fprintf(file, "(");
        gen_expr(file, expr->binary.l, scope);
        fprintf(file, " %s ", token_strs[(int)expr->binary.op]);
        gen_expr(file, expr->binary.r, scope);
        fprintf(file, ")");
        break;
    default:
        error("Unhandled type");
        break;
    }
}
void gen_stmt(FILE* file, Stmt* stmt, Scope* scope) {
    switch (stmt->type) {
    case StmtType::BLOCK:
        fprintf(file, "{\n");
        for (Stmt* b : stmt->block.stmts)
            gen_stmt(file, b, stmt->block.scope);
        fprintf(file, "}\n");
        break;
    case StmtType::EXPR:
        gen_expr(file, stmt->expr, scope); fprintf(file, ";\n");
        break;
    case StmtType::RETURN:
        fprintf(file, "return "); gen_expr(file, stmt->expr, scope); fprintf(file, ";\n");
        break;
    default:
        error("Unhandled stmt type");
        break;
    }
}
void gen(Scope* scope, const char* fname) {
    FILE* file = fopen(fname, "wt");
    if (!file) error("Failed to open %s: %s\n", fname, strerror(errno));
    for (ScopeVar& var : scope->vars) {
        switch (var.type->kind) {
        case TypeKind::FUNC: {
            fprintf(file, "%s %s(", var.func.ret_type->to_str(), var.name);
            bool is_first = true;
            for (ParamDef parm : var.func.params) {
                if (is_first) is_first = false; else fprintf(file, ", ");
                fprintf(file, "%s %s", parm.type->to_str(), parm.name);
            }
            fprintf(file, ") {\n");
            for (Stmt* stmt : var.func.block)
                gen_stmt(file, stmt, var.func.scope);
            fprintf(file, "}\n");
        }
            break;
        case TypeKind::STRUCT:
            error("Not handled yet");
            break;
        default:
            fprintf(file, "%s %s", var.type->to_str(), var.name);
            if (var.var.init) {
                fprintf(file, " = ");
                gen_expr(file, var.var.init, scope);
            }
            fprintf(file, ";\n");
            break;
        }
    }
    fclose(file);
}

#include <stdarg.h>
#include <cassert>
#include <cstring>

extern "C" { __declspec(dllimport) void __stdcall OutputDebugStringA(const char* str); }
void print(const char* fmt, va_list args) {
	static char errbuf[1024];
	vsnprintf(errbuf, 1024, fmt, args);
	OutputDebugStringA(errbuf);
}
void print(const char* fmt, ...) {
    va_list args; va_start(args, fmt); print(fmt, args); va_end(args);
}
void error(const char* loc, const char* fmt, va_list args) {
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
		for (int i = 0; i < lineoff; ++i) print(" ");
		print("^\n");
	}
	__debugbreak();
	exit(1);
}
void error(const char* fmt, ...) {
	va_list args; va_start(args, fmt); error(token.loc, fmt, args); va_end(args);
}
void error(Expr* expr, const char* fmt, ...) {
	va_list args; va_start(args, fmt); error(expr->loc, fmt, args); va_end(args);
}
void error(Stmt* stmt, const char* fmt, ...) {
	va_list args; va_start(args, fmt); error(stmt->loc, fmt, args); va_end(args);
}
void test_expr(const char* s, int v) { 
	print("%s\n", s);
    Scope* scope = parse(s);
    //gen(scope, "test.c");
}
void test() {
    assert(make_type(Type(TypeKind::INT_ARR, 3)) == make_type(Type(TypeKind::INT_ARR, 3)));
    assert(make_type(Type(TypeKind::INT_ARR, 4)) != make_type(Type(TypeKind::INT_ARR, 3)));
    assert(make_type(Type(TypeKind::INT_ARR, 3)) == make_type(*make_type(Type(TypeKind::INT_ARR, 3))));
    assert(make_type(Type(TypeKind::BOOL)) == make_type(Type(TypeKind::BOOL)));
    assert(make_type(Type(TypeKind::BOOL)) != make_type(Type(TypeKind::INT)));

    test_expr("func main():int { return 5; }", 5);
    test_expr("func main():bool { return true; }", 1);
    test_expr("func main():int { return (1 + 2 + 3) * 4; }", 24);
    test_expr("var a:int = 3; func main():int { return a; }", 3);
    test_expr("func main(a:int):int { a = 5; return a; }", 0);
    test_expr("var a:int = 2; func main(b:int,c:bool):bool { return a > b; }", 0);
    test_expr("var a:int[] = { 0, 1, 2 }; func main():int { a[0] = 1; return a[0]; }", 5);
    test_expr("func main():int { var a:bool = true; return int(a); }", 1);
    test_expr("func main() { var a:char[] = \"hello world!\"; var b:char = a[0]; }", 0);
    test_expr("var a:int = 3; var b:int* = &a; var c:int* = nullptr; var d:int = *b; func main() { c = &a; *c = 4 + *b; b[1] = 5; }", 0);
    test_expr("struct Foo(val:int); var a:Foo = Foo(0); var b:int = a.val; func main() { a.val = 5; }", 0);
    test_expr("struct Foo(a:int,b:int); struct Bar(c:Foo); var d:int = Bar(Foo(1,2)).c.a; var e:Foo[] = { Foo(1, 2), Foo(3, 4) }; var f:Foo = e[0]; var g:int = e[0].a;", 0);
    test_expr("struct Foo(val:int); var a:Foo = Foo(1); var b:Foo[] = { Foo(1) }; var c:Foo = b[0]; var d:Foo* = &b[0];", 0);

	assert(internstr("a") == internstr("a"));
	assert(internstr("a") != internstr("b"));
	assert(internstr("a") != "a");
	assert(internstr("fjfjf") == internstr("fjfjf"));
	assert(internstr(internstr("a")) == internstr("a"));
	streambeg = stream = "foo"; nexttoken();
}

int main(int argc, char** argv) {

    test();
	return 0;
}
