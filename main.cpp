//a = 5
//a = 5.243
//a = 2
//print(b=5,3)
//{a=1;{a=3;print(a);}print a;}
//foo(a,b)=>a+3
//foo = (a,b) => a+3
//foo = (a,b) => { a + 3; a-3; }
//library stuff
void print(const char* fmt, ...);
struct Expr; struct Stmt;
void error(Expr* expr, const char* fmt, ...);
void error(Stmt* stmt, const char* fmt, ...);
void error(const char* fmt, ...);
extern "C" { size_t strlen(const char* str); }
extern "C" { int strcmp(const char* str1, const char* str2); }
typedef long long s64; typedef unsigned long long u64;
typedef unsigned char u8; typedef char s8; typedef int s32; typedef unsigned int u32;
typedef float f32;
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
		Map new_map = { new K[newcap]{}, new V[newcap]{}, 0, newcap };
		for (u32 i = 0; i < cap; ++i)
			if (keys[i])
				new_map.put(keys[i], vals[i]);
		delete[] keys; delete[] vals;
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
enum class TokenType { LPR, RPR, GT, LT, EQEQ, LTEQ, GTEQ, NEQ, ADD, SUB, MUL, DIV, MOD, LSB, INT, ID, EQ, EOF, COMMA, LBR, RBR, SC, IF, ELIF, ELSE, WHILE, FUNC, RETURN, FOR, COLON, CHAR, BOOL, STRUCT, VAR, TRUE, FALSE, RSB };
const char* token_strs[] = { "(", ")", ">", "<", "==", "<=", ">=", "!=", "+", "-", "*", "/", "%", "[", "int", "id", "=", "<eof>", ",", "{", "}", ";", "if", "elif", "else", "while", "func", "return", "for", ":", "char", "bool", "struct", "var", "true", "false", "]" };
struct Token { TokenType type; int val; const char* str; const char* loc; } token;
const char *streambeg, *stream;
#define TOK(cv,t) if (c == cv) { ++stream; token.type = TokenType::t; return; }
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
		token.type = TokenType::INT; token.val = num; return;
	}
	if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		const char* start = stream; ++stream; c = *stream;
		while ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') { ++stream; c = *stream; }
		token.str = internstr(start, stream); 
		KEYW("if", IF) KEYW("elif", ELIF) KEYW("else", ELSE) KEYW("while", WHILE) KEYW("func", FUNC) KEYW("return", RETURN) KEYW("for", FOR)
        KEYW("int", INT) KEYW("char", CHAR) KEYW("bool", BOOL) KEYW("struct", STRUCT) KEYW("var", VAR) KEYW("true", TRUE) KEYW("false", FALSE)
		token.type = TokenType::ID; return;
	}
	TOK2("==", EQEQ) TOK2("<=", LTEQ) TOK2(">=", GTEQ) TOK2("!=", NEQ)
	TOK('>', GT) TOK('<', LT) TOK(':', COLON)
	TOK('+', ADD) TOK('-', SUB) TOK('*', MUL) TOK('/', DIV) TOK('%', MOD) TOK('(', LPR) TOK(')', RPR) TOK('[', LSB) TOK(']', RSB)
	TOK('\0', EOF) TOK('=', EQ) TOK(',', COMMA) TOK('{', LBR) TOK('}', RBR) TOK(';', SC)
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
enum class TypeKind { VOID, FUNC, INT, CHAR, BOOL, INT_ARR, CHAR_ARR, BOOL_ARR };
struct Type {
    TypeKind kind; int size;
    explicit operator int() const { return int(kind); }
    bool operator ==(const TypeKind& o) const { return kind == o; }
    bool operator !=(const TypeKind& o) const { return kind != o; }
    bool operator ==(const Type& o) const { return kind == o.kind && size == o.size; }
    bool operator !=(const Type& o) const { return !(*this == o); }
    bool is_array() const { return kind >= TypeKind::INT_ARR && kind <= TypeKind::BOOL_ARR; }
    bool is_maths_type() const { return kind >= TypeKind::INT && kind <= TypeKind::BOOL; }
    Type() {}
    Type(TypeKind kind, int size = 1) : kind(kind), size(size) {}
};
const char* type_strs[] = { "void", "func", "int", "char", "bool", "int[]", "char[]", "bool[]" };
Type to_array(TypeKind type, int size) {
    switch (type) {
    case TypeKind::INT: return { TypeKind::INT_ARR, size };
    case TypeKind::CHAR: return { TypeKind::CHAR_ARR, size };
    case TypeKind::BOOL: return { TypeKind::BOOL_ARR, size };
    default: error("Cannot create array of type %s", type_strs[int(type)]); return type;
    }
}
Type to_array_base_type(TypeKind type) {
    switch (type) {
    case TypeKind::INT_ARR: return Type(TypeKind::INT);
    case TypeKind::CHAR_ARR: return Type(TypeKind::CHAR);
    case TypeKind::BOOL_ARR: return Type(TypeKind::BOOL);
    default: error("Cannot get base type for %s", type_strs[int(type)]); return Type(type);
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
};
enum class ExprType { VAR, VAL, BINARY, CALL, ASSIGN, ARRAY, INDEX };
struct Expr {
	ExprType type;
	const char* loc;
	union {
		const char* varname;
        Value val;
		struct { TokenType op; Expr *l, *r; } binary;
		struct { const char* funcname; Vector<Expr*> args; } call;
		struct { const char* varname; Expr* e; } assign;
        struct { Vector<Expr*> vals; } arr;
	};
	Expr() {}
    Expr(const char* loc, Value val) : type(ExprType::VAL), loc(loc), val(val) {}
	Expr(const char* loc, TokenType op, Expr* l, Expr* r) : type(ExprType::BINARY), loc(loc), binary({ op, l, r }) {}
	Expr(const char* loc, const char* varname) : type(ExprType::VAR), loc(loc), varname(varname) {}
	Expr(const char* loc, const char* funcname, Vector<Expr*>& args) : type(ExprType::CALL), loc(loc), call({ funcname, args }) {}
	Expr(const char* loc, const char* varname, Expr* assign) : type(ExprType::ASSIGN), loc(loc), assign({varname, assign}) {}
    Expr(const char* loc, Vector<Expr*>& vals) : type(ExprType::ARRAY), loc(loc), arr({vals}) {}
};
Pool<Expr> exprs{};
Expr* parse_expr();
Expr* parse_binary() {
    const char* loc = token.loc;
	if (match(TokenType::LPR)) {//parens
		Expr* expr = parse_expr();
		expect(TokenType::RPR);
		return expr;
	}
	else if (token.type == TokenType::INT) {
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
				args.push(parse_expr());
				while (match(TokenType::COMMA))
					args.push(parse_expr());
			}
			expect(TokenType::RPR);
			return exprs.push(Expr(loc, t.str, args));
		}
		else if (match(TokenType::EQ)) {//assign
			return exprs.push(Expr(loc, t.str, parse_expr()));
		}
		else//var
			return exprs.push(Expr(loc, t.str));
	}
    else if (match(TokenType::LBR)) {//array
        Vector<Expr*> vals{};
        vals.push(parse_expr());
        while (match(TokenType::COMMA))
            vals.push(parse_expr());
        expect(TokenType::RBR);
        return exprs.push(Expr(loc, vals));
    }
	error("Unexpected %s", token_strs[(int)token.type]); return nullptr;
}
Expr* parse_unary(TokenType p = TokenType::GT) {
	if (p == TokenType::INT)
		return parse_binary();
	TokenType np = (TokenType)((int)p + 1);
    const char* loc = token.loc;
	Expr* expr = parse_unary(np);
    while (match(p)) {
        expr = exprs.push(Expr(loc, p, expr, parse_unary(np)));
        if (p == TokenType::LSB) expect(TokenType::RSB);
        loc = token.loc;
    }
	return expr;
}
Expr* parse_expr() {
	return parse_unary();
}
enum class StmtType { EXPR, BLOCK, IF, WHILE, RETURN };
struct CondBlock { Expr* cond; Stmt* block; };
struct Scope;
struct Stmt {
	StmtType type;
	const char* loc;
	union {
		Expr* expr;
        struct { Vector<Stmt*> stmts; Scope* scope; } block;
		struct { Vector<CondBlock> conds; Stmt* elseblock; } ifexpr;
		CondBlock whileexpr;
	};
	Stmt() {}
	Stmt(const char* loc, Vector<Stmt*>& stmts) : type(StmtType::BLOCK), loc(loc), block({ stmts }) {}
	Stmt(const char* loc, Vector<CondBlock>& conds, Stmt* elseblock) : type(StmtType::IF), loc(loc), ifexpr({ conds, elseblock }) {}
	Stmt(const char* loc, Expr* cond, Stmt* block) : type(StmtType::WHILE), loc(loc), whileexpr({ cond, block }) {}
	Stmt(const char* loc, bool is_return, Expr* expr) : type(is_return ? StmtType::RETURN : StmtType::EXPR), loc(loc), expr(expr) {}
};
Pool<Stmt> stmts;
Stmt* parse_stmt() {
    const char* loc = token.loc;
	if (match(TokenType::LBR)) {//scope block
		Vector<Stmt*> block{};
		while (token.type != TokenType::RBR && token.type != TokenType::EOF)
			block.push(parse_stmt());
		expect(TokenType::RBR);
		return stmts.push(Stmt(loc, block));
	}
	else if (match(TokenType::IF)) {
		expect(TokenType::LPR);
		Expr* ifexpr = parse_expr();
		expect(TokenType::RPR);
		Stmt* thenstmt = parse_stmt();
		Vector<CondBlock> conds{};
		conds.push({ ifexpr, thenstmt });
		while (match(TokenType::ELIF)) {
			expect(TokenType::LPR);
			ifexpr = parse_expr();
			expect(TokenType::RPR);
			thenstmt = parse_stmt();
			conds.push({ ifexpr, thenstmt });
		}
		Stmt* elsestmt = match(TokenType::ELSE) ? parse_stmt() : nullptr;
		return stmts.push(Stmt(loc, conds, elsestmt));
	}
	else if (match(TokenType::WHILE)) {
		expect(TokenType::LPR);
		Expr* cond = parse_expr();
		expect(TokenType::RPR);
		Stmt* block = parse_stmt();
		return stmts.push(Stmt(loc, cond, block));
	}
	else if (match(TokenType::RETURN)) {
		Expr* expr = parse_expr(); expect(TokenType::SC);
		return stmts.push(Stmt(loc, true, expr));
	}
	else if (match(TokenType::FOR)) {
		expect(TokenType::LPR);
		Vector<Stmt*> block{};
		if (token.type != TokenType::SC) {
			Expr* init = parse_expr(); block.push(stmts.push(Stmt(loc, false, init)));
			if (init->type != ExprType::ASSIGN) error(init, "Must initialise a variable");
		}
		expect(TokenType::SC);
		Expr* whilecond = parse_expr(); expect(TokenType::SC);
		Vector<Stmt*> forblock{};
		Expr* increment = parse_expr();
		if (increment->type != ExprType::ASSIGN) error(increment, "Must modify a variable");
		expect(TokenType::RPR);
		Stmt* body = parse_stmt(); forblock.push(body); forblock.push(stmts.push(Stmt(loc, false, increment)));
		block.push(stmts.push(Stmt(loc, whilecond, stmts.push(Stmt(loc, forblock)))));
		return stmts.push(Stmt(loc, block));
	}
	else {
		Expr* expr = parse_expr(); expect(TokenType::SC);
		return stmts.push(Stmt(loc, false, expr));
	}
}
struct ParamDef {
    const char* name; Type type;
};
struct ScopeVar {
    const char* name; const char* loc; Type type;
    union {
        struct { int local_var_idx; Expr* init; } var;
        struct { Type ret_type; Vector<ParamDef> params; Vector<Stmt*> block; Scope* scope; } func;
        //struct { Vector<ParamDef> elems; } struc;
    };
    ScopeVar() {}
    ScopeVar(const char* name, const char* loc, Type ret_type, Vector<ParamDef> params, Scope* scope) : name(name), loc(loc), type(Type(TypeKind::FUNC)), func({ ret_type, params, {}, scope }) {}
    ScopeVar(const char* name, const char* loc, Type type, Expr* init) : name(name), loc(loc), type(type), var({ 0, init }) {}
    //ScopeVar(const char* name, const char* loc, Vector<ParamDef>& elems) : name(name), loc(loc), type(Type::STRUCT), struc({elems}) {}
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
        if (var.type != TypeKind::FUNC) {
            var.var.local_var_idx = local_var_count;
            local_var_count += var.type.size;
        }
        vars.push(var);
        return &vars.back();
    }
};
Pool<Scope> scopes{};
Type parse_type(Scope* scope) {
    TypeKind type; int size = 1;
    switch (token.type) {
    case TokenType::INT: type = TypeKind::INT; break;
    case TokenType::CHAR: type = TypeKind::CHAR; break;
    case TokenType::BOOL: type = TypeKind::BOOL; break;
    /*case TokenType::ID: {
        type = Type::STRUCT_PTR;
        ScopeVar* struc = scope->get(token.str);
        if (!struc) error("Undefined struct %s", token.str);
        if (struc->type != Type::STRUCT) error("Expected struct definition");
    } break;*/
    default: error("Expected type"); break;
    }
    nexttoken();
    if (match(TokenType::LSB)) {
        if (token.type == TokenType::INT) {
            size = token.val; nexttoken();
        }
        else
            size = -1;
        expect(TokenType::RSB);
        return to_array(type, size);
    }
    /*if (match(TokenType::MUL)) {
        switch (type) {
        case Type::INT: return Type::INT_PTR;
        case Type::BOOL: return Type::BOOL_PTR;
        case Type::CHAR: return Type::CHAR_PTR;
        default: error("Cannot create pointer to %s", type_strs[(int)type]); break;
        }
    }*/
    return Type(type);
}
Type validate_expr(Expr* expr, Scope* scope) {
    switch (expr->type) {
    case ExprType::ASSIGN: {
        ScopeVar* var = scope->get(expr->assign.varname);
        if (!var) error("Undefined variable %s", expr->assign.varname);
        if (var->type == TypeKind::FUNC || var->type == TypeKind::VOID) error("Cannot assign %s to %s", type_strs[int(var->type)], var->name);
        Type ret_type = validate_expr(expr->assign.e, scope);
        if (ret_type != var->type) error("Expected %s got %s", type_strs[int(var->type)], type_strs[int(ret_type)]);
        return var->type;
    }
    case ExprType::BINARY: {
        Type left = validate_expr(expr->binary.l, scope);
        Type right = validate_expr(expr->binary.r, scope);
        if (expr->binary.op == TokenType::LSB) {
            if (!left.is_array()) error(expr, "Expected array type");
            if (right != TypeKind::INT) error(expr, "Expected int array indexer");
            return to_array_base_type(left.kind);
        }
        else {
            if (!left.is_maths_type()) error(expr, "Cannot apply operator %s to %s", token_strs[(int)expr->binary.op], type_strs[(int)left]);
            if (!right.is_maths_type()) error(expr, "Cannot apply operator %s to %s", token_strs[(int)expr->binary.op], type_strs[(int)right]);
            if (expr->binary.op >= TokenType::GT && expr->binary.op <= TokenType::LT)
                return Type(TypeKind::BOOL);
            else if (expr->binary.op >= TokenType::ADD && expr->binary.op <= TokenType::MOD)
                return left;
        }
        error(expr->loc, "Invalid operation %s", token_strs[(int)expr->binary.op]);
    }
    case ExprType::CALL: {
        ScopeVar* func = scope->get(expr->call.funcname);
        if (!func) error("Undefined function %s", expr->call.funcname);
        if (func->type != TypeKind::FUNC) error("%s is not a function", expr->call.funcname);
        if (func->func.params.len != expr->call.args.len) error("%s expected %d args got %d", expr->call.funcname, func->func.params.len, expr->call.args.len);
        for (u32 i = 0; i < func->func.params.len; ++i) {
            Type ret_type = validate_expr(expr->call.args.items[i], scope);
            if (ret_type != func->func.params.items[i].type) error("Expected %s got %s", type_strs[int(func->func.params.items[i].type)], type_strs[int(ret_type)]);
        }
        return func->func.ret_type;
    }
    case ExprType::VAL:
        return { expr->val.type, 1 };
    case ExprType::VAR: {
        ScopeVar* var = scope->get(expr->varname);
        if (!var) error("Undefined variable %s", expr->varname);
        if (var->type == TypeKind::FUNC || var->type == TypeKind::VOID) error("Cannot use %s as a variable", type_strs[int(var->type)]);
        return var->type;
    }
    case ExprType::ARRAY: {
        Type type = validate_expr(expr->arr.vals.items[0], scope);
        int size = type.size;
        for (u32 i = 1; i < expr->arr.vals.len; ++i) {
            Type next_type = validate_expr(expr->arr.vals.items[i], scope);
            if (type != next_type) error("Expected %s got %s", type_strs[int(type)], type_strs[int(next_type)]);
            size += next_type.size;
        }
        return to_array(type.kind, size);
    }
    default: error("Unhandled expr type");
        break;
    }
    return Type(TypeKind::VOID);
}
void expect_expr_type(Expr* expr, Type ret_type, Scope* scope) {
    Type type = validate_expr(expr, scope);
    if (type != ret_type) error("Expected %s got %s", type_strs[int(ret_type)], type_strs[int(type)]);
}
bool validate_stmt(Stmt* stmt, Type ret_type, Scope* scope) {
    bool did_return;
    switch (stmt->type) {
    case StmtType::BLOCK: {
        Scope* block_scope = scopes.push({});
        block_scope->parent = scope;
        block_scope->local_var_count = scope->local_var_count;
        stmt->block.scope = block_scope;
        did_return = false;
        for (Stmt* s : stmt->block.stmts)
            did_return = validate_stmt(s, ret_type, block_scope);
        return did_return;
    }
    case StmtType::EXPR:
        validate_expr(stmt->expr, scope);
        return false;
    case StmtType::IF:
        did_return = true;
        for (CondBlock cond : stmt->ifexpr.conds) {
            expect_expr_type(cond.cond, Type(TypeKind::BOOL), scope);
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
        expect_expr_type(stmt->whileexpr.cond, Type(TypeKind::BOOL), scope);
        return validate_stmt(stmt->whileexpr.block, ret_type, scope);
    default:
        error("Unhandled stmt");
        return false;
    }
}
Scope* parse(const char* str) {
	stream = streambeg = str; nexttoken();
    Scope* scope = scopes.push({});
    while (token.type != TokenType::EOF) {
        const char* loc = token.loc;
        if (match(TokenType::VAR)) {
            if (token.type != TokenType::ID) error("Expected variable name");
            const char* name = token.str; nexttoken();
            expect(TokenType::COLON);
            Type type = parse_type(scope);
            expect(TokenType::EQ);
            Expr* expr = parse_expr();
            expect(TokenType::SC);
            Type ret_type = validate_expr(expr, scope);
            if (type.is_array() && type.size == -1 && ret_type.is_array()) {
                type.size = ret_type.size;
            }
            if (type != ret_type) error("Expected %s got %s", type_strs[(int)type], type_strs[(int)ret_type]);
            scope->put(ScopeVar(name, loc, type, expr));
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
                Type param_type = parse_type(scope);
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
            Type ret_type = match(TokenType::COLON) ? parse_type(scope) : Type(TypeKind::VOID);
            expect(TokenType::LBR);
            ScopeVar* func = scope->put(ScopeVar(name, loc, ret_type, parms, func_scope));
            bool did_return = false;
            while (token.type != TokenType::RBR && token.type != TokenType::EOF) {
                Stmt* stmt = parse_stmt();
                did_return = validate_stmt(stmt, ret_type, func_scope);
                func->func.block.push(stmt);
            }
            if (ret_type != TypeKind::VOID && !did_return) error(loc, "Not all paths return a value");
            expect(TokenType::RBR);
        }
        else
            error("Unexpected token");
    }
    return scope;
}

/*void resolve_expr(Expr* expr, Scope* scope) {
	switch (expr->type) {
	case ExprType::VAL: break;
	case ExprType::VAR:
		if (!scope->get(expr->varname))
			error(expr, "Unknown variable %s", expr->varname);
		break;
	case ExprType::ASSIGN:
		resolve_expr(expr->assign.e, scope);
		if (Value* val = scope->get(expr->assign.varname)) {
			if (val->type == ValueKind::FUNC)
				error(expr, "Cannot assign function to variable");
		}
		else {
			u32 count = 0;
			for (Scope* s = scope; s; s = s->parent)
				count += s->vars.len;
			scope->vars.put(expr->assign.varname, Value::INT(count));
			scope->vars_in_scope++;
		}
		break;
	case ExprType::BINARY:
		resolve_expr(expr->binary.l, scope); resolve_expr(expr->binary.r, scope);
		break;
	case ExprType::CALL:
		if (Value* val = scope->get(expr->call.funcname)) {
			if (val->type != ValueKind::FUNC) error(expr, "%s is not a function", expr->call.funcname);
		}
		else
			error(expr, "Unknown function %s", expr->call.funcname);
		for (Expr* e : expr->call.args)
			resolve_expr(e, scope);
		break;
	default: __debugbreak(); break;
	}
}
void resolve_stmt(Stmt* stmt, Scope* scope) {
	switch (stmt->type) {
	case StmtType::BLOCK:
		if (scope) stmt->block.scope.parent = scope;
		stmt->block.scope.global = scope ? scope->global : &stmt->block.scope;
		for (Stmt* s : stmt->block.stmts)
			resolve_stmt(s, &stmt->block.scope);
		break;
	case StmtType::IF:
		for (CondBlock& cond : stmt->ifexpr.conds) {
			resolve_expr(cond.cond, scope);
			resolve_stmt(cond.block, scope);
		}
		if (stmt->ifexpr.elseblock)
			resolve_stmt(stmt->ifexpr.elseblock, scope);
		break;
	case StmtType::WHILE:
		resolve_expr(stmt->whileexpr.cond, scope);
		resolve_stmt(stmt->whileexpr.block, scope);
		break;
	case StmtType::FUNC:
		if (scope->get(stmt->func.funcname))
			error(stmt, "%s already defined", stmt->func.funcname);
		for (const char* arg : stmt->func.params)
			stmt->func.scope.vars.put(arg, Value::INT(stmt->func.scope.vars.len - stmt->func.params.len - 2));
		scope->vars.put(stmt->func.funcname, Value::FUNC());
		stmt->func.scope.global = scope->global;
		stmt->func.scope.vars.put(stmt->func.funcname, Value::FUNC());
		resolve_stmt(stmt->func.block, &stmt->func.scope);
		break;
	case StmtType::EXPR: resolve_expr(stmt->expr, scope); break;
	case StmtType::RETURN: 
		resolve_expr(stmt->expr, scope);
		while (scope->parent != nullptr) scope = scope->parent;
		scope->returns = true;
		break;
	default: __debugbreak(); break;
	}
}

//vm!
enum class Op : u8 { HLT, LIT, GT, LT, EQEQ, LTEQ, GTEQ, NEQ, ADD, SUB, MUL, DIV, MOD, LOAD, STORE, POP, JMP, TEST, CALL, RET, LDGB, STGB };
struct OpInfo { const char* str; bool has_val; };
const OpInfo ops[] = { {"HLT", false }, { "LIT", true }, { "GT", false }, { "LT", false }, { "EQEQ", false }, { "LTEQ", false }, { "GTEQ", false }, { "NEQ", false }, { "ADD", false }, { "SUB", false }, { "MUL", false }, { "DIV", false }, { "MOD", false }, { "LOAD", true }, { "STORE", true }, { "POP", false }, { "JMP", true }, { "TEST", true }, { "CALL", true }, { "RET", false }, { "LDGB", true }, { "STGB", true } };
static_assert((int)Op::GT == (int)TokenType::GT, "?");
static_assert((int)Op::MOD == (int)TokenType::MOD, "?");
static_assert((int)Op::STGB+1 == sizeof(ops) / sizeof(OpInfo), "?");
Vector<u8> code;
template <typename T> void code_set(u32 pos, T t) { *(T*)(code.items + pos) = t; }
template <typename T> void code_push(T t) { u32 p = code.len; code.len += sizeof(T); if (code.len >= code.cap) code.grow(); code_set<T>(p, t); }
void vm_compile_expr(Expr* expr, Scope* scope) {
	switch (expr->type) {
	case ExprType::VAL: code_push(Op::LIT); code_push(expr->val.val); break;
	case ExprType::VAR: code_push(scope->is_global(expr->varname) ? Op::LDGB : Op::LOAD); code_push(scope->get(expr->varname)->val); break;
	case ExprType::ASSIGN: 
		vm_compile_expr(expr->assign.e, scope);
		code_push(scope->is_global(expr->varname) ? Op::STGB : Op::STORE); code_push(scope->get(expr->assign.varname)->val);
		break;
	case ExprType::BINARY: vm_compile_expr(expr->binary.l, scope); vm_compile_expr(expr->binary.r, scope); code_push((Op)expr->binary.op); break;
	case ExprType::CALL:
		for (Expr* arg : expr->call.args) vm_compile_expr(arg, scope);
		code_push(Op::CALL); code_push(scope->get(expr->call.funcname)->val);
		break;
	default: __debugbreak(); break;
	}
}
void vm_compile_stmt(Stmt* stmt, Scope* scope) {
	switch (stmt->type) {
	case StmtType::BLOCK: {
		for (u32 i = 0; i < stmt->block.scope.vars_in_scope; ++i) { code_push(Op::LIT); code_push<u32>(0); }
		for (Stmt* s : stmt->block.stmts)
			vm_compile_stmt(s, &stmt->block.scope);
		for (u32 i = 0; i < stmt->block.scope.vars_in_scope; ++i) code_push(Op::POP);
	} break;
	case StmtType::WHILE: {
		u32 while_start = code.len;
		vm_compile_expr(stmt->whileexpr.cond, scope);
		code_push(Op::TEST); u32 goto_whileend = code.len; code_push<u32>(0);
		vm_compile_stmt(stmt->whileexpr.block, scope);
		code_push(Op::JMP); code_push(while_start);
		code_set<u32>(goto_whileend, code.len);
	} break;
	case StmtType::EXPR: vm_compile_expr(stmt->expr, scope); code_push(Op::POP); break;
	case StmtType::FUNC: {
		code_push(Op::JMP); u32 goto_funcend = code.len; code_push<u32>(0);
		scope->get(stmt->func.funcname)->val = code.len;
		stmt->func.scope.get(stmt->func.funcname)->val = code.len;
		vm_compile_stmt(stmt->func.block, &stmt->func.scope);
		code_push(Op::RET);
		code_set<u32>(goto_funcend, code.len);
	} break;
	case StmtType::RETURN:
		vm_compile_expr(stmt->expr, scope);
		code_push(Op::STORE); code_push<int>(-3);
		code_push(Op::RET);
		break;
	case StmtType::IF: {
		u32 goto_elif = 0;
		Vector<u32> goto_end{};
		for (CondBlock& cond : stmt->ifexpr.conds) {
			if (goto_elif != 0)
				code_set<u32>(goto_elif, code.len);
			vm_compile_expr(cond.cond, scope);
			code_push(Op::TEST); goto_elif = code.len; code_push<u32>(0);
			vm_compile_stmt(cond.block, scope);
			code_push(Op::JMP); goto_end.push(code.len); code_push<u32>(0);
		}
		code_set<u32>(goto_elif, code.len);
		if (stmt->ifexpr.elseblock)
			vm_compile_stmt(stmt->ifexpr.elseblock, scope);
		for (u32 label : goto_end)
			code_set<u32>(label, code.len);
	} break;
	default: __debugbreak(); break;
	}
}
int stack[512];
u32 pc = 0, fp = 0, sp = 0;
template <typename T> T code_pop() { T v = *(T*)(code.items + pc); pc += sizeof(T); return v; }
void vm_disasm() {
	pc = 0;
	while (pc < code.len) {
		Op op = code_pop<Op>();
		print("%s ", ops[(int)op].str);
		if (ops[(int)op].has_val)
			print("%d ", code_pop<int>());
	}
	print("\n");
}
#define OP(o,op) case Op::o: stack[sp-2] = (stack[sp-2] op stack[sp-1]); --sp; break;
void vm_exec() {
	pc = 0; fp = 0; sp = 0;
	int val = 0;
	while (pc >= 0 && pc < code.len) {
		Op op = code_pop<Op>();
		print("%s ", ops[(int)op].str);
		if (ops[(int)op].has_val) {
			val = code_pop<int>();
			print("%d ", val);
		}
		switch (op) {
		case Op::HLT: return;
		case Op::LIT: stack[sp++] = val; break;
		case Op::LOAD: stack[sp++] = stack[fp + val]; break;
		case Op::STORE: stack[fp + val] = stack[sp - 1]; break;
		case Op::LDGB: stack[sp++] = stack[val]; break;
		case Op::STGB: stack[val] = stack[sp - 1]; break;
		case Op::POP: --sp; break;
		case Op::JMP: pc = val; break;
		case Op::TEST: if (stack[--sp] == 0) pc = val; break;
		case Op::CALL: {
			stack[sp] = fp; fp = sp + 2; sp++; stack[sp++] = pc; pc = val;
		} break;
		case Op::RET: {
			sp = fp - 2; pc = stack[fp - 1]; fp = stack[fp - 2];
		} break;
			OP(GT, >) OP(LT, <) OP(EQEQ, ==) OP(LTEQ, <=) OP(GTEQ, >=) OP(NEQ, !=) OP(ADD, +) OP(SUB, -) OP(MUL, *) OP(DIV, /) OP(MOD, %)
		default: __debugbreak(); break;
		}
	}
	if (sp != 0 || fp != 0) __debugbreak();
	print("\n");
}*/

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdarg.h>
#include <cassert>
#include <stdlib.h>
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
	/*resolve_stmt(stmt, nullptr);
	code.clear();
	vm_compile_stmt(stmt, nullptr);
	vm_disasm();
	vm_exec();
	if (stack[0] != v) __debugbreak();
	assert(stack[0] == v);*/
}
void test() {
    test_expr("func main():int { return 5; }", 5);
    test_expr("func main():bool { return true; }", 1);
    test_expr("func main():int { return (1 + 2 + 3) * 4; }", 24);
    test_expr("var a:int = 3; func main():int { return a; }", 3);
    test_expr("func main(a:int):int { a = 5; return a; }", 0);
    test_expr("var a:int = 2; func main(b:int,c:bool):bool { return a > b; }", 0);
    test_expr("var a:int[] = { 0, 1, 2 }; func main():int { return a[0]; }", 5);
    //test_expr("var a:int[] = { 0, 1 }; func main() { a = { 1, 2 }; a[1] = 3; }", 0);
    //test_expr("var a:char[] = \"hello\"; func main():int { var c:char* = a; while (*a != '\0') { putchar(a); a = a + 1; } return 0; }", 0);

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
