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
enum class TokenType { LPR, RPR, GT, LT, EQEQ, LTEQ, GTEQ, NEQ, ADD, SUB, MUL, DIV, MOD, INT, ID, EQ, EOF, COMMA, LBR, RBR, SC, IF, ELIF, ELSE, WHILE, FUNC, RETURN };
const char* token_strs[] = { "(", ")", ">", "<", "==", "<=", ">=", "!=", "+", "-", "*", "/", "%", "int", "id", "=", "<eof>", ",", "{", "}", ";", "if", "elif", "else", "while", "func", "return" };
struct Token { TokenType type; int val; const char* str; const char* loc; } token;
const char *streambeg, *stream;
#define TOK(cv,t) if (c == cv) { ++stream; token.type = TokenType::t; return; }
#define TOK2(cv,t) if (c == cv[0] && stream[1] == cv[1]) { stream += 2; token.type = TokenType::t; return; }
#define KEYW(s,t) if (strcmp(s, token.str) == 0) { token.type = TokenType::t; return; }
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
		KEYW("if", IF) KEYW("elif", ELIF) KEYW("else", ELSE) KEYW("while", WHILE) KEYW("func", FUNC) KEYW("return", RETURN)
		token.type = TokenType::ID; return;
	}
	TOK2("==", EQEQ) TOK2("<=", LTEQ) TOK2(">=", GTEQ) TOK2("!=", NEQ)
	TOK('>', GT) TOK('<', LT)
	TOK('+', ADD) TOK('-', SUB) TOK('*', MUL) TOK('/', DIV) TOK('%', MOD) TOK('(', LPR) TOK(')', RPR)
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
enum class ValueType { VOID, VAR, FUNC };
struct Value {
	ValueType type;
	int val;
	static Value VAR(int val) { return { ValueType::VAR, val }; }
	static Value VOID() { return { ValueType::VOID, 0 }; }
	static Value FUNC() { return { ValueType::FUNC, 0 }; }
};
enum class ExprType { VAR, VAL, BINARY, CALL, ASSIGN };
struct Expr {
	ExprType type;
	const char* loc;
	union {
		const char* varname;
		Value val;
		struct { TokenType op; Expr *l, *r; } binary;
		struct { const char* funcname; Vector<Expr*> args; } call;
		struct { const char* varname; Expr* e; } assign;
	};
	Expr() {}
	Expr(const char* loc, Value v) : type(ExprType::VAL), loc(loc), val(v) {}
	Expr(const char* loc, TokenType op, Expr* l, Expr* r) : type(ExprType::BINARY), loc(loc), binary({ op, l, r }) {}
	Expr(const char* loc, const char* varname) : type(ExprType::VAR), loc(loc), varname(varname) {}
	Expr(const char* loc, const char* funcname, Vector<Expr*>& args) : type(ExprType::CALL), loc(loc), call({ funcname, args }) {}
	Expr(const char* loc, const char* varname, Expr* assign) : type(ExprType::ASSIGN), loc(loc), assign({varname, assign}) {}
};
Pool<Expr> exprs{};
Expr* parse_expr();
Expr* parse_binary() {
	if (match(TokenType::LPR)) {//parens
		Expr* expr = parse_expr();
		expect(TokenType::RPR);
		return expr;
	}
	else if (token.type == TokenType::INT) {
		Token t = token; nexttoken();
		return exprs.push(Expr(token.loc, Value::VAR(t.val)));
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
			return exprs.push(Expr(token.loc, t.str, args));
		}
		else if (match(TokenType::EQ)) {//assign
			return exprs.push(Expr(token.loc, t.str, parse_expr()));
		}
		else//var
			return exprs.push(Expr(token.loc, t.str));
	}
	error("Unexpected %s", token_strs[(int)token.type]); return nullptr;
}
Expr* parse_unary(TokenType p = TokenType::GT) {
	if (p == TokenType::INT)
		return parse_binary();
	TokenType np = (TokenType)((int)p + 1);
	Expr* expr = parse_unary(np);
	while (match(p))
		expr = exprs.push(Expr(token.loc, p, expr, parse_unary(np)));
	return expr;
}
Expr* parse_expr() {
	return parse_unary();
}
enum class StmtType { EXPR, FUNC, ASSIGN, BLOCK, IF, WHILE, RETURN };
struct CondBlock { Expr* cond; Stmt* block; };
struct Scope { Map<const char*, Value> vars; u32 vars_in_scope; Scope* parent; bool returns; };
struct Stmt {
	StmtType type;
	const char* loc;
	union {
		Expr* expr;
		struct { Vector<Stmt*> stmts; Scope scope; } block;
		struct { Vector<CondBlock> conds; Stmt* elseblock; } ifexpr;
		struct { const char* funcname; Vector<const char*> params; Stmt* block; Scope scope; } func;
		CondBlock whileexpr;
	};
	Stmt() {}
	Stmt(const char* loc, Vector<Stmt*>& stmts) : type(StmtType::BLOCK), loc(loc), block({ stmts, {} }) {}
	Stmt(const char* loc, Vector<CondBlock>& conds, Stmt* elseblock) : type(StmtType::IF), loc(loc), ifexpr({ conds, elseblock }) {}
	Stmt(const char* loc, Expr* cond, Stmt* block) : type(StmtType::WHILE), loc(loc), whileexpr({ cond, block }) {}
	Stmt(const char* loc, bool is_return, Expr* expr) : type(is_return ? StmtType::RETURN : StmtType::EXPR), loc(loc), expr(expr) {}
	Stmt(const char* loc, const char* funcname, Vector<const char*>& params, Stmt* block) : type(StmtType::FUNC), loc(loc), func({ funcname, params, block }) {}
};
Pool<Stmt> stmts;
Stmt* parse_stmt() {
	if (match(TokenType::LBR)) {//scope block
		Vector<Stmt*> block{};
		while (token.type != TokenType::RBR && token.type != TokenType::EOF)
			block.push(parse_stmt());
		expect(TokenType::RBR);
		return stmts.push(Stmt(token.loc, block));
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
		return stmts.push(Stmt(token.loc, conds, elsestmt));
	}
	else if (match(TokenType::WHILE)) {
		expect(TokenType::LPR);
		Expr* cond = parse_expr();
		expect(TokenType::RPR);
		Stmt* block = parse_stmt();
		return stmts.push(Stmt(token.loc, cond, block));
	}
	else if (match(TokenType::FUNC)) {
		if (token.type != TokenType::ID) error("Expected function name");
		const char* name = token.str; nexttoken();
		Vector<const char*> parms{};
		expect(TokenType::LPR);
		if (token.type == TokenType::ID) {
			parms.push(token.str); nexttoken();
			while (match(TokenType::COMMA)) {
				if (token.type != TokenType::ID) error("Expected arg name");
				parms.push(token.str); nexttoken();
			}
		}
		expect(TokenType::RPR);
		return stmts.push(Stmt(token.loc, name, parms, parse_stmt()));
	}
	else if (match(TokenType::RETURN)) {
		Expr* expr = parse_expr(); expect(TokenType::SC);
		return stmts.push(Stmt(token.loc, true, expr));
	}
	else {
		Expr* expr = parse_expr(); expect(TokenType::SC);
		return stmts.push(Stmt(token.loc, false, expr));
	}
}
Stmt* parse(const char* str) {
	stream = streambeg = str; nexttoken();
	Vector<Stmt*> block{};
	while (token.type != TokenType::EOF)
		block.push(parse_stmt());
	return stmts.push(Stmt(token.loc, block));
}

//resolve variables
void resolve_expr(Expr* expr, Scope* scope) {
	switch (expr->type) {
	case ExprType::VAL: break;
	case ExprType::VAR:
		if (!scope->vars.get(expr->varname))
			error(expr, "Unknown variable %s", expr->varname);
		break;
	case ExprType::ASSIGN:
		resolve_expr(expr->assign.e, scope);
		if (Value* val = scope->vars.get(expr->assign.varname)) {
			if (val->type == ValueType::FUNC)
				error(expr, "Cannot assign function to variable");
		}
		else {
			scope->vars.put(expr->assign.varname, Value::VAR(scope->vars.len));
			scope->vars_in_scope++;
		}
		break;
	case ExprType::BINARY:
		resolve_expr(expr->binary.l, scope); resolve_expr(expr->binary.r, scope);
		break;
	case ExprType::CALL:
		if (Value* val = scope->vars.get(expr->call.funcname)) {
			if (val->type != ValueType::FUNC) error(expr, "%s is not a function", expr->call.funcname);
		}
		else
			error(expr, "Unknown function %s", expr->call.funcname);
		for (Expr* e : expr->call.args)
			resolve_expr(e, scope);
		break;
	default: __debugbreak(); break;
	}
}
void copy_scope(Scope& src, Scope& tgt) {
	tgt.parent = &src;
	for (u32 i = 0; i < src.vars.cap; ++i)
		if (src.vars.keys[i])
			tgt.vars.put(src.vars.keys[i], src.vars.vals[i]);
}
void resolve_stmt(Stmt* stmt, Scope* scope) {
	switch (stmt->type) {
	case StmtType::BLOCK:
		if (scope) copy_scope(*scope, stmt->block.scope);
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
		if (scope->vars.get(stmt->func.funcname))
			error(stmt, "%s already defined", stmt->func.funcname);
		scope->vars.put(stmt->func.funcname, Value::FUNC());
		for (const char* arg : stmt->func.params)
			stmt->func.scope.vars.put(arg, Value::VAR(stmt->func.scope.vars.len - stmt->func.params.len - 2));
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
enum class Op : u8 { HLT, LIT, GT, LT, EQEQ, LTEQ, GTEQ, NEQ, ADD, SUB, MUL, DIV, MOD, LOAD, STORE, POP, JMP, TEST, CALL, RET };
struct OpInfo { const char* str; bool has_val; };
const OpInfo ops[] = { {"HLT", false }, { "LIT", true }, { "GT", false }, { "LT", false }, { "EQEQ", false }, { "LTEQ", false }, { "GTEQ", false }, { "NEQ", false }, { "ADD", false }, { "SUB", false }, { "MUL", false }, { "DIV", false }, { "MOD", false }, { "LOAD", true }, { "STORE", true }, { "POP", false }, { "JMP", true }, { "TEST", true }, { "CALL", true }, { "RET", false } };
static_assert((int)Op::GT == (int)TokenType::GT, "?");
static_assert((int)Op::MOD == (int)TokenType::MOD, "?");
static_assert((int)Op::RET+1 == sizeof(ops) / sizeof(OpInfo), "?");
Vector<u8> code;
template <typename T> void code_set(u32 pos, T t) { *(T*)(code.items + pos) = t; }
template <typename T> void code_push(T t) { u32 p = code.len; code.len += sizeof(T); if (code.len >= code.cap) code.grow(); code_set<T>(p, t); }
void vm_compile_expr(Expr* expr, Scope* scope) {
	switch (expr->type) {
	case ExprType::VAL: code_push(Op::LIT); code_push(expr->val.val); break;
	case ExprType::VAR: code_push(Op::LOAD); code_push(scope->vars.get(expr->varname)->val); break;
	case ExprType::ASSIGN: 
		vm_compile_expr(expr->assign.e, scope);
		code_push(Op::STORE); code_push(scope->vars.get(expr->assign.varname)->val);
		break;
	case ExprType::BINARY: vm_compile_expr(expr->binary.l, scope); vm_compile_expr(expr->binary.r, scope); code_push((Op)expr->binary.op); break;
	case ExprType::CALL:
		for (Expr* arg : expr->call.args) vm_compile_expr(arg, scope);
		code_push(Op::CALL); code_push(scope->vars.get(expr->call.funcname)->val);
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
		scope->vars.get(stmt->func.funcname)->val = code.len;
		vm_compile_stmt(stmt->func.block, &stmt->func.scope);
		code_push(Op::RET);
		code_set<u32>(goto_funcend, code.len);
	} break;
	case StmtType::RETURN:
		vm_compile_expr(stmt->expr, scope);
		code_push(Op::STORE); code_push<int>(-3);
		code_push(Op::RET);
		break;
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
}

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
	Stmt* stmt = parse(s);
	resolve_stmt(stmt, nullptr);
	code.clear();
	vm_compile_stmt(stmt, nullptr);
	vm_disasm();
	vm_exec();
	if (stack[0] != v) __debugbreak();
	assert(stack[0] == v);
}
void test() {
	test_expr("v = 0; func x(n) { return n + 1; } v = x(5);", 6);
	test_expr("v = 0; x = 3; while (x > 0) { x = x - 1; v = v + 1; }", 3);
	test_expr("v=3+3>=6;", 1);
	test_expr("v=245645432;", 245645432);
	test_expr("v=3;", 3);
	test_expr("v=13%10==3;", 1);
	test_expr("v=1+2+3; { x = 2+v; x=x+1; v=x; } v = v*2;", 18);
	test_expr("v=(3*4)+5;", 17);
	test_expr("v=(3+(5-2) \t\n );", 6);
	test_expr("v=(3);", 3);
	test_expr("v=  5 +   3; \t", 8);
	test_expr("v=5*3;", 15);
	test_expr("v=15/3*4;", 20);
	test_expr("v=4+3*3;", 13);
	test_expr("v=3+2+1;", 6);
	test_expr("v=10;", 10);
	/*test_expr("if (3 > 1) 1", 1);
	test_expr("if (3 > 4) 1 else 2", 2);
	test_expr("if (3 > 4) 1 elif (5 > 1) 2 else 3", 2);
	test_expr("{ x = 3; print(x); }", 0);
	test_expr("{ x = 3; }", 3);
	test_expr("{ x = 3; x; }", 3);
	
	test_expr("func x(n) n+1; x(3);");
	test_expr("func fib(n) if (n > 1) n+fib(n-1) else 1; fib(3);");*/
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
